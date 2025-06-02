
// SPDX-License-Identifier: MIT

module;

#include <sodium.h>

export module password_manager;

import uzleo.json;
import std;
import fmt;

namespace rng = std::ranges;

namespace config {

constexpr std::size_t kSaltLength{crypto_pwhash_SALTBYTES};
constexpr std::size_t kNonceLength{crypto_secretbox_NONCEBYTES};
constexpr std::size_t kKeyLength{crypto_secretbox_KEYBYTES};

}  // namespace config

namespace {

auto GenerateRandomByte() -> std::byte {
  static std::uniform_int_distribution<std::uint8_t> distr{};
  static std::random_device device{};
  static std::mt19937 engine{device()};
  return std::byte{distr(engine)};
}

template <class T>
concept CharLike = std::same_as<std::remove_cv_t<T>, char> or
                   std::same_as<std::remove_cv_t<T>, char8_t> or
                   std::same_as<std::remove_cv_t<T>, unsigned char> or
                   std::same_as<std::remove_cv_t<T>, signed char>;

template <class Parent>
class ByteBuffer final : public Parent {
 public:
  template <CharLike T>
  [[nodiscard]] auto GetCConstPtr() const -> T* {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, typename Parent::value_type>,
                  "ByteBuffer must hold std::byte objects.");
    // NOTE: byte* to (char-like) T* is safe
    return reinterpret_cast<T*>(this->data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }

  template <CharLike T>
  [[nodiscard]] auto GetCPtr() -> T* {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, typename Parent::value_type>,
                  "ByteBuffer must hold std::byte objects.");
    // NOTE: byte* to (char-like) T* is safe
    return reinterpret_cast<T*>(this->data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }
};

using salt_t = ByteBuffer<std::array<std::byte, config::kSaltLength>>;
using nonce_t = ByteBuffer<std::array<std::byte, config::kNonceLength>>;
using master_key_t = ByteBuffer<std::array<std::byte, config::kKeyLength>>;

auto LoadOrGenerateSaltAndNonce(std::string_view vault_path, salt_t& salt,
                                nonce_t& nonce) -> void {
  if (std::filesystem::exists(vault_path)) {
    std::ifstream file_stream{vault_path.data(), std::ios::binary};
    if (not file_stream.is_open() or file_stream.fail()) {
      throw std::runtime_error{
          "Failed to open vault file for reading salt and nonce."};
    }

    file_stream.read(salt.GetCPtr<char>(), rng::size(salt));
    if (file_stream.gcount() != static_cast<std::streamsize>(rng::size(salt))) {
      throw std::runtime_error{"Failed to read full salt from vault file."};
    }

    file_stream.read(nonce.GetCPtr<char>(), rng::size(nonce));
    if (file_stream.gcount() !=
        static_cast<std::streamsize>(rng::size(nonce))) {
      throw std::runtime_error{"Failed to read full nonce from vault file."};
    }
  } else {
    rng::generate(salt, GenerateRandomByte);
    rng::generate(nonce, GenerateRandomByte);
  }
}

}  // namespace

export namespace pm {

struct Context {
  std::string_view vault_path;
  salt_t salt;
  nonce_t nonce;
  master_key_t master_key;
};

auto format_as(Context const& context) -> std::string {
  return fmt::format("Context:\n salt: {}\n nonce: {}\n master_key: {}",
                     context.salt, context.nonce, context.master_key);
}

auto Authorize(std::string_view master_password, std::string_view vault_path)
    -> Context {
  Context context{};
  context.vault_path = vault_path;
  LoadOrGenerateSaltAndNonce(vault_path, context.salt, context.nonce);

  int pwhash_status{crypto_pwhash(
      context.master_key.GetCPtr<unsigned char>(),
      rng::size(context.master_key), master_password.data(),
      rng::size(master_password),
      context.salt.GetCConstPtr<unsigned char const>(),
      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT)};
  if (pwhash_status != 0) {
    throw std::runtime_error{fmt::format(
        "Key derivation failed with pwhash_status = {}", pwhash_status)};
  }

  return context;
}

class PasswordsStore final {
 public:
  constexpr explicit PasswordsStore(Context const& context)
      : m_context{context} {
    if (std::filesystem::exists(m_context.vault_path)) {
      auto plain_text{LoadAndDecrypt()};
      m_passwords = uzleo::json::Parse(std::string_view{
          plain_text.GetCConstPtr<char const>(), rng::size(plain_text)});
    } else {
      Add("foo", "bar");
    }
  }

  constexpr auto List() const -> void {
    if (m_passwords.IsType<std::monostate>()) {
      fmt::println("{}", m_passwords);
    } else {
      for (auto const& [key, password] : m_passwords.GetMap()) {
        fmt::println("{} : {}", key, password.GetStringView());
      }
    }
  }

  [[nodiscard]] constexpr auto Get(std::string_view key) const {
    return m_passwords.GetMap().at(std::string{key}).GetStringView();
  }

  constexpr auto Delete(std::string_view key) -> void {
    uzleo::json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap() | std::views::filter([key](auto const& kvp) {
          return (kvp.first != key);
        }),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, uzleo::json::Json> {
          return {kvp.first, uzleo::json::Json{kvp.second.GetStringView()}};
        });

    m_passwords = uzleo::json::Json{std::move(new_passwords)};
    EncryptAndSave();
  }

  constexpr auto Add(std::string_view key, std::string_view password) -> void {
    uzleo::json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap(),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, uzleo::json::Json> {
          return {kvp.first, uzleo::json::Json{kvp.second.GetStringView()}};
        });
    new_passwords.emplace(key, uzleo::json::Json{password});

    m_passwords = uzleo::json::Json{std::move(new_passwords)};
    EncryptAndSave();
  }

 private:
  constexpr auto EncryptAndSave() -> void {
    auto const plain_text{fmt::format("{}", m_passwords)};
    ByteBuffer<std::vector<std::byte>> cipher_text;
    cipher_text.resize(rng::size(plain_text) + crypto_secretbox_MACBYTES);

    rng::generate(m_context.nonce, GenerateRandomByte);

    auto encryption_status{crypto_secretbox_easy(
        cipher_text.GetCPtr<unsigned char>(),
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
        // NOTE: <char const*> to <unsigned char const *> is safe
        reinterpret_cast<unsigned char const*>(plain_text.data()),
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
        rng::size(plain_text),
        m_context.nonce.GetCConstPtr<unsigned char const>(),
        m_context.master_key.GetCConstPtr<unsigned char const>())};
    if (encryption_status != 0) {
      throw std::runtime_error(
          fmt::format("encryption failed with status: {}", encryption_status));
    }

    std::ofstream file_stream{m_context.vault_path.data(), std::ios::binary};
    if (not file_stream.is_open() or file_stream.fail()) {
      throw std::runtime_error{"Failed to open vault file for encryption."};
    }

    file_stream.write(m_context.salt.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(rng::size(m_context.salt)));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write salt to vault file."};
    }

    file_stream.write(m_context.nonce.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(rng::size(m_context.nonce)));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write nonce to vault file."};
    }

    file_stream.write(cipher_text.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(rng::size(cipher_text)));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write cipher-text to vault file."};
    }
  }

  [[nodiscard]] constexpr auto LoadAndDecrypt() const
      -> ByteBuffer<std::vector<std::byte>> {
    // load cipher-text from disk
    std::ifstream file_stream{m_context.vault_path.data(),
                              std::ios::binary bitor std::ios::ate};
    if (not file_stream.is_open() or file_stream.fail()) {
      throw std::runtime_error{"Failed to open vault file for decryption."};
    }

    auto const file_size{file_stream.tellg()};
    if (file_size <
        static_cast<std::streamoff>(config::kSaltLength + config::kNonceLength +
                                    crypto_secretbox_MACBYTES)) {
      throw std::runtime_error{"Vault file too small or corrupted."};
    }

    file_stream.seekg(config::kSaltLength + config::kNonceLength,
                      std::ios::beg);
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to seek within vault file."};
    }

    auto const cipher_length{static_cast<std::size_t>(file_size) -
                             (config::kSaltLength + config::kNonceLength)};
    ByteBuffer<std::vector<std::byte>> cipher_text;
    cipher_text.resize(cipher_length);
    file_stream.read(cipher_text.GetCPtr<char>(),
                     static_cast<std::streamsize>(cipher_length));
    if (file_stream.gcount() != static_cast<std::streamsize>(cipher_length)) {
      throw std::runtime_error{"Failed to read full cipher text from vault."};
    }

    // decrypt cipher-text to retrieve plain-text
    ByteBuffer<std::vector<std::byte>> plain_text;
    plain_text.resize(rng::size(cipher_text) - crypto_secretbox_MACBYTES);

    auto decrypt_status{crypto_secretbox_open_easy(
        plain_text.GetCPtr<unsigned char>(),
        cipher_text.GetCConstPtr<unsigned char const>(), rng::size(cipher_text),
        m_context.nonce.GetCConstPtr<unsigned char const>(),
        m_context.master_key.GetCConstPtr<unsigned char const>())};
    if (decrypt_status != 0) {
      throw std::runtime_error{
          fmt::format("Decryption failed with status: {}", decrypt_status)};
    }

    return plain_text;
  }

  Context m_context{};
  uzleo::json::Json m_passwords{uzleo::json::Json::json_object_t{}};
};

}  // namespace pm
