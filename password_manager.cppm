
// SPDX-License-Identifier: MIT

module;

#include <sodium.h>

export module password_manager;

import uzleo.json;
import std;
import fmt;

// TODO(uzleo): do error-handling around file-stream operations (saving,
// loading)

namespace rng = std::ranges;

namespace config {

constexpr std::size_t kSaltLength{crypto_pwhash_SALTBYTES};
constexpr std::size_t kNonceLength{crypto_secretbox_NONCEBYTES};
constexpr std::size_t kKeyLength{crypto_secretbox_KEYBYTES};

constexpr auto GetSaltPath(std::string_view passwords_file_path) {
  return std::string{passwords_file_path} + ".salt";
}

constexpr auto GetNoncePath(std::string_view passwords_file_path) {
  return std::string{passwords_file_path} + ".nonce";
}

}  // namespace config

namespace {

template <class Parent>
class ByteBuffer final : public Parent {
 public:
  template <class T>
  // TODO(uzleo): T should be constrained to be a char type
  [[nodiscard]] auto GetCConstPtr() const -> T* {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, typename Parent::value_type>,
                  "ByteBuffer must hold std::byte objects.");
    // NOTE: byte* to (char-like) T* is safe
    return reinterpret_cast<T*>(this->data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }

  template <class T>
  // TODO(uzleo): T should be constrained to be a char type
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

auto LoadOrGenerateSalt(std::string_view passwords_file_path) -> salt_t {
  salt_t salt{};

  auto const salt_path{config::GetSaltPath(passwords_file_path)};
  if (std::filesystem::exists(salt_path)) {
    std::ifstream file_stream{salt_path, std::ios::binary};
    rng::copy(
        rng::istream_view<std::uint8_t>{file_stream} |
            rng::views::take(rng::size(salt)) |
            rng::views::transform([](std::uint8_t const value) -> std::byte {
              return std::byte{value};
            }),
        rng::begin(salt));
  } else {
    rng::generate(salt, []() -> std::byte {
      static std::uniform_int_distribution<std::uint8_t> distr{};
      static std::random_device device{};
      static std::mt19937 engine{device()};
      return std::byte{distr(engine)};
    });

    std::ofstream file_stream{salt_path};
    file_stream.write(salt.GetCConstPtr<char const>(), rng::size(salt));
  }

  return salt;
}

auto LoadOrGenerateNonce(std::string_view passwords_file_path) -> nonce_t {
  nonce_t nonce{};

  auto const nonce_path{config::GetNoncePath(passwords_file_path)};
  if (std::filesystem::exists(nonce_path)) {
    std::ifstream file_stream{nonce_path, std::ios::binary};
    rng::copy(
        rng::istream_view<std::uint8_t>{file_stream} |
            rng::views::take(rng::size(nonce)) |
            rng::views::transform([](std::uint8_t const value) -> std::byte {
              return std::byte{value};
            }),
        rng::begin(nonce));
  } else {
    std::ofstream file_stream{nonce_path};
    file_stream.write(nonce.GetCConstPtr<char const>(), rng::size(nonce));
  }

  return nonce;
}

}  // namespace

export namespace pm {

struct Context {
  std::string_view passwords_file_path;
  salt_t salt;
  nonce_t nonce;
  master_key_t master_key;
};

auto Authorize(std::string_view master_password,
               std::string_view passwords_file_path) {
  Context context{};
  context.passwords_file_path = passwords_file_path;
  context.salt = LoadOrGenerateSalt(passwords_file_path);
  context.nonce = LoadOrGenerateNonce(passwords_file_path);

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
    if (std::filesystem::exists(m_context.passwords_file_path)) {
      // decrypt realtext (json) from ciphertext
      m_passwords = uzleo::json::Parse(m_context.passwords_file_path);
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
    // TODO(uzleo)
    // SaveStringToDisk(m_context.passwords_file_path,
    //                  fmt::format("{}", m_passwords));
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

    // TODO(uzleo): increment nonce
    // m_context.nonce++;

    crypto_secretbox_easy(
        cipher_text.GetCPtr<unsigned char>(),
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
        // NOTE: <char const*> to <unsigned char const *> is safe
        reinterpret_cast<unsigned char const*>(plain_text.data()),
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
        rng::size(plain_text),
        m_context.nonce.GetCConstPtr<unsigned char const>(),
        m_context.master_key.GetCConstPtr<unsigned char const>());

    std::ofstream file_stream{m_context.passwords_file_path.data(),
                              std::ios::binary};
    file_stream.write(cipher_text.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(rng::size(cipher_text)));
    // TODO(uzleo): also save nonce file
  }

  Context m_context{};
  uzleo::json::Json m_passwords{uzleo::json::Json::json_object_t{}};
};

}  // namespace pm
