
// SPDX-License-Identifier: MIT

export module password_manager;

import uzleo.json;
import utils;
import std;
import fmt;

namespace rng = std::ranges;

namespace {

namespace json = ::uzleo::json;
namespace utils = ::uzleo::utils;

}  // namespace

export namespace pm {

template <class CryptoLibrary>
class PasswordsStore final {
  using salt_t = utils::StaticByteBuffer<CryptoLibrary::kSaltSize>;
  using nonce_t = utils::StaticByteBuffer<CryptoLibrary::kNonceSize>;

 public:
  ~PasswordsStore() = default;
  PasswordsStore(PasswordsStore&&) = default;
  auto operator=(PasswordsStore&&) -> PasswordsStore& = default;
  PasswordsStore(PasswordsStore const&) = delete;
  auto operator=(PasswordsStore const&) = delete;
  PasswordsStore() = delete;

  constexpr explicit PasswordsStore(std::string_view master_password,
                                    std::string_view vault_path)
      : m_vault_path{vault_path} {
    if (std::filesystem::exists(m_vault_path)) {
      auto [salt, nonce, cipher_text] = LoadVault();
      m_crypto_library = std::make_unique<CryptoLibrary>(salt, nonce);
      m_crypto_library->Authorize(master_password);
      auto plain_text{m_crypto_library->Decrypt(cipher_text)};
      m_passwords = json::Parse(
          std::string_view(plain_text.template GetCConstPtr<char const>(),
                           rng::size(plain_text)));
    } else {
      m_crypto_library = std::make_unique<CryptoLibrary>();
      m_crypto_library->Authorize(master_password);
      Add("foo", "bar");
    }
  }

  constexpr auto List() const -> void {
    if (m_passwords.IsType<std::monostate>()) {
      fmt::println("{}", m_passwords);
    } else {
      for (auto const& key : m_passwords.GetMap() | rng::views::keys) {
        fmt::println("{}", key);
      }
    }
  }

  [[nodiscard]] constexpr auto Get(std::string_view key) const {
    return m_passwords.GetMap().at(std::string{key}).GetStringView();
  }

  constexpr auto Delete(std::string_view key) -> void {
    json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap() | std::views::filter([key](auto const& kvp) {
          return (kvp.first != key);
        }),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, json::Json> {
          return {kvp.first, json::Json{kvp.second.GetStringView()}};
        });

    m_passwords = json::Json{std::move(new_passwords)};
    SaveVault(m_crypto_library->Encrypt(fmt::format("{}", m_passwords)));
  }

  constexpr auto Add(std::string_view key, std::string_view password) -> void {
    if (std::ranges::any_of(m_passwords.GetMap(), [key](auto const& kvp) {
          return kvp.first == key;
        })) {
      throw std::invalid_argument{fmt::format("key '{}' already exists", key)};
    }

    json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap(),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, json::Json> {
          return {kvp.first, json::Json{kvp.second.GetStringView()}};
        });
    new_passwords.emplace(key, json::Json{password});

    m_passwords = json::Json{std::move(new_passwords)};
    SaveVault(m_crypto_library->Encrypt(fmt::format("{}", m_passwords)));
  }

 private:
  [[nodiscard]] constexpr auto LoadVault() const
      -> std::tuple<salt_t, nonce_t, utils::DynamicByteBuffer> {
    std::ifstream file_stream{m_vault_path.data(),
                              std::ios::binary bitor std::ios::ate};
    if (not file_stream.is_open() or file_stream.fail()) {
      throw std::runtime_error{"Failed to open vault file for decryption."};
    }
    auto const file_size{file_stream.tellg()};
    if (file_size < static_cast<std::streamoff>(CryptoLibrary::kVaultSize)) {
      throw std::runtime_error{"Vault file too small or corrupted."};
    }
    auto const cipher_length{
        static_cast<std::size_t>(file_size) -
        (CryptoLibrary::kSaltSize + CryptoLibrary::kNonceSize)};
    file_stream.seekg(0, std::ios::beg);
    if (file_stream.fail()) {
      throw std::runtime_error{"failed to seek within vault file."};
    }

    salt_t salt{};
    nonce_t nonce{};
    utils::DynamicByteBuffer cipher_text;
    cipher_text.resize(cipher_length);

    file_stream.read(salt.template GetCPtr<char>(),
                     static_cast<std::streamsize>(CryptoLibrary::kSaltSize));
    if (file_stream.gcount() !=
        static_cast<std::streamsize>(CryptoLibrary::kSaltSize)) {
      throw std::runtime_error{"Failed to read salt from vault file."};
    }
    file_stream.read(nonce.template GetCPtr<char>(),
                     static_cast<std::streamsize>(CryptoLibrary::kNonceSize));
    if (file_stream.gcount() !=
        static_cast<std::streamsize>(CryptoLibrary::kNonceSize)) {
      throw std::runtime_error{"Failed to read nonce from vault file."};
    }
    file_stream.read(cipher_text.GetCPtr<char>(),
                     static_cast<std::streamsize>(cipher_length));
    if (file_stream.gcount() != static_cast<std::streamsize>(cipher_length)) {
      throw std::runtime_error{"Failed to read full cipher text from vault."};
    }

    return {salt, nonce, cipher_text};
  }

  constexpr auto SaveVault(utils::DynamicByteBuffer const& cipher_text) const
      -> void {
    std::ofstream file_stream{m_vault_path.data(), std::ios::binary};
    if (not file_stream.is_open() or file_stream.fail()) {
      throw std::runtime_error{"Failed to open vault file for encryption."};
    }

    // NOTE: we write the vault data as [salt | nonce | cipher-text]

    utils::ByteBuffer<std::span<std::byte const>> salt_span{
        m_crypto_library->GetSalt()};
    file_stream.write(salt_span.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(CryptoLibrary::kSaltSize));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write salt to vault file."};
    }

    utils::ByteBuffer<std::span<std::byte const>> nonce_span{
        m_crypto_library->GetNonce()};
    file_stream.write(nonce_span.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(CryptoLibrary::kNonceSize));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write nonce to vault file."};
    }

    file_stream.write(cipher_text.GetCConstPtr<char const>(),
                      static_cast<std::streamsize>(rng::size(cipher_text)));
    if (file_stream.fail()) {
      throw std::runtime_error{"Failed to write cipher-text to vault file."};
    }
  }

  std::string_view m_vault_path;
  std::unique_ptr<CryptoLibrary> m_crypto_library{nullptr};
  json::Json m_passwords{json::Json::json_object_t{}};
};

}  // namespace pm
