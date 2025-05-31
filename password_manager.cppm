
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
constexpr std::size_t kKeyLength{crypto_secretbox_KEYBYTES};

constexpr auto GetSaltPath(std::string_view passwords_file_path) {
  return std::string{passwords_file_path} + ".salt";
}

constexpr auto GetNoncePath(std::string_view passwords_file_path) {
  return std::string{passwords_file_path} + ".nonce";
}

}  // namespace config

namespace {

auto SaveStringToDisk(std::string_view file_path, std::string_view content) {
  std::ofstream file_stream{file_path.data()};
  // TODO(uzleo): make sure file is properly opened, if not throw
  file_stream.write(content.data(),
                    static_cast<std::streamsize>(rng::size(content)));
  // TODO(uzleo): make sure data is written properly, else throw
}

auto LoadOrGenerateSalt(std::string_view passwords_file_path)
    -> std::array<std::byte, config::kSaltLength> {
  std::array<std::byte, config::kSaltLength> salt{};

  auto const salt_path{config::GetSaltPath(passwords_file_path)};
  if (std::filesystem::exists(salt_path)) {
    std::ifstream file_stream{salt_path, std::ios::binary};
    rng::copy(
        rng::istream_view<std::uint8_t>{file_stream} |
            rng::views::take(config::kSaltLength) |
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

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, decltype(salt)::value_type>,
                  "salt variable must hold std::byte");
    // NOTE: byte* to char(like)* is safe
    std::string_view salt_sv{reinterpret_cast<char const*>(salt.data()),
                             rng::size(salt)};
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    SaveStringToDisk(salt_path, salt_sv);
  }

  return salt;
}

auto LoadOrGenerateNonce(std::string_view passwords_file_path)
    -> std::uint64_t {
  std::uint64_t nonce{0};

  auto const nonce_path{config::GetNoncePath(passwords_file_path)};
  if (std::filesystem::exists(nonce_path)) {
    std::ifstream file_stream{nonce_path, std::ios::binary};
    file_stream >> nonce;
  } else {
    std::ofstream file_stream{nonce_path};
    file_stream << nonce;
  }

  return nonce;
}

}  // namespace

export namespace pm {

struct Context {
  std::string_view passwords_file_path;
  std::array<std::byte, config::kSaltLength> salt;
  std::uint64_t nonce{0};
  std::array<std::byte, config::kKeyLength> key;
};

auto Authorize(std::string_view master_password,
               std::string_view passwords_file_path) {
  Context context{};
  context.passwords_file_path = passwords_file_path;
  context.salt = LoadOrGenerateSalt(passwords_file_path);
  context.nonce = LoadOrGenerateNonce(passwords_file_path);

  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
  static_assert(std::is_same_v<std::byte, decltype(context.key)::value_type>,
                "salt variable must hold std::byte");
  static_assert(std::is_same_v<std::byte, decltype(context.salt)::value_type>,
                "salt variable must hold std::byte");
  // NOTE: byte* to char(like)* is safe
  int pwhash_status{crypto_pwhash(
      reinterpret_cast<unsigned char*>(context.key.data()),
      rng::size(context.key), master_password.data(),
      rng::size(master_password),
      reinterpret_cast<unsigned char const*>(context.salt.data()),
      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_DEFAULT)};
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  if (pwhash_status != 0) {
    throw std::runtime_error{fmt::format(
        "Key derivation failed with pwhash_status = {}", pwhash_status)};
  }

  return context;
}

class PasswordsStore final {
 public:
  constexpr explicit PasswordsStore(Context const& context)
      : m_passwords_file_path{context.passwords_file_path} {
    Load();
  }

  constexpr auto List() const {
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

  constexpr auto Delete(std::string_view key) {
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
    SaveStringToDisk(m_passwords_file_path, fmt::format("{}", m_passwords));
  }

  constexpr auto Add(std::string_view key, std::string_view password) {
    uzleo::json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap(),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, uzleo::json::Json> {
          return {kvp.first, uzleo::json::Json{kvp.second.GetStringView()}};
        });
    new_passwords.emplace(key, uzleo::json::Json{password});

    m_passwords = uzleo::json::Json{std::move(new_passwords)};
    SaveStringToDisk(m_passwords_file_path, fmt::format("{}", m_passwords));
  }

 private:
  constexpr auto Load() -> void {
    if (std::filesystem::exists(m_passwords_file_path)) {
      m_passwords = uzleo::json::Parse(m_passwords_file_path);
    }
  }

  uzleo::json::Json m_passwords{uzleo::json::Json::json_object_t{}};
  std::string_view m_passwords_file_path;
};

}  // namespace pm
