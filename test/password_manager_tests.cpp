#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

import password_manager;
import utils;
import std;

namespace fs = std::filesystem;
namespace chr = std::chrono;

namespace {

namespace utils = ::uzleo::utils;

auto MakeTemporaryVault(std::string const& prefix = "vault_test_") -> fs::path {
  return fs::temp_directory_path() /
         (prefix +
          std::to_string(
              chr::high_resolution_clock::now().time_since_epoch().count()));
}

class MockCrypto final {
 public:
  static constexpr std::size_t kSaltSize{1};
  static constexpr std::size_t kNonceSize{1};
  static constexpr std::size_t kVaultSize{kSaltSize + kNonceSize + 1};
  static constexpr std::size_t kMasterKeySize{1};

  MockCrypto() = default;
  MockCrypto(utils::StaticByteBuffer<kSaltSize> const& salt,
             utils::StaticByteBuffer<kNonceSize> const& nonce)
      : m_salt{salt}, m_nonce{nonce} {
  }

  void Authorize(std::string_view master_password) {
    m_key = static_cast<std::byte>(master_password.size() % 256);
  }

  [[nodiscard]] auto Decrypt(utils::DynamicByteBuffer const& cipher_text) const
      -> utils::DynamicByteBuffer {
    auto len = static_cast<std::size_t>(
        std::to_integer<unsigned char>(cipher_text[0]));
    utils::DynamicByteBuffer plain;
    plain.resize(len);
    for (std::size_t i = 0; i < len; ++i) {
      plain[i] = static_cast<std::byte>(
          std::to_integer<unsigned char>(cipher_text[i + 1]) ^
          std::to_integer<unsigned char>(m_key));
    }
    return plain;
  }

  [[nodiscard]] auto Encrypt(std::string_view plain_text)
      -> utils::DynamicByteBuffer {
    utils::DynamicByteBuffer cipher;
    cipher.resize(plain_text.size() + 1);
    cipher[0] = static_cast<std::byte>(plain_text.size());
    for (std::size_t i = 0; i < plain_text.size(); ++i) {
      cipher[i + 1] =
          static_cast<std::byte>(static_cast<unsigned char>(plain_text[i]) ^
                                 std::to_integer<unsigned char>(m_key));
    }
    return cipher;
  }

  [[nodiscard]] auto GetSalt() const -> std::span<std::byte const> {
    return m_salt;
  }

  [[nodiscard]] auto GetNonce() const -> std::span<std::byte const> {
    return m_nonce;
  }

 private:
  utils::StaticByteBuffer<kSaltSize> m_salt{};
  utils::StaticByteBuffer<kNonceSize> m_nonce{};
  std::byte m_key{std::byte{0}};
};

}  // namespace

TEST_CASE("PasswordsStore persists added and deleted passwords",
          "[PasswordsStore]") {
  auto vault_path_string = MakeTemporaryVault().string();
  std::string master = "mypass";

  std::uintmax_t size_after_add = 0;
  std::uintmax_t size_after_delete = 0;

  {
    pm::PasswordsStore<MockCrypto> store(master, vault_path_string);

    REQUIRE(fs::exists(vault_path_string));
    REQUIRE(store.Get("foo") == "bar");

    auto size_initial = fs::file_size(vault_path_string);
    store.Add("alpha", "beta");
    REQUIRE(store.Get("alpha") == "beta");
    size_after_add = fs::file_size(vault_path_string);
    REQUIRE(size_after_add != size_initial);

    store.Delete("foo");
    size_after_delete = fs::file_size(vault_path_string);
    REQUIRE(size_after_delete != size_after_add);
    REQUIRE_THROWS_AS(store.Get("foo"), std::out_of_range);
  }

  pm::PasswordsStore<MockCrypto> store2(master, vault_path_string);
  REQUIRE(store2.Get("alpha") == "beta");
  REQUIRE_THROWS_AS(store2.Get("foo"), std::out_of_range);
  REQUIRE(fs::file_size(vault_path_string) == size_after_delete);
}
