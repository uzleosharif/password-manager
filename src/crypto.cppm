
// SPDX-License-Identifier: MIT

module;

#include <sodium.h>

export module crypto;

import std;
import utils;
import fmt;

namespace {
namespace utils = ::uzleo::utils;
namespace rng = std::ranges;
}  // namespace

export namespace pm {

class SodiumCrypto final {
 public:
  static constexpr std::size_t kSaltSize{crypto_pwhash_SALTBYTES};
  static constexpr std::size_t kNonceSize{crypto_secretbox_NONCEBYTES};
  static constexpr std::size_t kVaultSize{kSaltSize + kNonceSize +
                                          crypto_secretbox_MACBYTES};
  static constexpr std::size_t kMasterKeySize{crypto_secretbox_KEYBYTES};

  ~SodiumCrypto() = default;
  SodiumCrypto(SodiumCrypto const&) = delete;
  auto operator=(SodiumCrypto const&) = delete;
  SodiumCrypto(SodiumCrypto&&) = default;
  auto operator=(SodiumCrypto&&) -> SodiumCrypto& = default;

  constexpr SodiumCrypto() {
    if (sodium_init() < 0) {
      throw std::runtime_error{"sodium_init failed"};
    }
    randombytes_buf(m_salt.data(), kSaltSize);
    randombytes_buf(m_nonce.data(), kNonceSize);
  }

  constexpr SodiumCrypto(utils::StaticByteBuffer<kSaltSize> const& salt,
                         utils::StaticByteBuffer<kNonceSize> const& nonce)
      : m_salt{salt}, m_nonce{nonce} {
    if (sodium_init() < 0) {
      throw std::runtime_error{"sodium_init failed"};
    }
  }

  constexpr auto Authorize(std::string_view master_password) -> void {
    auto pwhash_status{crypto_pwhash(
        m_master_key.GetCPtr<unsigned char>(), kMasterKeySize,
        master_password.data(), rng::size(master_password),
        m_salt.GetCConstPtr<unsigned char const>(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT)};
    if (pwhash_status != 0) {
      throw std::runtime_error{fmt::format(
          "Key derivation failed with pwhash_status = {}", pwhash_status)};
    }
  }

  [[nodiscard]] constexpr auto Decrypt(
      utils::DynamicByteBuffer const& cipher_text) const
      -> utils::DynamicByteBuffer {
    utils::DynamicByteBuffer plain_text{};
    plain_text.resize(rng::size(cipher_text) - crypto_secretbox_MACBYTES);

    auto decrypt_status{crypto_secretbox_open_easy(
        plain_text.GetCPtr<unsigned char>(),
        cipher_text.GetCConstPtr<unsigned char const>(), rng::size(cipher_text),
        m_nonce.GetCConstPtr<unsigned char const>(),
        m_master_key.GetCConstPtr<unsigned char const>())};
    if (decrypt_status != 0) {
      throw std::runtime_error{
          fmt::format("Decryption failed with status: {}", decrypt_status)};
    }

    return plain_text;
  }

  [[nodiscard]] constexpr auto Encrypt(std::string_view plain_text)
      -> utils::DynamicByteBuffer {
    utils::DynamicByteBuffer cipher_text{};
    cipher_text.resize(rng::size(plain_text) + crypto_secretbox_MACBYTES);

    randombytes_buf(m_nonce.data(), kNonceSize);
    auto encrypt_status{crypto_secretbox_easy(
        cipher_text.GetCPtr<unsigned char>(),
        // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
        // NOTE: <char const*> to <unsigned char const *> is safe
        reinterpret_cast<unsigned char const*>(plain_text.data()),
        // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
        rng::size(plain_text), m_nonce.GetCConstPtr<unsigned char const>(),
        m_master_key.GetCConstPtr<unsigned char const>())};
    if (encrypt_status != 0) {
      throw std::runtime_error{
          fmt::format("encryption failed with status: {}", encrypt_status)};
    }

    return cipher_text;
  }

  [[nodiscard]] constexpr auto GetSalt() const -> std::span<std::byte const> {
    return m_salt;
  }

  [[nodiscard]] constexpr auto GetNonce() const -> std::span<std::byte const> {
    return m_nonce;
  }

 private:
  utils::StaticByteBuffer<kSaltSize> m_salt{};
  utils::StaticByteBuffer<kNonceSize> m_nonce{};
  utils::StaticByteBuffer<kMasterKeySize> m_master_key{};
};

}  // namespace pm
