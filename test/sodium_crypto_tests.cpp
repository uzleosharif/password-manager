#include <catch2/catch_all.hpp>

import crypto;
import utils;
import std;

namespace {

namespace utils = ::uzleo::utils;

}

TEST_CASE("SodiumCrypto encrypts and decrypts correctly", "[SodiumCrypto]") {
  pm::SodiumCrypto crypto{};
  crypto.Authorize("master");

  std::string_view plain_text{"hello world"};
  auto cipher = crypto.Encrypt(plain_text);
  auto decrypted = crypto.Decrypt(cipher);

  REQUIRE(std::string_view(decrypted.GetCPtr<const char>(), decrypted.size()) ==
          plain_text);
}

TEST_CASE("SodiumCrypto decrypts data with same salt/nonce", "[SodiumCrypto]") {
  pm::SodiumCrypto crypto1{};
  crypto1.Authorize("master");
  auto cipher = crypto1.Encrypt("data");

  utils::StaticByteBuffer<pm::SodiumCrypto::kSaltSize> salt{};
  std::ranges::copy(crypto1.GetSalt(), salt.begin());
  utils::StaticByteBuffer<pm::SodiumCrypto::kNonceSize> nonce{};
  std::ranges::copy(crypto1.GetNonce(), nonce.begin());

  pm::SodiumCrypto crypto2{salt, nonce};
  crypto2.Authorize("master");

  auto plain = crypto2.Decrypt(cipher);
  REQUIRE(std::string_view(plain.GetCPtr<const char>(), plain.size()) ==
          "data");
}

TEST_CASE("SodiumCrypto fails with wrong password", "[SodiumCrypto]") {
  pm::SodiumCrypto crypto{};
  crypto.Authorize("master");
  auto cipher = crypto.Encrypt("secret");

  utils::StaticByteBuffer<pm::SodiumCrypto::kSaltSize> salt{};
  std::ranges::copy(crypto.GetSalt(), salt.begin());
  utils::StaticByteBuffer<pm::SodiumCrypto::kNonceSize> nonce{};
  std::ranges::copy(crypto.GetNonce(), nonce.begin());

  pm::SodiumCrypto crypto_wrong{salt, nonce};
  crypto_wrong.Authorize("wrong");

  REQUIRE_THROWS_AS(crypto_wrong.Decrypt(cipher), std::runtime_error);
}
