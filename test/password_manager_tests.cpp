

#define CATCH_CONFIG_MAIN

#include <catch2/catch_all.hpp>

import password_manager;
import std;

namespace fs = std::filesystem;
namespace chr = std::chrono;

namespace {

auto MakeTemporaryVault(std::string const& prefix = "vault_test_") -> fs::path {
  return fs::temp_directory_path() /
         (prefix + std::to_string(std::chrono::high_resolution_clock::now()
                                      .time_since_epoch()
                                      .count()));
}

TEST_CASE("Authorize generates salt+nonce and derives a master key",
          "[Authorize]") {
  auto const vault = MakeTemporaryVault();
  auto const password = std::string{"test_password"};

  auto const ctx = pm::Authorize(password, vault.string());

  REQUIRE(ctx.vault_path == vault.string());
  REQUIRE(std::ranges::any_of(ctx.salt, [](std::byte b) { return b != std::byte{}; }));
  REQUIRE(std::ranges::any_of(ctx.nonce, [](std::byte b) { return b != std::byte{}; }));
  REQUIRE(std::ranges::any_of(ctx.master_key, [](std::byte b) { return b != std::byte{}; }));
}

TEST_CASE("PasswordsStore basic CRUD", "[PasswordsStore]") {
  auto const vault = MakeTemporaryVault();
  auto const ctx = pm::Authorize("pw", vault.string());
  pm::PasswordsStore store{ctx};

  auto const key = std::string{"key1"};
  auto const value = std::string{"value1"};

  store.Add(key, value);
  REQUIRE(store.Get(key) == value);

  store.Delete(key);
  REQUIRE_THROWS_AS(store.Get(key), std::out_of_range);
}

}  // namespace
