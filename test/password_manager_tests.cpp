#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

import password_manager;
import std;
import fmt;

namespace fs = std::filesystem;
namespace chr = std::chrono;

namespace {

auto MakeTemporaryVault(std::string const& prefix = "vault_test_") -> fs::path {
  return fs::temp_directory_path() /
         (prefix +
          std::to_string(
              chr::high_resolution_clock::now().time_since_epoch().count()));
}

auto const HasNonZero = [](auto const& buffer) {
  return std::any_of(buffer.begin(), buffer.end(), [](std::byte byte_val) {
    return byte_val != std::byte{0};
  });
};

}  // namespace

TEST_CASE("Authorize generates salt+nonce and derives a master key",
          "[Authorize]") {
  auto vault_path_string = MakeTemporaryVault().string();
  auto context = pm::Authorize("master", vault_path_string);

  REQUIRE(context.vault_path == vault_path_string);
  REQUIRE_FALSE(fs::exists(vault_path_string));
  REQUIRE(HasNonZero(context.salt));
  REQUIRE(HasNonZero(context.nonce));
  REQUIRE(HasNonZero(context.master_key));
}

TEST_CASE("PasswordsStore persists added and deleted passwords",
          "[PasswordsStore]") {
  auto vault_path_string = MakeTemporaryVault().string();
  std::string master = "mypass";

  std::uintmax_t size_after_add = 0;
  std::uintmax_t size_after_delete = 0;

  {
    auto context = pm::Authorize(master, vault_path_string);
    pm::PasswordsStore store(context);

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

  auto context2 = pm::Authorize(master, vault_path_string);
  pm::PasswordsStore store2(context2);
  REQUIRE(store2.Get("alpha") == "beta");
  REQUIRE_THROWS_AS(store2.Get("foo"), std::out_of_range);
  REQUIRE(fs::file_size(vault_path_string) == size_after_delete);
}
