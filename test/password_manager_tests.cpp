

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
}

}  // namespace
