
// SPDX-License-Identifier: MIT

// Objective
// -----------
// {account -> password} stored as encrypted blob on disk

#include <fstream>
#include <print>
#include <string_view>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace {

std::string_view constexpr kPasswordFilePath{"/home/ush/Documents/passwords.json"};

auto LoadPasswords() {
  if (not std::filesystem::exists(kPasswordFilePath)) {
    std::ofstream password_f{kPasswordFilePath};
  }

  try {
    auto passwords_j{nlohmann::json::parse(kPasswordFilePath)};
  } catch (std::exception const& e) {
    spdlog::error("Passwords file seems corrupted as couldn't parse into json format.");
  }
}

}  // namespace

auto main() -> int {
  // load the current passowrds (json) file into memory
  LoadPasswords();

  // wait for user input
  // -> seems async task -> co-routines but no compiler support i am afraid
}
