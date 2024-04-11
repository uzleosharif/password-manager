
// SPDX-License-Identifier: MIT

// Objective
// -----------
// {account -> password} stored as encrypted blob on disk

#include <fstream>
#include <string_view>
#include <print>
#include <future>
#include <iostream>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace {

std::string_view constexpr kPasswordFilePath{"/tmp/passwords.json"};

auto LoadPasswords() {
  // NOTE: This might seem to be a unnecessary check but this routine is meant to be called rarely (e.g. at start of program) so this check can still be kept as
  // it will not have an performance impact.
  if (not std::filesystem::exists(kPasswordFilePath)) {
    std::ofstream password_f{kPasswordFilePath};
    if (not password_f.is_open()) {
      spdlog::error("Could not create an empty passwords file on specified path.");
      return;
    }

    password_f << R"({"foo": "bar"})" << '\n';
  }

  nlohmann::json password_j{};
  std::ifstream password_f{kPasswordFilePath};
  try {
    password_f >> password_j;
  } catch (std::exception const& e) {
    spdlog::error("Passwords file seems corrupted as couldn't parse into json format. Exception: {}", e.what());
    return;
  }
  std::println("{}", password_j.dump());
}

auto UserInputTask() {
  while (true) {
    std::string input{};
    std::getline(std::cin, input);

    std::println("Processing user input: {}", input);
  }
}

}  // namespace

auto main() -> int {
  // load the current passowrds (json) file into memory
  LoadPasswords();

  // set up async tasks:
  // - one handling user input
  // - one reacting to user events

  auto user_input_task_f{std::async(std::launch::async, UserInputTask)};
  user_input_task_f.wait();
}
