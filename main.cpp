
// SPDX-License-Identifier: MIT

// Objective
// -----------
// {account -> password} stored as encrypted blob on disk

// Features to do:
// [x] kill application (x)
// [ ] show passwords (s)
// [ ] add password (a)
// [ ] delete password (d)
// [ ] encryption of passwords before writing to disk

#include <fstream>
#include <string_view>
#include <print>
#include <iostream>
#include <expected>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// TODO: possibly make everything noexcept for faster code
// TODO: concept for PasswordsMap template type

namespace {

using password_map_t = std::unordered_map<std::string, std::string>;

std::string_view constexpr kPasswordFilePath{"/tmp/passwords.json"};

template <class password_map_t>
auto LoadPasswords() -> std::expected<password_map_t, std::string> {
  // NOTE: This might seem to be a unnecessary check but this routine is meant to be called rarely (e.g. at start of program) so this check can still be kept as
  // it will not have an performance impact.
  if (not std::filesystem::exists(kPasswordFilePath)) {
    std::ofstream password_f{kPasswordFilePath};
    if (not password_f.is_open()) {
      return std::unexpected{"Could not create an empty passwords file on specified path."};
    }

    password_f << R"({"foo": "bar"})" << '\n';
  }

  nlohmann::json password_j{};
  std::ifstream password_f{kPasswordFilePath};
  try {
    password_f >> password_j;
  } catch (std::exception const& e) {
    return std::unexpected{std::format("Passwords file seems corrupted as couldn't parse into json format. Exception: {}", e.what())};
  }

  password_map_t passwords_map{};
  std::ranges::transform(password_j.items(), std::inserter(passwords_map, std::end(passwords_map)),
                         [](auto const& entry) { return std::make_pair(entry.key(), entry.value()); });
  return passwords_map;
}

auto WelcomeScreen() {
  std::println("Welcome to Password Manager!!");
  std::println("a : add password entry");
  std::println("x : close app");
  std::println("S : show all managed passwords");
  std::println("");
}

auto UserInteraction(auto&& passwords_map) {
  using namespace std::literals;

  std::string input{};
  bool keep_going{true};

  std::unordered_map<std::string_view, std::function<void()>> const kActionMap{{"x"sv, [&keep_going]() { keep_going = false; }},
                                                                               {"S"sv, [&passwords_map]() {
                                                                                  std::println("Currently, I am managing following passwords:");
                                                                                  for (auto const& [k, v] : passwords_map) {
                                                                                    std::println("{} -> {}", k, v);
                                                                                  }
                                                                                }}};

  while (keep_going) {
    std::getline(std::cin, input);

    try {
      kActionMap.at(input)();
    } catch (std::exception const& ex) {
      std::println("The passed input is not supported yet. Please try again!");
      std::println("");
    }
  }

  return passwords_map;
}

auto SavePasswords(auto&& passwords_map) {
  // TODO: save passwords
}

}  // namespace

auto main() -> int {
  WelcomeScreen();

  // Loads current stored passwords from disk to memory for faster in-app access
  auto expected_passwords_map{LoadPasswords<password_map_t>()};
  if (not expected_passwords_map.has_value()) {
    spdlog::error(expected_passwords_map.error());
    return -1;
  }

  // Entering main user-interaction task
  auto passwords_map{UserInteraction<password_map_t>(std::move(expected_passwords_map.value()))};

  // Before finishing, we save the passwords back to disk
  SavePasswords(std::move(passwords_map));
}
