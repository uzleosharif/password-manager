
// SPDX-License_Identifier: MIT

import password_manager;
import std;
import fmt;

#include <termios.h>
#include <unistd.h>

namespace rng = std::ranges;

namespace {

auto GetArgs(int argc, char const** argv) {
  auto args_view{std::span(argv, argc) |
                 std::views::transform(
                     [](char const* arg) { return std::string_view{arg}; })};

  if (rng::size(args_view) < 2) {
    fmt::println("Usage:");
    fmt::println(" add <key> <password>");
    fmt::println(" get <key>");
    fmt::println(" list");
    fmt::println(" delete <key>");

    throw std::invalid_argument{"Incorrect usage."};
  }

  return args_view;
}

auto PromptMasterPassword() {
  fmt::print("Enter master password: ");

  // disable echo on user entered input so that he/she can't see password while
  // typing it in
  termios terminal_settings{};
  tcgetattr(STDIN_FILENO, &terminal_settings);
  terminal_settings.c_lflag and_eq (compl ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &terminal_settings);

  std::string password{};
  std::getline(std::cin, password);
  fmt::println("");

  return password;
}

auto ExtractPasswordFilePath() -> std::string_view {
  std::string_view constexpr kPasswordsEnvVar{"UPM_PASSWORDS_FILE_PATH"};

  auto const* passwords_file_path{std::getenv(kPasswordsEnvVar.data())};
  if (passwords_file_path == nullptr) {
    throw std::invalid_argument{
        fmt::format("Please set {} to specify the passwords-store file.",
                    kPasswordsEnvVar)};
  }

  return passwords_file_path;
}

auto ProcessInput(auto args_view) {
  pm::PasswordsStore password_store{
      pm::Authorize(PromptMasterPassword(), ExtractPasswordFilePath())};

  auto command{args_view[1]};
  if (command == "add" and rng::size(args_view) == 4) {
    password_store.Add(args_view[2], args_view[3]);
  } else if (command == "get" and rng::size(args_view) == 3) {
    fmt::println("{}", password_store.Get(args_view[2]));
  } else if (command == "list" and rng::size(args_view) == 2) {
    password_store.List();
  } else if (command == "delete" and rng::size(args_view) == 3) {
    password_store.Delete(args_view[2]);
  } else {
    throw std::runtime_error{"unknown command."};
  }
}

}  // namespace

auto main(int argc, char const** argv) -> int {
  try {
    ProcessInput(GetArgs(argc, argv));
  } catch (std::exception const& exception) {
    fmt::println("Exception: {}", exception.what());
    return 1;
  }

  return 0;
}
