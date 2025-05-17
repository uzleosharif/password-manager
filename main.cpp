

import std;
import password_store;

auto main(int argc, char* argv[]) -> int {  // NOLINT(bugprone-exception-escape)
  if (argc < 2) {
    std::println("Usage:");
    std::println(" add <key> <password>");
    std::println(" get <key>");
    std::println(" list");
    std::println(" delete <key>");

    return 1;
  }

  std::filesystem::path const passwords_file_path{"/tmp/dummy_passwords.json"};

  std::string const command{argv[1]};
  if (command == "add" and argc == 4) {
    //
  } else if (command == "get" and argc == 3) {
    //
  } else if (command == "list" and argc == 2) {
    //
  } else if (command == "delete" and argc == 3) {
    //
  } else {
    std::println("ERROR: invalid cli arguments.");
    return 2;
  }

  return 0;
}
