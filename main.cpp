
import password_store;
import std;
import fmt;

auto main(int argc, char* argv[]) -> int {  // NOLINT(bugprone-exception-escape)
  if (argc < 2) {
    fmt::println("Usage:");
    fmt::println(" add <key> <password>");
    fmt::println(" get <key>");
    fmt::println(" list");
    fmt::println(" delete <key>");

    return 1;
  }

  pm::PasswordsStore ps{};
  ps.LoadPasswords();

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
    fmt::println("ERROR: invalid cli arguments.");
    return 2;
  }

  return 0;
}
