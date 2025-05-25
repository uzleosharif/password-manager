
import password_store;
import std;
import fmt;

auto main(int argc, char const** argv)
    -> int {  // NOLINT(bugprone-exception-escape)
  if (argc < 2) {
    fmt::println("Usage:");
    fmt::println(" add <key> <password>");
    fmt::println(" get <key>");
    fmt::println(" list");
    fmt::println(" delete <key>");

    return 1;
  }
  auto argv_span{std::span(argv, argc) |
                 std::views::transform(
                     [](char const* arg) { return std::string_view{arg}; })};

  pm::PasswordsStore password_store{};
  password_store.Load();

  auto command{argv_span[1]};
  if (command == "add" and argc == 4) {
    //
  } else if (command == "get" and argc == 3) {
    //
  } else if (command == "list" and argc == 2) {
    password_store.List();
  } else if (command == "delete" and argc == 3) {
    //
  } else {
    fmt::println("ERROR: invalid cli arguments.");
    return 2;
  }

  return 0;
}
