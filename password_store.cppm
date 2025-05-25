

export module password_store;

import uzleo.json;
import std;
import fmt;

export namespace pm {

class PasswordsStore final {
 public:
  constexpr auto Load() {
    auto const* passwords_file_path{std::getenv("UPM_PASSWORDS_FILE_PATH")};
    if (passwords_file_path == nullptr) {
      throw std::invalid_argument{
          "Please set UPM_PASSWORDS_FILE_PATH to "
          "specify the passwords-store file."};
    }

    if (std::filesystem::exists(passwords_file_path)) {
      m_passwords = uzleo::json::Parse(passwords_file_path);
    }
  }

  constexpr auto List() const {
    if (m_passwords.IsType<std::monostate>()) {
      fmt::println("{}", m_passwords);
    } else {
      for (auto const& [key, password] : m_passwords.GetMap()) {
        fmt::println("{} : {}", key, password.GetStringView());
      }
    }
  }

  constexpr auto Get(std::string_view key) {
    return m_passwords.GetMap().at(std::string{key}).GetStringView();
  }

 private:
  uzleo::json::Json m_passwords{std::monostate{}};
};

}  // namespace pm
