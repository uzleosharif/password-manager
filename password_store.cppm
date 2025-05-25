

export module password_store;

import uzleo.json;
import std;

export namespace pm {

class PasswordsStore final {
 public:
  auto LoadPasswords() {
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

 private:
  uzleo::json::Json m_passwords{std::monostate{}};
};

}  // namespace pm
