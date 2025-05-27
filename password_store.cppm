
// SPDX-License-Identifier: MIT

export module password_store;

import uzleo.json;
import std;
import fmt;

export namespace pm {

class PasswordsStore final {
 public:
  constexpr auto Load(std::string_view passwords_file_path) {
    m_passwords_file_path = passwords_file_path;

    if (std::filesystem::exists(m_passwords_file_path)) {
      m_passwords = uzleo::json::Parse(m_passwords_file_path);
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

  [[nodiscard]] constexpr auto Get(std::string_view key) const {
    return m_passwords.GetMap().at(std::string{key}).GetStringView();
  }

  constexpr auto Delete(std::string_view key) {
    uzleo::json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap() | std::views::filter([key](auto const& kvp) {
          return (kvp.first != key);
        }),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, uzleo::json::Json> {
          return {kvp.first, uzleo::json::Json{kvp.second.GetStringView()}};
        });

    m_passwords = uzleo::json::Json{std::move(new_passwords)};
    Save();
  }

  constexpr auto Add(std::string_view key, std::string_view password) {
    uzleo::json::Json::json_object_t new_passwords{};
    std::ranges::transform(
        m_passwords.GetMap(),
        std::inserter(new_passwords, std::ranges::end(new_passwords)),
        [](auto const& kvp) -> std::pair<std::string, uzleo::json::Json> {
          return {kvp.first, uzleo::json::Json{kvp.second.GetStringView()}};
        });
    new_passwords.emplace(key, uzleo::json::Json{password});

    m_passwords = uzleo::json::Json{std::move(new_passwords)};
    Save();
  }

 private:
  constexpr auto Save() const -> void {
    std::ofstream file_stream{m_passwords_file_path.data()};
    file_stream.exceptions(std::ios::failbit | std::ios::badbit);
    file_stream << fmt::format("{}", m_passwords);
  }

  uzleo::json::Json m_passwords{uzleo::json::Json::json_object_t{}};
  std::string_view m_passwords_file_path;
};

}  // namespace pm
