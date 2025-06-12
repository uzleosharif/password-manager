// SPDX-License-Identifier: MIT

module;

#include <sodium.h>

export module password_generator;

import std;

namespace rng = std::ranges;

export namespace pm {

inline constexpr std::string_view kDefaultCharset{
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"};

inline constexpr std::size_t kDefaultLength{16};

inline auto GeneratePassword(std::size_t length = kDefaultLength,
                             std::string_view charset = kDefaultCharset)
    -> std::string {
  if (charset.empty()) {
    throw std::invalid_argument{"charset cannot be empty"};
  }

  if (sodium_init() < 0) {
    throw std::runtime_error{"sodium_init failed"};
  }

  std::string password;
  password.resize(length);

  for (std::size_t i = 0; i < length; ++i) {
    unsigned char byte{};
    randombytes_buf(&byte, 1);
    password[i] = charset[byte % charset.size()];
  }

  return password;
}

} // namespace pm

