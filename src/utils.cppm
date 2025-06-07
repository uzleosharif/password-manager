
// SPDX-License-Identifier: MIT

export module utils;

import std;

export namespace uzleo::utils {

template <class T>
concept CharLike = std::same_as<std::remove_cv_t<T>, char> or
                   std::same_as<std::remove_cv_t<T>, char8_t> or
                   std::same_as<std::remove_cv_t<T>, unsigned char> or
                   std::same_as<std::remove_cv_t<T>, signed char>;

template <class Parent>
class ByteBuffer final : public Parent {
 public:
  template <CharLike T>
  [[nodiscard]] constexpr auto GetCConstPtr() const -> T* {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, typename Parent::value_type>,
                  "ByteBuffer must hold std::byte objects.");
    // NOTE: byte* to (char-like) T* is safe
    return reinterpret_cast<T*>(this->data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }

  template <CharLike T>
  [[nodiscard]] constexpr auto GetCPtr() -> T* {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    static_assert(std::is_same_v<std::byte, typename Parent::value_type>,
                  "ByteBuffer must hold std::byte objects.");
    // NOTE: byte* to (char-like) T* is safe
    return reinterpret_cast<T*>(this->data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  }
};

using DynamicByteBuffer = ByteBuffer<std::vector<std::byte>>;

template <std::size_t kSize>
using StaticByteBuffer = ByteBuffer<std::array<std::byte, kSize>>;

}  // namespace uzleo::utils
