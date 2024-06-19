

cmake_minimum_required(VERSION 3.22)

project(password_manager CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-stdlib=libc++")

add_subdirectory(libs/json/)
add_subdirectory(libs/spdlog/)

add_executable(pm main.cpp)
target_link_libraries(pm PRIVATE nlohmann_json::nlohmann_json spdlog::spdlog)
