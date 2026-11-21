# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.16)
project(baccarat_sdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE AND NOT OPENSSL_ROOT_DIR)
  if(EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
  elseif(EXISTS "/usr/local/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
  endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_library(baccarat_sdk STATIC src/sdk.cpp)
target_include_directories(baccarat_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(baccarat_sdk PUBLIC OpenSSL::Crypto CURL::libcurl Threads::Threads)
target_compile_options(baccarat_sdk PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(baccarat_sdk_tests tests/sdk_test.cpp)
target_link_libraries(baccarat_sdk_tests PRIVATE baccarat_sdk)
target_compile_options(baccarat_sdk_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(
  NAME baccarat_sdk_tests
  COMMAND baccarat_sdk_tests
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
