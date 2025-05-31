cmake_minimum_required(VERSION 3.15)
project(CPlusPass LANGUAGES CXX)

set(TARGET_NAME CPlusPass)

# Use C++23 and require a conforming compiler
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find libsodium via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Source files
set(SOURCES
  src/main.cpp
  src/crypto_engine.cpp
  src/ciphertext.cpp
)

# Define the executable
add_executable(${TARGET_NAME} ${SOURCES})

target_include_directories(${TARGET_NAME} PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(${TARGET_NAME} PRIVATE
  ${SODIUM_CFLAGS_OTHER}
)

# Link against libsodium
target_link_libraries(${TARGET_NAME} PRIVATE
  ${SODIUM_LIBRARIES}
)
