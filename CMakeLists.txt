cmake_minimum_required(VERSION 3.10)

# Extract version info from bpak.h
file(READ "include/bpak/version.h" ver)

string(REGEX MATCH ".+BPAK_VERSION_MAJOR\ +([0-9]*)" _ ${ver})
set(ver_major ${CMAKE_MATCH_1})

string(REGEX MATCH ".+BPAK_VERSION_MINOR\ +([0-9]*)" _ ${ver})
set(ver_minor ${CMAKE_MATCH_1})

string(REGEX MATCH ".+BPAK_VERSION_PATCH\ +([0-9]*)" _ ${ver})
set(ver_patch ${CMAKE_MATCH_1})

project(bpak VERSION ${ver_major}.${ver_minor}.${ver_patch}
             DESCRIPTION BitPacker
             HOMEPAGE_URL https://github.com/jonasblixt/bpak
)

enable_language(C)
enable_testing()
set(CMAKE_C_STANDARD 99)

add_compile_options(-Wall -Werror)
include_directories(include/)

option(BPAK_BUILD_MINIMAL "Build a minial version of the library" OFF)
option(BPAK_BUILD_TOOL "Build the bpak tool" ON)
option(BPAK_BUILD_PYTHON_WRAPPER "Build the python wrapper" ON)
option(BPAK_BUILD_TESTS "Build test cases" OFF)

# TODO: Choice option for BPAK_CRYPTO_BACKEND
#   Select between a pre-defined set of options

if (NOT BPAK_BUILD_MINIMAL)
    set(BPAK_CONFIG_MERKLE 1)
    set(BPAK_CONFIG_LZMA 1)
    set(BPAK_CONFIG_MBEDTLS 1)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
    find_library(LZMA_LIBRARY lzma)
else()
    set(BPAK_CONFIG_MBEDTLS 0)
    set(BPAK_CONFIG_LZMA 0)
    set(BPAK_CONFIG_MERKLE 0)
endif()

if (BPAK_BUILD_TESTS)
    add_subdirectory("test")
    add_compile_options(-g -fprofile-arcs -ftest-coverage -fstack-usage)
    link_libraries(gcov)
endif()

add_subdirectory("lib")

if ((NOT BPAK_BUILD_MINIMAL) AND BPAK_BUILD_TOOL)
    add_subdirectory("src")
endif()

if ((NOT BPAK_BUILD_MINIMAL) AND BPAK_BUILD_PYTHON_WRAPPER)
    add_subdirectory("python")
endif()

