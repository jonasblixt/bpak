cmake_minimum_required(VERSION 3.10)

# Extract version info from bpak.h
file(READ "include/bpak/bpak.h" ver)

string(REGEX MATCH ".+BPAK_VERSION_MAJOR ([0-9]*)" _ ${ver})
set(ver_major ${CMAKE_MATCH_1})

string(REGEX MATCH ".+BPAK_VERSION_MINOR ([0-9]*)" _ ${ver})
set(ver_minor ${CMAKE_MATCH_1})

string(REGEX MATCH ".+BPAK_VERSION_PATCH ([0-9]*)" _ ${ver})
set(ver_patch ${CMAKE_MATCH_1})

project(bpak VERSION ${ver_major}.${ver_minor}.${ver_patch}
             DESCRIPTION BitPacker
             HOMEPAGE_URL https://github.com/jonasblixt/bpak
)

enable_language(C)
enable_testing()
set(CMAKE_C_STANDARD 99)

add_compile_options(-Wall -Werror -fstack-usage)
include_directories(include/)

option(BPAK_BUILD_MINIMAL "Build a minial version of the library" OFF)
option(BPAK_BUILD_TOOL "Build the bpak tool" ON)
option(BPAK_BUILD_PYTHON_WRAPPER "Build the python wrapper" OFF)
option(BPAK_BUILD_TESTS "Build test cases" OFF)

# TODO: Choice option for BPAK_CRYPTO_BACKEND
#   Select between a pre-defined set of options

if (NOT BPAK_BUILD_MINIMAL)
    find_library(MBEDTLS_LIBRARY mbedtls)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
    find_library(UUID_LIBRARY uuid)
    find_library(LZMA_LIBRARY lzma)
endif()

if (BPAK_BUILD_TESTS)
    add_subdirectory("test")
    add_compile_options(-g -fprofile-arcs -ftest-coverage)
    link_libraries(gcov)
endif()

add_subdirectory("lib")

if ((NOT BPAK_BUILD_MINIMAL) AND BPAK_BUILD_TOOL)
    add_subdirectory("src")
endif()

if ((NOT BPAK_BUILD_MINIMAL) AND BPAK_BUILD_PYTHON_WRAPPER)
    add_subdirectory("python")
endif()

