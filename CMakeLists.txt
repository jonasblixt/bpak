cmake_minimum_required(VERSION 3.10)

# version.txt is the single source of the project version
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" BPAK_VERSION LIMIT_COUNT 1)

if (NOT BPAK_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR
        "version.txt must contain MAJOR.MINOR.PATCH, got '${BPAK_VERSION}'")
endif()

# Re-run cmake when the version changes
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS version.txt)

project(bpak VERSION ${BPAK_VERSION}
             DESCRIPTION BitPacker
             HOMEPAGE_URL https://github.com/jonasblixt/bpak
)

enable_language(C)
enable_testing()
set(CMAKE_C_STANDARD 99)

find_package(PkgConfig REQUIRED)

add_compile_options(-Wall -Werror)
include_directories(include/)

option(BPAK_BUILD_MINIMAL "Build a minial version of the library" OFF)
option(BPAK_BUILD_TOOL "Build the bpak tool" ON)
option(BPAK_BUILD_TESTS "Build test cases" OFF)

# TODO: Choice option for BPAK_CRYPTO_BACKEND
#   Select between a pre-defined set of options

if (NOT BPAK_BUILD_MINIMAL)
    set(BPAK_CONFIG_MERKLE 1)
    set(BPAK_CONFIG_LZMA 1)
    set(BPAK_CONFIG_MBEDTLS 1)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto REQUIRED)
    find_library(LZMA_LIBRARY lzma REQUIRED)
else()
    set(BPAK_CONFIG_MBEDTLS 0)
    set(BPAK_CONFIG_LZMA 0)
    set(BPAK_CONFIG_MERKLE 0)
endif()

if (BPAK_BUILD_TESTS)
    add_subdirectory("python")
    add_subdirectory("test")
    add_compile_options(-g -fprofile-arcs -ftest-coverage -fstack-usage)
    link_libraries(gcov)
endif()

add_subdirectory("lib")

if ((NOT BPAK_BUILD_MINIMAL) AND BPAK_BUILD_TOOL)
    add_subdirectory("src")
endif()
