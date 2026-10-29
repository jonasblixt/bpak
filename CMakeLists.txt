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
             LANGUAGES C
)

enable_testing()
set(CMAKE_C_STANDARD 99)

option(BPAK_BUILD_MINIMAL "Build a minimal version of the library" OFF)
option(BPAK_BUILD_TESTS "Build test cases" OFF)
option(BPAK_WERROR "Treat compiler warnings as errors" ON)
option(BPAK_BUILD_FUZZERS "Build the libFuzzer targets, requires clang" OFF)

add_compile_options(-Wall)
if (BPAK_WERROR)
    add_compile_options(-Werror)
endif()

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

add_subdirectory("lib")

# Test builds and python package builds with scikit-build-core, see
# pyproject.toml, build the C extension
if (BPAK_BUILD_TESTS OR SKBUILD)
    add_subdirectory("tools")
endif()

if (BPAK_BUILD_TESTS)
    # Python for the examples and the tests, tools/ finds it with the
    # components that the C extension needs
    find_package(Python 3.10 REQUIRED COMPONENTS Interpreter)
    add_subdirectory("examples")
    add_subdirectory("test")
endif()

# The fuzz targets, and their corpus as tests in test builds
if (BPAK_BUILD_TESTS OR BPAK_BUILD_FUZZERS)
    if (BPAK_BUILD_MINIMAL)
        message(FATAL_ERROR "BPAK_BUILD_FUZZERS requires BPAK_BUILD_MINIMAL=OFF")
    endif()
    add_subdirectory("test/fuzz")
endif()
