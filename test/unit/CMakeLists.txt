find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

set(UNIT_TESTS
    test_abi
    test_bsdiff
    test_crypto
    test_heatshrink
    test_merkle
    test_meta
    test_part
    test_pkg
    test_transport
    test_utils
    test_verify
)

# The helpers, built once, and the settings of all unit tests
add_library(test_helpers OBJECT test_helpers.c)

# Internal headers of the library
target_include_directories(test_helpers PUBLIC ${PROJECT_SOURCE_DIR}/lib)
target_compile_definitions(test_helpers PUBLIC
    BPAK_TEST_DATA_DIR="${BPAK_TEST_DATA_DIR}"
)
target_compile_options(test_helpers PUBLIC -fsanitize=address)
target_link_options(test_helpers PUBLIC -fsanitize=address)

# Link statically so tests can reach internal symbols (e.g. heatshrink)
target_link_libraries(test_helpers PUBLIC
    ${PROJECT_NAME}-static
    ${PROJECT_NAME}-vendor-names
    ${MBEDCRYPTO_LIBRARY}
    ${LZMA_LIBRARY}
    PkgConfig::CMOCKA
)

foreach(unit_test IN LISTS UNIT_TESTS)
    add_executable(${unit_test} ${unit_test}.c)
    target_link_libraries(${unit_test} PRIVATE test_helpers)

    add_test(NAME unit.${unit_test} COMMAND ${unit_test})
    set_tests_properties(unit.${unit_test} PROPERTIES LABELS unit)
endforeach()

# Every public header compiles on its own
file(GLOB PUBLIC_HEADERS RELATIVE ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/bpak/*.h
)
set(HEADER_SOURCES)
foreach(header IN LISTS PUBLIC_HEADERS)
    string(MAKE_C_IDENTIFIER ${header} name)
    set(source ${CMAKE_CURRENT_BINARY_DIR}/headers/${name}.c)
    file(GENERATE OUTPUT ${source} CONTENT "#include <${header}>\n")
    list(APPEND HEADER_SOURCES ${source})
endforeach()
add_library(test_headers OBJECT ${HEADER_SOURCES})
target_compile_options(test_headers PRIVATE -Wextra -pedantic)
target_link_libraries(test_headers PRIVATE ${PROJECT_NAME}-static)
