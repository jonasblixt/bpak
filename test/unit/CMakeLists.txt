find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)

set(UNIT_TESTS
    test_abi
    test_alg_heatshrink
    test_bsdiff
    test_core_meta
    test_core_part
    test_crypto
    test_merkle
    test_misc
    test_utils
    test_verify
)

foreach(unit_test IN LISTS UNIT_TESTS)
    add_executable(${unit_test} ${unit_test}.c test_helpers.c)

    # Internal headers of the library
    target_include_directories(${unit_test} PRIVATE ${PROJECT_SOURCE_DIR}/lib)
    target_compile_definitions(${unit_test} PRIVATE
        BPAK_TEST_DATA_DIR="${BPAK_TEST_DATA_DIR}"
    )
    target_compile_options(${unit_test} PRIVATE -fsanitize=address)
    target_link_options(${unit_test} PRIVATE -fsanitize=address)

    # Link statically so tests can reach internal symbols (e.g. heatshrink)
    target_link_libraries(${unit_test} PRIVATE
        ${PROJECT_NAME}-static
        ${MBEDCRYPTO_LIBRARY}
        ${LZMA_LIBRARY}
        PkgConfig::CMOCKA
    )

    add_test(NAME unit.${unit_test} COMMAND ${unit_test})
    set_tests_properties(unit.${unit_test} PROPERTIES LABELS unit)
endforeach()
