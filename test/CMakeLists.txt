
add_compile_options(
        -fsanitize=address
        -DTEST_SRC_DIR="${CMAKE_SOURCE_DIR}/test"
)
add_link_options(-fsanitize=address)
include_directories(${CMAKE_SOURCE_DIR}/lib)

set(C_TESTS
    test_alignment
    test_bsdiff
    test_bsdiff_hs
    test_core_meta
    test_core_part
    test_merkle
    test_meta_align
    test_misc
    test_struct_sz
)

foreach(c_test IN LISTS C_TESTS)
    add_executable(${c_test} ${c_test}.c nala.c common.c)
    target_link_libraries(${c_test}
        ${PROJECT_NAME}
        ${MBEDTLS_LIBRARY}
        ${MBEDCRYPTO_LIBRARY}
        ${UUID_LIBRARY}
    )
    add_test(${c_test} ${c_test})
endforeach()

set(TEST_SCRIPTS
    test_misc.sh
    test_corrupt_header.sh
    test_corrupt_merkle_tree.sh
    test_corrupt_payload2.sh
    test_corrupt_payload.sh
    test_create.sh
    test_extract.sh
    test_generate_id.sh
    test_help_output.sh
    test_keystore_gen.sh
    test_multiple_bsdiff.sh
    test_openssl_resign.sh
    test_openssl_sign.sh
    test_set_string.sh
    test_sign_dont_hash.sh
    test_signec256.sh
    test_signec384.sh
    test_signec521.sh
    test_sign_rsa4096.sh
    test_transport.sh
    test_transport4.sh
    test_transport5.sh
    test_transport6.sh
    test_transport_lzma.sh
    test_python_transport.py
    test_python_create_package.py
    test_python_meta.py
    test_python_lib.py
)

foreach(test_script IN LISTS TEST_SCRIPTS)
    add_test(NAME ${test_script}
      COMMAND "${CMAKE_CURRENT_LIST_DIR}/${test_script}" "${CMAKE_SOURCE_DIR}"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/test")
endforeach()

