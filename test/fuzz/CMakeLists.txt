# Fuzz targets for the code that parses untrusted input, see
# docs/development.md. BPAK_BUILD_FUZZERS builds them with libFuzzer, test
# builds run the corpus in corpus/<target> and the golden packages of the
# target with driver.c.
set(FUZZ_TARGETS
    bspatch
    header
    transport
    verify
)

set(GOLDEN_SET ${PROJECT_SOURCE_DIR}/test/golden/0.9.3)

set(FUZZ_DEFINITIONS
    BPAK_FUZZ_KEY_DIR="${GOLDEN_SET}/inputs"
    BPAK_FUZZ_ORIGIN="${GOLDEN_SET}/origin.bpak"
)

# Golden packages that are part of the seed corpus of a target, the header
# target only reads their header
set(FUZZ_GOLDEN_header basic keystore merkle patch)
set(FUZZ_GOLDEN_transport patch patch-lzma)
set(FUZZ_GOLDEN_verify
    basic merkle sha256-rsa4096 sha384-secp384r1 sha512-secp521r1
)

foreach(target IN LISTS FUZZ_TARGETS)
    if (BPAK_BUILD_FUZZERS)
        add_executable(fuzz_${target} fuzz_${target}.c)
        target_compile_definitions(fuzz_${target} PRIVATE ${FUZZ_DEFINITIONS})
        target_compile_options(fuzz_${target} PRIVATE
            -g -fsanitize=fuzzer,address,undefined
        )
        target_link_options(fuzz_${target} PRIVATE
            -fsanitize=fuzzer,address,undefined
        )
        target_link_libraries(fuzz_${target} PRIVATE ${PROJECT_NAME}-fuzz)
    endif()

    if (BPAK_BUILD_TESTS)
        add_executable(fuzz_${target}_corpus fuzz_${target}.c driver.c)
        target_compile_definitions(fuzz_${target}_corpus PRIVATE
            ${FUZZ_DEFINITIONS}
        )
        target_compile_options(fuzz_${target}_corpus PRIVATE -fsanitize=address)
        target_link_options(fuzz_${target}_corpus PRIVATE -fsanitize=address)
        target_link_libraries(fuzz_${target}_corpus PRIVATE
            ${PROJECT_NAME}-static
            ${MBEDCRYPTO_LIBRARY}
            ${LZMA_LIBRARY}
        )

        set(golden_packages)
        foreach(name IN LISTS FUZZ_GOLDEN_${target})
            list(APPEND golden_packages ${GOLDEN_SET}/${name}.bpak)
        endforeach()

        add_test(NAME fuzz.${target}
            COMMAND fuzz_${target}_corpus
                ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${target}
                ${golden_packages}
        )
        set_tests_properties(fuzz.${target} PROPERTIES LABELS fuzz)
    endif()
endforeach()
