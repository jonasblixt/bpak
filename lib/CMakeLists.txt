include(GNUInstallDirs)

# @ONLY "Restrict variable replacement to references of the form @VAR@"
configure_file(${PROJECT_NAME}.pc.in ${PROJECT_NAME}.pc @ONLY)

# Generated public headers, next to the public headers in include/bpak/ when
# installed
set(LIB_GENERATED_INCLUDE_DIR ${${PROJECT_NAME}_BINARY_DIR}/include)
configure_file(build_config.h.in
        ${LIB_GENERATED_INCLUDE_DIR}/bpak/build_config.h @ONLY)
configure_file(version.h.in
        ${LIB_GENERATED_INCLUDE_DIR}/bpak/version.h @ONLY)

set(LIB_SRC_FILES
    bpak.c
    crc.c
    id.c
    keystore.c
    mem.c
    utils.c
)

# Every .h -file in include/bpak/ is a public header
file(GLOB_RECURSE LIB_PUBLIC_HEADERS "${CMAKE_SOURCE_DIR}/include/bpak/*.h")

set(LIB_PUBLIC_HEADERS
    ${LIB_PUBLIC_HEADERS}
    ${LIB_GENERATED_INCLUDE_DIR}/bpak/build_config.h
    ${LIB_GENERATED_INCLUDE_DIR}/bpak/version.h
)
if (NOT BPAK_BUILD_MINIMAL)
    set(LIB_SRC_FILES
        ${LIB_SRC_FILES}
        bsdiff.c
        bspatch.c
        merkle.c
        pkg.c
        pkg_create.c
        pkg_sign.c
        pkg_verify.c
        transport_decode.c
        transport_encode.c
        verify.c
        crypto.c
        crypto_mbedtls.c
        keystore_file.c
        vendor/heatshrink/heatshrink_decoder.c
        vendor/heatshrink/heatshrink_encoder.c
        vendor/sais/sais.c
)
endif()

SET(CMAKE_C_VISIBILITY_PRESET hidden)

add_library(
    ${PROJECT_NAME} SHARED ${LIB_SRC_FILES}
)

add_library(
    ${PROJECT_NAME}-static STATIC ${LIB_SRC_FILES}
)

set_target_properties(${PROJECT_NAME}
    PROPERTIES
    PUBLIC_HEADER "${LIB_PUBLIC_HEADERS}"
)

set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(${PROJECT_NAME}-static PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

foreach(target ${PROJECT_NAME} ${PROJECT_NAME}-static)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${LIB_GENERATED_INCLUDE_DIR}>
    )
    target_compile_options(${target} PRIVATE -Wextra -pedantic)

    # Coverage of the library when the tests run, see docs/development.md
    if (BPAK_BUILD_TESTS)
        target_compile_options(${target} PRIVATE -g -fprofile-arcs -ftest-coverage)
        target_link_libraries(${target} gcov)
    endif()
endforeach()

set(LIB_LIBS)

if (NOT BPAK_BUILD_MINIMAL)
    set(LIB_LIBS
        ${LIB_LIBS}
        ${LZMA_LIBRARY}
        ${MBEDCRYPTO_LIBRARY}
    )
endif()

target_link_libraries(${PROJECT_NAME} ${LIB_LIBS})

# Built with the sanitizers of the fuzz targets in test/fuzz
if (BPAK_BUILD_FUZZERS)
    add_library(${PROJECT_NAME}-fuzz STATIC ${LIB_SRC_FILES})
    target_include_directories(${PROJECT_NAME}-fuzz PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${LIB_GENERATED_INCLUDE_DIR}
    )
    target_compile_options(${PROJECT_NAME}-fuzz PRIVATE
        -Wextra -pedantic -g -fsanitize=fuzzer-no-link,address,undefined
    )
    target_link_libraries(${PROJECT_NAME}-fuzz ${LIB_LIBS})
endif()

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

install(TARGETS ${PROJECT_NAME} ${PROJECT_NAME}-static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bpak
)
