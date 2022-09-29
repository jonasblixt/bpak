include(GNUInstallDirs)

# @ONLY "Restrict variable replacement to references of the form @VAR@"
configure_file(${PROJECT_NAME}.pc.in ${PROJECT_NAME}.pc @ONLY)
configure_file(build_config.h.in
        ${${PROJECT_NAME}_BINARY_DIR}/lib/bpak/build_config.h @ONLY)

set(LIB_SRC_FILES
    bpak.c
    bpakcrc.c
    id.c
    keystore.c
    mem.c
    utils.c
)

# Every .h -file in include/bpak/ is a public header
file(GLOB_RECURSE LIB_PUBLIC_HEADERS "${CMAKE_SOURCE_DIR}/include/bpak/*.h")

set(LIB_PUBLIC_HEADERS
    ${LIB_PUBLIC_HEADERS}
    ${${PROJECT_NAME}_BINARY_DIR}/lib/bpak/build_config.h
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
        sais.c
        transport_decode.c
        transport_encode.c
        verify.c
        heatshrink/heatshrink_decoder.c
        heatshrink/heatshrink_encoder.c
        crypto.c
        mbedtls_wrapper.c
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

set(LIB_CFLAGS
    -Wextra -pedantic
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
)

target_compile_options(${PROJECT_NAME} PRIVATE ${LIB_CFLAGS})
target_compile_options(${PROJECT_NAME}-static PRIVATE ${LIB_CFLAGS})

set(LIB_LIBS ${UUID_LIBRARY})

if (NOT BPAK_BUILD_MINIMAL)
    set(LIB_LIBS
        ${LIB_LIBS}
        ${LZMA_LIBRARY}
        ${MBEDCRYPTO_LIBRARY}
    )
endif()

target_link_libraries(${PROJECT_NAME} ${LIB_LIBS})

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)

install(TARGETS ${PROJECT_NAME} ${PROJECT_NAME}-static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bpak
)
