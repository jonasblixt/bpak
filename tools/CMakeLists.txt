# The C extension bpak._bpak of the python package in tools/bpak.
#
# Wheels, built by scikit-build-core (see pyproject.toml), link the static
# library into the extension. Test builds link it against the shared library
# and assemble the package in the build directory, tools/bpak/ with the
# extension and links to the python sources.

if (CMAKE_VERSION VERSION_LESS 3.18)
    message(FATAL_ERROR "The python package requires CMake 3.18 or later")
endif()

find_package(Python 3.10 REQUIRED COMPONENTS Interpreter Development.Module)

python_add_library(${PROJECT_NAME}-python-wrapper MODULE WITH_SOABI
    _bpak/module.c
    _bpak/exceptions.c
    _bpak/package.c
    _bpak/meta.c
    _bpak/part.c
)

target_compile_options(${PROJECT_NAME}-python-wrapper PRIVATE -Wextra -pedantic)

set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES
    OUTPUT_NAME _${PROJECT_NAME}
)

if (SKBUILD)
    set_target_properties(${PROJECT_NAME}-static PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )

    target_link_libraries(${PROJECT_NAME}-python-wrapper PRIVATE
        ${PROJECT_NAME}-static
        ${LZMA_LIBRARY}
        ${MBEDCRYPTO_LIBRARY}
    )

    install(TARGETS ${PROJECT_NAME}-python-wrapper
        LIBRARY DESTINATION ${PROJECT_NAME}
        COMPONENT python
    )
else()
    set(PACKAGE_DIR ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

    target_link_libraries(${PROJECT_NAME}-python-wrapper PRIVATE ${PROJECT_NAME})

    set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${PACKAGE_DIR}
    )

    file(GLOB PACKAGE_SOURCES LIST_DIRECTORIES false CONFIGURE_DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}/*
    )

    file(MAKE_DIRECTORY ${PACKAGE_DIR})
    foreach(source IN LISTS PACKAGE_SOURCES)
        get_filename_component(name ${source} NAME)
        file(CREATE_LINK ${source} ${PACKAGE_DIR}/${name} SYMBOLIC)
    endforeach()
endif()
