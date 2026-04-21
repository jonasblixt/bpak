include(GNUInstallDirs)

find_package(Python 3.6
    COMPONENTS Interpreter Development
)

set(_BPAK_PY_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpak")

# Stage the pure-Python package layout inside the build tree so that
# `sys.path.insert(0, "../python/") ; import bpak` resolves to a complete
# package rooted at ${CMAKE_CURRENT_BINARY_DIR}/bpak/, with the compiled
# extension placed alongside __init__.py as bpak._bpak.
file(MAKE_DIRECTORY "${_BPAK_PY_BUILD_DIR}/_cli")

set(_BPAK_PY_TOP_FILES
    __init__.py
    __main__.py
    _helpers.py
)
set(_BPAK_PY_CLI_FILES
    _cli/__init__.py
    _cli/_common.py
    _cli/add.py
    _cli/compare.py
    _cli/create.py
    _cli/delete.py
    _cli/extract.py
    _cli/generate.py
    _cli/set.py
    _cli/show.py
    _cli/sign.py
    _cli/transport.py
)

set(_BPAK_PY_STAGED_OUTPUTS)
foreach(_src IN LISTS _BPAK_PY_TOP_FILES _BPAK_PY_CLI_FILES)
    set(_in "${CMAKE_CURRENT_SOURCE_DIR}/bpak/${_src}")
    set(_out "${_BPAK_PY_BUILD_DIR}/${_src}")
    add_custom_command(
        OUTPUT "${_out}"
        COMMAND ${CMAKE_COMMAND} -E copy "${_in}" "${_out}"
        DEPENDS "${_in}"
        COMMENT "Staging Python source: ${_src}"
    )
    list(APPEND _BPAK_PY_STAGED_OUTPUTS "${_out}")
endforeach()

add_custom_target(${PROJECT_NAME}-python-sources ALL
    DEPENDS ${_BPAK_PY_STAGED_OUTPUTS})

# Build the CPython extension `bpak._bpak`. The init function in
# python_wrapper.c is PyInit__bpak, which Python expects from a module
# file named `_bpak`, so name the output accordingly.
Python_add_library(
    ${PROJECT_NAME}-python-wrapper MODULE
    python_wrapper.c
    package.c
    meta.c
    part.c
)

target_include_directories(${PROJECT_NAME}-python-wrapper PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${Python_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}-python-wrapper PRIVATE
    ${PROJECT_NAME}
)

target_compile_options(${PROJECT_NAME}-python-wrapper PRIVATE
    -Wextra -pedantic
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
)

set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES
    OUTPUT_NAME "_bpak"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${_BPAK_PY_BUILD_DIR}"
)

add_dependencies(${PROJECT_NAME}-python-wrapper
    ${PROJECT_NAME}-python-sources)
