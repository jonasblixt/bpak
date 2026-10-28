if (BPAK_BUILD_MINIMAL)
    message(FATAL_ERROR "BPAK_BUILD_TESTS requires BPAK_BUILD_MINIMAL=OFF")
endif()

set(BPAK_TEST_DATA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/data)

# C unit tests (cmocka)
add_subdirectory(unit)

# Tool and python wrapper tests (pytest)
find_package(Python 3.10 REQUIRED COMPONENTS Interpreter)

execute_process(
    COMMAND ${Python_EXECUTABLE} -c "import pytest"
    RESULT_VARIABLE PYTEST_MISSING
    OUTPUT_QUIET ERROR_QUIET
)

if (PYTEST_MISSING)
    message(FATAL_ERROR
        "pytest not found for ${Python_EXECUTABLE}. Install it with your "
        "package manager (e.g. python3-pytest) or run 'uv sync' and "
        "configure with the virtual environment in .venv activated")
endif()

# Each file is registered as a separate CTest test so 'ctest -j' runs them
# in parallel.
set(PYTEST_FILES
    cli/test_basic.py
    cli/test_corruption.py
    cli/test_delete.py
    cli/test_keystore.py
    cli/test_meta.py
    cli/test_sign.py
    cli/test_transport.py
    golden/test_packages.py
    golden/test_symbols.py
    python/test_meta.py
    python/test_package.py
    python/test_sign.py
    python/test_transport.py
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pytest)

foreach(pytest_file IN LISTS PYTEST_FILES)
    get_filename_component(suite ${pytest_file} DIRECTORY)
    get_filename_component(name ${pytest_file} NAME_WE)
    set(test_name ${suite}.${name})

    add_test(NAME ${test_name}
        COMMAND ${Python_EXECUTABLE} -m pytest
            ${CMAKE_CURRENT_SOURCE_DIR}/${pytest_file}
            --bpak-build-dir=${PROJECT_BINARY_DIR}
            --basetemp=${CMAKE_CURRENT_BINARY_DIR}/pytest/${test_name}
            --junitxml=${CMAKE_CURRENT_BINARY_DIR}/junit/${test_name}.xml
            -p no:cacheprovider
    )
    set_tests_properties(${test_name} PROPERTIES
        LABELS ${suite}
        ENVIRONMENT "CC=${CMAKE_C_COMPILER}"
    )
endforeach()
