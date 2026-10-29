# The examples are built and run with the tests, so they do not go stale

find_package(Python 3.10 REQUIRED COMPONENTS Interpreter)

add_executable(c_example c_example.c)
target_link_libraries(c_example PRIVATE ${PROJECT_NAME})

add_test(NAME examples.c_example
    COMMAND c_example ${PROJECT_SOURCE_DIR}/test/golden/0.9.3/basic.bpak
)

add_test(NAME examples.package
    COMMAND ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/python/package.py
        ${PROJECT_SOURCE_DIR}/test/data/secp256r1-key-pair.pem
        ${PROJECT_SOURCE_DIR}/test/data/secp256r1-pub-key.der
)

set_tests_properties(examples.c_example examples.package PROPERTIES
    LABELS examples
)
# package.py works in a temporary directory that it leaves for inspection
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tmp)
set_tests_properties(examples.package PROPERTIES
    ENVIRONMENT "PYTHONPATH=${PROJECT_BINARY_DIR}/python;TMPDIR=${CMAKE_CURRENT_BINARY_DIR}/tmp"
)
