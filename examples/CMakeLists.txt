# The examples are built and run with the tests, so they do not go stale

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

set_tests_properties(examples.c_example PROPERTIES LABELS examples)

# package.py works in a temporary directory that it leaves for inspection
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tmp)
set_tests_properties(examples.package PROPERTIES
    LABELS examples
    ENVIRONMENT "PYTHONPATH=${PROJECT_BINARY_DIR}/tools;TMPDIR=${CMAKE_CURRENT_BINARY_DIR}/tmp"
)
