include(GNUInstallDirs)

pkg_check_modules(PYTHON REQUIRED python3)

add_library(
    ${PROJECT_NAME}-python-wrapper SHARED
    python_wrapper.c
    package.c
    meta.c
    part.c
)

target_include_directories(${PROJECT_NAME}-python-wrapper PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}-python-wrapper
    ${PYTHON_LDFLAGS}
    ${PROJECT_NAME}
)

set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_options(${PROJECT_NAME}-python-wrapper PRIVATE
    -Wextra -pedantic
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
    ${PYTHON_CFLAGS}
)

set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME}-python-wrapper
    LIBRARY DESTINATION ${Python_SITELIB}
)
