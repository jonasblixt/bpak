include(GNUInstallDirs)

find_package(Python 3.6
    COMPONENTS Interpreter Development
)

add_library(
    ${PROJECT_NAME}-python-wrapper SHARED
    python_wrapper.c
    package.c
    meta.c
    part.c
)

target_include_directories(${PROJECT_NAME}-python-wrapper PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${Python_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}-python-wrapper
    ${Python_LIBRARIES}
    ${PROJECT_NAME}
)

set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

target_compile_options(${PROJECT_NAME}-python-wrapper PRIVATE
    -Wextra -pedantic
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
)

set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
