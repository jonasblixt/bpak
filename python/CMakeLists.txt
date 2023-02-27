include(GNUInstallDirs)

find_package(Python 3.6 REQUIRED
    COMPONENTS Interpreter Development
)

add_library(
    ${PROJECT_NAME}-python-wrapper SHARED
    python_wrapper.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/unpack.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/unparse.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/clear.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/compare.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/pack.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/parse.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/isnull.c
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
    -I${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
)

set_target_properties(${PROJECT_NAME}-python-wrapper PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME}-python-wrapper
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME}-python-wrapper
    LIBRARY DESTINATION ${Python_SITELIB}
)
