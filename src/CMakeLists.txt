
SET(TOOL_SRC_FILES
    add.c
    compare.c
    create.c
    extract.c
    generate.c
    main.c
    misc.c
    set.c
    show.c
    sign.c
    transport.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/unpack.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/unparse.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/clear.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/compare.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/pack.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/parse.c
    ${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid/isnull.c
)

add_executable(${PROJECT_NAME}-tool ${TOOL_SRC_FILES})
set_target_properties(${PROJECT_NAME}-tool
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

target_compile_options(${PROJECT_NAME}-tool PRIVATE
    -Wextra -pedantic
    -I${${PROJECT_NAME}_SOURCE_DIR}/ext/uuid
    -I${${PROJECT_NAME}_BINARY_DIR}/lib/
)

target_link_libraries(${PROJECT_NAME}-tool
    ${PROJECT_NAME}
)

install(TARGETS ${PROJECT_NAME}-tool
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
