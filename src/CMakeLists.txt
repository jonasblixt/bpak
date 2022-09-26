
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
)

add_executable(${PROJECT_NAME}-tool ${TOOL_SRC_FILES})
set_target_properties(${PROJECT_NAME}-tool
    PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

target_compile_options(${PROJECT_NAME}-tool PRIVATE -Wextra -pedantic)

target_link_libraries(${PROJECT_NAME}-tool
    ${UUID_LIBRARY}
    ${PROJECT_NAME}
)

install(TARGETS ${PROJECT_NAME}-tool
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
