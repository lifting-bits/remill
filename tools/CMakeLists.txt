# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

install(CODE
    "execute_process(COMMAND python ${PROJECT_SOURCE_DIR}/tools/setup.py install -f --prefix=${CMAKE_INSTALL_PREFIX})")

add_subdirectory(${PROJECT_SOURCE_DIR}/tools/remill_lift)
add_subdirectory(${PROJECT_SOURCE_DIR}/tools/remill_opt)

if (EXISTS ${PROJECT_SOURCE_DIR}/tools/mcsema)
    add_subdirectory(${PROJECT_SOURCE_DIR}/tools/mcsema)
endif()

if (LINUX)
    add_subdirectory(${PROJECT_SOURCE_DIR}/tools/vmill)
endif(LINUX)
