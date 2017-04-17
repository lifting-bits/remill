# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_subdirectory(${PROJECT_SOURCE_DIR}/tools/remill_lift)
add_subdirectory(${PROJECT_SOURCE_DIR}/tools/remill_opt)

if (EXISTS ${PROJECT_SOURCE_DIR}/tools/mcsema)
    add_subdirectory(${PROJECT_SOURCE_DIR}/tools/mcsema)
endif()

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

# if (LINUX)
#     add_subdirectory(${PROJECT_SOURCE_DIR}/tools/vmill)
# endif(LINUX)
