# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_executable(remill-opt Optimize.cpp)

target_link_libraries(remill-opt remill)
add_dependencies(remill-opt semantics)

install(
    TARGETS remill-opt
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
