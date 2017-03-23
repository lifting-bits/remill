# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_executable(remill-lift Lift.cpp)
target_link_libraries(remill-lift remill)
add_dependencies(remill-lift semantics)

install(
    TARGETS remill-lift
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
