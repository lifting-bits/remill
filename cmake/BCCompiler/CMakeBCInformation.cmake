set(DEFAULT_BC_COMPILER_FLAGS "-std=gnu++11 -emit-llvm -Wno-unknown-warning-option -Wall -Wshadow -Wconversion -Wpadded -pedantic -Wshorten-64-to-32 -Wno-gnu-anonymous-struct -Wno-return-type-c-linkage -Wno-gnu-zero-variadic-macro-arguments -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-statement-expression -Wno-c99-extensions -Wno-ignored-attributes -mtune=generic -fno-vectorize -fno-slp-vectorize -ffreestanding -fno-common -fno-builtin -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -Wno-unneeded-internal-declaration -Wno-unused-function")

if (NOT CMAKE_BC_COMPILE_OBJECT)
    if (NOT DEFINED CMAKE_BC_COMPILER)
        message(SEND_ERROR "The bitcode compiler was not found!")
    endif ()

    set(CMAKE_BC_COMPILE_OBJECT "${CMAKE_BC_COMPILER} <DEFINES> <INCLUDES> ${DEFAULT_BC_COMPILER_FLAGS} <FLAGS> -c <SOURCE> -o <OBJECT>")
endif ()

if (NOT CMAKE_BC_LINK_EXECUTABLE)
    if (NOT DEFINED CMAKE_BC_LINKER)
        message(SEND_ERROR "The bitcode linker was not found!")
    endif ()

    set(CMAKE_BC_LINK_EXECUTABLE "${CMAKE_BC_LINKER} <OBJECTS> -o <TARGET>")
endif ()

if (NOT CMAKE_INCLUDE_FLAG_BC)
    set(CMAKE_INCLUDE_FLAG_BC -I)
endif ()

# this is the runtime target generator, used in a similar way to add_executable
set(add_runtime_usage "add_runtime(target_name SOURCES <source file list> ADDRESS_SIZE <size>")

function (add_runtime target_name)
    foreach (macro_parameter ${ARGN})
        if ("${macro_parameter}" STREQUAL "SOURCES")
            set(state "${macro_parameter}")
            continue ()

        elseif ("${macro_parameter}" STREQUAL "ADDRESS_SIZE")
            set(state "${macro_parameter}")
            continue ()
        endif ()

        if ("${state}" STREQUAL "SOURCES")
            set_source_files_properties("${macro_parameter}" PROPERTIES LANGUAGE BC)
            list(APPEND source_file_list "${macro_parameter}")

        elseif ("${state}" STREQUAL "ADDRESS_SIZE")
            if (NOT "${macro_parameter}" MATCHES "^[0-9]+$")
                message(SEND_ERROR "Invalid ADDRESS_SIZE parameter passed to add_runtime")
            endif ()

            list(APPEND definitions "ADDRESS_SIZE_BITS=${macro_parameter}")
            set(address_size_bits_found True)

        else ()
            message(SEND_ERROR "Syntax error. Usage: ${add_runtime_usage}")
        endif ()
    endforeach ()

    foreach (source_file ${sourcefile_list})
        set_source_files_properties("${source_file}" PROPERTIES LANGUAGE BC)
    endforeach ()

    if (NOT address_size_bits_found)
        message(SEND_ERROR "Missing address size.")
    endif ()

    if ("${source_file_list}" STREQUAL "")
        message(SEND_ERROR "No source files specified.")
    endif ()

    add_executable("${target_name}" ${source_file_list})
    target_compile_definitions("${target_name}" PRIVATE ${definitions})
    set_target_properties("${target_name}" PROPERTIES SUFFIX ".bc")

    foreach (source_file ${sourcefile_list})
        add_dependencies("${target_name}" "${source_file}")
    endforeach ()
endfunction ()
