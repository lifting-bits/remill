cmake_minimum_required(VERSION 3.2)

function(FindAndSelectClangCompiler)
  if(DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX} PARENT_SCOPE)
  endif()

  if(DEFINED LLVM_INSTALL_PREFIX)
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm/")
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake/")
    set(FINDPACKAGE_LLVM_HINTS ${FINDPACKAGE_LLVM_HINTS} PARENT_SCOPE)

    message(STATUS "Using LLVM_INSTALL_PREFIX hints for find_package(LLVM): ${FINDPACKAGE_LLVM_HINTS}")
  endif()

  if(DEFINED WIN32)
    set(executable_extension ".exe")
  else()
    set(executable_extension "")
  endif()

  # it is important to avoid re-defining these variables if they have been already
  # set or you risk ending up in a configure loop!
  if(NOT DEFINED CMAKE_C_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang${executable_extension}"
        CACHE PATH "Path to clang binary." FORCE)
    else()
      set(CMAKE_C_COMPILER "clang" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++${executable_extension}"
        CACHE PATH "Path to clang++ binary." FORCE)
    else()
      set(CMAKE_CXX_COMPILER "clang++${executable_extension}" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_ASM_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++${executable_extension}"
        CACHE PATH "Path to assembler (aka clang) binary." FORCE)
    else()
      set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER} PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_LLVM_LINK)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link${executable_extension}"
        CACHE PATH "Path to llvm-link binary." FORCE)
    else()
      set(CMAKE_LLVM_LINK "llvm-link${executable_extension}" PARENT_SCOPE)
    endif()
  endif()
endfunction()

function(GetTargetTree output_variable)
  if(${ARGC} LESS 1)
    message(FATAL_ERROR "Usage: GetTargetTree output_var target1 target2 ...")
  endif()
  
  foreach(target ${ARGN})
    list(APPEND queue "${target}")
  endforeach()

  while(true)
    # Update the queue
    unset(new_queue)
    
    foreach(target ${queue})
      list(APPEND visited_dependencies "${target}")
      
      if (NOT TARGET "${target}")
        continue()
      endif()
      
      # Always reset to empty value
      set(target_link_libs "target_link_libs-NOTFOUND")
      set(target_interface_link_libs "target_interface_link_libs-NOTFOUND")

      # Skip utility targets
      get_target_property(target_type "${target}" TYPE)
      if("${target_type}" STREQUAL "UTILITY")
        continue()
      endif()

      # Collect the results
      unset(new_queue_candidates)

      # We can only get LINK_LIBRARIES from normal targets
      if(NOT "${target_type}" STREQUAL "INTERFACE_LIBRARY")
        get_target_property(target_link_libs "${target}" LINK_LIBRARIES)
        if(NOT "${target_link_libs}" STREQUAL "target_link_libs-NOTFOUND")
          list(APPEND new_queue_candidates ${target_link_libs})
        endif()
      endif()

      # INTERFACE_LINK_LIBRARIES are potentially always present
      get_target_property(target_interface_link_libs "${target}" INTERFACE_LINK_LIBRARIES)
      if(NOT "${target_interface_link_libs}" STREQUAL "target_interface_link_libs-NOTFOUND")
        list(APPEND new_queue_candidates ${target_interface_link_libs})
      endif()

      # Try to find the actual file
      if ("${target_type}" STREQUAL "UNKNOWN_LIBRARY" OR
          "${target_type}" STREQUAL "STATIC_LIBRARY" OR
          "${target_type}" STREQUAL "SHARED_LIBRARY" OR
          "${target_type}" STREQUAL "IMPORTED_LIBRARY")
        get_target_property(target_imported_loc "${target}" IMPORTED_LOCATION)
        if(NOT "${target_imported_loc}" STREQUAL "target_imported_loc-NOTFOUND")
          list(APPEND new_queue_candidates "${target_imported_loc}")
        endif()
      endif()
      
      foreach(queue_candidate ${new_queue_candidates})
        list(FIND visited_dependencies "${queue_candidate}" visited)
        if(visited EQUAL -1)
          list(APPEND new_queue "${queue_candidate}")
        endif()
      endforeach()
    endforeach()

    list(LENGTH new_queue new_queue_size)
    if(${new_queue_size} EQUAL 0)
      break()
    endif()

    set(queue ${new_queue})
  endwhile()

  list(REVERSE visited_dependencies)
  list(REMOVE_DUPLICATES visited_dependencies)
  list(REVERSE visited_dependencies)
  set("${output_variable}" ${visited_dependencies} PARENT_SCOPE)
endfunction()

function(GetPublicIncludeFolders output_variable)
  if(${ARGC} LESS 1)
    message(FATAL_ERROR "Usage: GetPublicIncludeFolders output_var target1 target2 ...")
  endif()
  
  foreach(target ${ARGN})
    if (NOT TARGET "${target}")
      continue()
    endif()
    
    get_target_property(include_dir_list "${target}" INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT "${include_dir_list}" STREQUAL "include_dir_list-NOTFOUND")
      list(APPEND collected_include_dirs "${include_dir_list}")
    endif()
  endforeach()

  list(REMOVE_DUPLICATES collected_include_dirs)
  set("${output_variable}" ${collected_include_dirs} PARENT_SCOPE)
endfunction()

function(InstallExternalTarget target_name target_path install_type installed_file_name)
  # Get the optional rpath parameter
  set(additional_arguments ${ARGN})
  list(LENGTH additional_arguments additional_argument_count)

  if("${additional_argument_count}" EQUAL 0)
  elseif("${additional_argument_count}" EQUAL 1)
    list(GET additional_arguments 0 rpath)
  else()
    message(FATAL_ERROR "InstallExternalTarget: Invalid argument count")
  endif()

  # We need to locate the patchelf executable to fix the rpath; search for it
  # only once, and then export the variable with PARENT_SCOPE so that we can
  # re-use it in the next calls
  if(NOT "${rpath}" STREQUAL "")
    if("${PATCHELF_LOCATION}" STREQUAL "")
      find_program("program_location" "patchelf")
      if("${program_location}" STREQUAL "program_location-NOTFOUND")
        message(FATAL_ERROR "InstallExternalTarget: Failed to locate the patchelf executable")
      endif()

      # We need to set it both in local and in parent scope
      set("PATCHELF_LOCATION" "${program_location}" PARENT_SCOPE)
      set("PATCHELF_LOCATION" "${program_location}")
    endif()
  endif()

  # Make sure the parameters are correct
  if(NOT EXISTS "${target_path}")
    message(FATAL_ERROR "InstallExternalTarget: The following path does not exists: ${target_path}")
  endif()

  if("${target_name}")
    message(FATAL_ERROR "InstallExternalTarget: The following target already exists: ${target_name}")
  endif()

  if("${install_type}" STREQUAL "")
    message(FATAL_ERROR "InstallExternalTarget: Invalid install type specified")
  endif()

  # Generate the target
  set("output_file_path" "${CMAKE_CURRENT_BINARY_DIR}/${installed_file_name}")

  if(NOT "${rpath}" STREQUAL "")
    set(CHRPATH_COMMAND ${PATCHELF_LOCATION} --set-rpath ${rpath} ${output_file_path})
  else()
    set(CHRPATH_COMMAND ${CMAKE_COMMAND} -E echo 'No rpath patch needed for ${target_name}')
  endif()

  add_custom_command(
    OUTPUT "${output_file_path}"

    COMMAND "${CMAKE_COMMAND}" -E copy ${target_path} ${output_file_path}
    COMMAND ${CHRPATH_COMMAND}
  )

  add_custom_target("${target_name}" ALL DEPENDS "${output_file_path}")

  install(FILES "${output_file_path}"
    TYPE ${install_type}
    PERMISSIONS OWNER_READ OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
  )
endfunction()

