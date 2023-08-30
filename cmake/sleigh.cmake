add_compile_definitions(REMILL_ENABLE_SLEIGH)

set(sleigh_ENABLE_TESTS OFF)
set(sleigh_RELEASE_TYPE "HEAD" CACHE STRING "" FORCE)

file(GLOB sleigh_patches "${REMILL_PROJECT_SOURCE_DIR}/patches/sleigh/*.patch")

set(sleigh_ADDITIONAL_PATCHES "${sleigh_patches}" CACHE STRING "" FORCE)

# GHIDRA SLEIGH
FetchContent_Declare(sleigh
  GIT_REPOSITORY https://github.com/lifting-bits/sleigh.git
  GIT_TAG 7c6b742
)

set(sleigh_BUILD_SUPPORT ON CACHE BOOL "" FORCE)
set(sleigh_BUILD_SLEIGHSPECS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(sleigh)

set(ghidra_patch_user "github-actions[bot]")
set(ghidra_patch_email "41898282+github-actions[bot]@users.noreply.github.com")

# pinned stable patches list
set(ghidra_patches
  PATCH_COMMAND "${GIT_EXECUTABLE}" config user.name "${ghidra_patch_user}" &&
  "${GIT_EXECUTABLE}" config user.email "${ghidra_patch_email}" &&
  "${GIT_EXECUTABLE}" am --ignore-space-change --ignore-whitespace --no-gpg-sign)
list(APPEND ghidra_patches ${sleigh_ADDITIONAL_PATCHES})

FetchContent_Declare(ghidra-fork
  GIT_REPOSITORY https://github.com/trail-of-forks/ghidra.git
  GIT_TAG e7196d8
  ${ghidra_patches}
)

FetchContent_MakeAvailable(ghidra-fork)

if(SLEIGH_EXECUTABLE)
  set(sleigh_compiler "${SLEIGH_EXECUTABLE}")
else()
  set(sleigh_compiler "$<TARGET_FILE:sleigh::sleigh>")
endif()

sleigh_compile(
  TARGET ppc_e200_spec
  COMPILER "${sleigh_compiler}"
  SLASPEC "${ghidra-fork_SOURCE_DIR}/Ghidra/Processors/PowerPC/data/languages/ppc_32_e200_be.slaspec"
  LOG_FILE "${sleigh_BINARY_DIR}/sleighspecs/spec_build_logs/ppc_32_e200_be.sla.log"
  OUT_FILE "${sleigh_BINARY_DIR}/specfiles/Ghidra/Processors/PowerPC/data/languages/ppc_32_e200_be.sla"
)

add_custom_target(sleigh_custom_specs)
add_dependencies(sleigh_custom_specs ppc_e200_spec)
