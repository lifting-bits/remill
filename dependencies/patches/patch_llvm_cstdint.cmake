# patch_llvm_cstdint.cmake
# Injected during LLVM extraction to fix GCC 15 compatibility

set(TARGET_FILE "llvm/include/llvm/ADT/SmallVector.h")

if(EXISTS "${TARGET_FILE}")
  file(READ "${TARGET_FILE}" FILE_CONTENTS)

  if(NOT FILE_CONTENTS MATCHES "#include <cstdint>")
    message(STATUS "Patching ${TARGET_FILE} to include <cstdint>")
    string(REPLACE
      "#include <algorithm>"
      "#include <cstdint>\n#include <algorithm>"
      PATCHED_CONTENTS
      "${FILE_CONTENTS}"
    )
    file(WRITE "${TARGET_FILE}" "${PATCHED_CONTENTS}")
  else()
    message(STATUS "${TARGET_FILE} is already patched.")
  endif()
else()
  message(FATAL_ERROR "Could not find target file to patch: ${TARGET_FILE}")
endif()
