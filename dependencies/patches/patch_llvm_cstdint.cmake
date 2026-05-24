# patch_llvm_cstdint.cmake
# Injected during LLVM extraction to fix GCC 15 compatibility

function(inject_cstdint TARGET_FILE INCLUDE_ANCHOR)
  if(EXISTS "${TARGET_FILE}")
    file(READ "${TARGET_FILE}" FILE_CONTENTS)

    if(NOT FILE_CONTENTS MATCHES "#include <cstdint>")
      string(FIND "${FILE_CONTENTS}" "${INCLUDE_ANCHOR}" INCLUDE_ANCHOR_POS)
      if(INCLUDE_ANCHOR_POS EQUAL -1)
        message(FATAL_ERROR
          "Could not find include anchor in ${TARGET_FILE}: ${INCLUDE_ANCHOR}"
        )
      endif()

      message(STATUS "Patching ${TARGET_FILE} to include <cstdint>")
      string(REPLACE
        "${INCLUDE_ANCHOR}"
        "#include <cstdint>\n${INCLUDE_ANCHOR}"
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
endfunction()

inject_cstdint("llvm/include/llvm/ADT/SmallVector.h" "#include <algorithm>")

foreach(TARGET_FILE IN ITEMS
  "llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCTargetDesc.h"
  "llvm/lib/Target/AMDGPU/MCTargetDesc/AMDGPUMCTargetDesc.h"
  "llvm/lib/Target/ARM/MCTargetDesc/ARMMCTargetDesc.h"
  "llvm/lib/Target/AVR/MCTargetDesc/AVRMCTargetDesc.h"
  "llvm/lib/Target/BPF/MCTargetDesc/BPFMCTargetDesc.h"
  "llvm/lib/Target/LoongArch/MCTargetDesc/LoongArchMCTargetDesc.h"
  "llvm/lib/Target/MSP430/MCTargetDesc/MSP430MCTargetDesc.h"
  "llvm/lib/Target/PowerPC/MCTargetDesc/PPCMCTargetDesc.h"
  "llvm/lib/Target/RISCV/MCTargetDesc/RISCVMCTargetDesc.h"
  "llvm/lib/Target/Sparc/MCTargetDesc/SparcMCTargetDesc.h"
  "llvm/lib/Target/SystemZ/MCTargetDesc/SystemZMCTargetDesc.h"
  "llvm/lib/Target/VE/MCTargetDesc/VEMCTargetDesc.h"
  "llvm/lib/Target/X86/MCTargetDesc/X86MCTargetDesc.h"
  "llvm/lib/Target/Xtensa/MCTargetDesc/XtensaMCTargetDesc.h"
)
  inject_cstdint("${TARGET_FILE}" "#include <memory>")
endforeach()
