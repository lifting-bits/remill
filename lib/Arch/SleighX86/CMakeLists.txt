add_library(remill_arch_sleighx86 STATIC
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Runtime.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"

  "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Operators.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/State.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Types.h"

  Arch.cpp
  )

set_property(TARGET remill_arch_sleighx86 PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_arch_sleighx86 LINK_PUBLIC
  remill_settings
)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS remill_arch_sleighx86
    EXPORT remillTargets
  )
endif()
