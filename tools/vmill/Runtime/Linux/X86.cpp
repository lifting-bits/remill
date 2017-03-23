/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "remill/Arch/X86/Runtime/State.h"
#include "remill/Arch/Runtime/Intrinsics.h"

#include "tools/vmill/Runtime/Generic/Intrinsics.cpp"
#include "tools/vmill/Runtime/Linux/SystemCallABI.cpp"
#include "tools/vmill/Runtime/Linux/SystemCall.cpp"

extern "C" {

Memory *__remill_async_hyper_call(
    Memory *memory, State &state, addr_t ret_addr) {

  switch (state.hyper_call) {
    case AsyncHyperCall::kX86SysEnter: {
      SysEnter32SystemCall abi;
      memory = __remill_atomic_begin(memory);
      memory = SystemCall32(memory, &state, abi);
      memory = __remill_atomic_end(memory);
      ret_addr = abi.GetReturnAddress(memory, ret_addr);
      state.gpr.rip.aword = ret_addr;
      return __remill_jump(memory, state, ret_addr);
    }

    case AsyncHyperCall::kX86IntN:
      if (0x80 == state.interrupt_vector) {
        Int0x80SystemCall abi;
        memory = __remill_atomic_begin(memory);
        memory = SystemCall32(memory, &state, abi);
        memory = __remill_atomic_end(memory);
        ret_addr = abi.GetReturnAddress(memory, ret_addr);
        state.gpr.rip.aword = ret_addr;
        return __remill_jump(memory, state, ret_addr);
      }
      break;

    default:
      break;
  }
  return __remill_error(memory, state, ret_addr);
}

}  // extern C
