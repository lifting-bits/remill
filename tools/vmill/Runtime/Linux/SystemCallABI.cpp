/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "remill/Arch/X86/Runtime/State.h"
#include "tools/vmill/Runtime/Generic/SystemCallABI.h"

// 32-bit `int 0x80` system call ABI.
class Int0x80SystemCall : public SystemCallABI {
 public:
  virtual ~Int0x80SystemCall(void) = default;

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const override {
    return ret_addr;
  }

  Memory *SetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.rax.aword;
  }

 protected:

  bool CanReadArgs(Memory *, State *, int num_args) const override {
    return num_args <= 6;
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const override {
    switch (i) {
      case 0:
        return state->gpr.rbx.aword;
      case 1:
        return state->gpr.rcx.aword;
      case 2:
        return state->gpr.rdx.aword;
      case 3:
        return state->gpr.rsi.aword;
      case 4:
        return state->gpr.rdi.aword;
      case 5:
        return state->gpr.rbp.aword;
      default:
        return 0;
    }
  }
};

// 32-bit `sysenter` ABI.
class SysEnter32SystemCall : public SystemCallABI {
 public:
  virtual ~SysEnter32SystemCall(void) = default;

  // Find the return address of this system call.
  addr_t GetReturnAddress(Memory *memory, addr_t ret_addr) const override {
    addr_t addr = ret_addr;
    for (addr_t i = 0; i < 15; ++i) {
      uint8_t b0 = 0;

      if (TryReadMemory(memory, addr + i, &b0)) {
        if (0x90 == b0) {  // NOP.
          continue;
        } else if (0xcd == b0) {  // First byte of `int N` instruction.
          return addr + i + 2;
        } else {
          return addr + i;
        }
      }
    }
    return addr;
  }

  bool CanReadArgs(Memory *memory, State *state, int num_args) const override {
    if (num_args == 6) {
      addr_t arg6_addr = state->gpr.rbp.aword;
      return CanReadMemory(memory, arg6_addr, sizeof(addr_t));
    } else {
      return num_args < 6;
    }
  }

  Memory *SetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.rax.aword;
  }

 protected:
  addr_t GetArg(Memory *&memory, State *state, int i) const override {
    switch (i) {
      case 0:
        return state->gpr.rbx.aword;
      case 1:
        return state->gpr.rcx.aword;
      case 2:
        return state->gpr.rdx.aword;
      case 3:
        return state->gpr.rsi.aword;
      case 4:
        return state->gpr.rdi.aword;
      case 5:
        return ReadMemory<addr_t>(memory, state->gpr.rbp.aword);
      default:
        return 0;
    }
  }
};
