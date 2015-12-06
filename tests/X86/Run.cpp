/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>
#include <iostream>
#include <type_traits>
#include <setjmp.h>

#include "tests/X86/Test.h"
#include "tests/X86/State.h"

namespace test {

struct alignas(128) Stack {
  uint8_t bytes[kPageSize];
};

static Stack gStack;
static std::aligned_storage<sizeof(State), alignof(State)> gState;
static jmp_buf gJmpBuf;

typedef void (*NativeFunc)(void);
typedef void (*LiftedFunc)(State *);

static void CreateTest(const TestInfo &test) {

  auto info_addr = reinterpret_cast<intptr_t>(&test);
  auto test_name = reinterpret_cast<const char *>(info_addr + test.test_name);
  auto native_func = reinterpret_cast<NativeFunc>(info_addr + test.test_begin);
  auto lifted_func = reinterpret_cast<LiftedFunc>(info_addr + test.lifted_func);

  std::cout << test_name << std::endl;

  auto state = reinterpret_cast<State *>(&gState);
  native_func();
  if (!setjmp(gJmpBuf)) {
    lifted_func(state);
  } else {
    std::cout << "after test" << std::endl;
  }
}

}  // namespace test
extern "C" {

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
addr_t __mcsema_compute_address(const State &state, addr_t address,
                                int address_space) {
  (void) state;
  (void) address;
  (void) address_space;
  return 0;
}

// Memory read intrinsics.
uint8_t __mcsema_read_memory_8(addr_t) {
  return 0;
}

uint16_t __mcsema_read_memory_16(addr_t) {
  return 0;
}

uint32_t __mcsema_read_memory_32(addr_t) {
  return 0;
}

uint64_t __mcsema_read_memory_64(addr_t) {
  return 0;
}

void __mcsema_read_memory_v64(addr_t, vec64_t &) {

}

void __mcsema_read_memory_v128(addr_t, vec128_t &) {

}
void __mcsema_read_memory_v256(addr_t, vec256_t &) {

}

void __mcsema_read_memory_v512(addr_t, vec512_t &) {

}

// Memory write intrinsics.
void __mcsema_write_memory_8(addr_t, uint8_t) {

}

void __mcsema_write_memory_16(addr_t, uint16_t) {

}

void __mcsema_write_memory_32(addr_t, uint32_t) {

}

void __mcsema_write_memory_64(addr_t, uint64_t) {

}

void __mcsema_write_memory_v64(addr_t, const vec64_t &) {

}

void __mcsema_write_memory_v128(addr_t, const vec128_t &) {

}

void __mcsema_write_memory_v256(addr_t, const vec256_t &) {

}

void __mcsema_write_memory_v512(addr_t, const vec512_t &) {

}

void __mcsema_defer_inlining(void) {

}

// Control-flow intrinsics.
void __mcsema_error(State &) {
  longjmp(test::gJmpBuf, 0);
}

void __mcsema_function_call(State &) {
  __builtin_unreachable();
}

void __mcsema_function_return(State &) {
  __builtin_unreachable();
}

void __mcsema_jump(State &) {
  __builtin_unreachable();
}

void __mcsema_system_call(State &) {
  __builtin_unreachable();
}

void __mcsema_system_return(State &) {
  __builtin_unreachable();
}

void __mcsema_interrupt_call(State &) {
  __builtin_unreachable();
}

void __mcsema_interrupt_return(State &) {
  __builtin_unreachable();
}

}  // extern C

extern "C" int main(void) {
  (void) test::gStack;
  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    CreateTest(test);
  }

  return 0;
}
