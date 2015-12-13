/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>
#include <cstring>
#include <iostream>
#include <type_traits>
#include <vector>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "tests/X86/Test.h"

#include "mcsema/Arch/X86/Runtime/State.h"

namespace {

typedef void (*LiftedFunc)(State *);

struct alignas(128) Stack {
  uint8_t bytes[4096 * 16];
};

// Native test case code executes off of `gStack`. The state of the stack
// after executing this code is saved in `gBackupStack`. Lifted test case
// code executes off of the normal runtime stack, but emulates operations
// that act on `gStack`.
static Stack gLiftedStack;
static Stack gNativeStack;

extern "C" {

// Native state before we run the native test case. We then use this as the
// initial state for the lifted testcase. The lifted test case code mutates
// this, and we require that after running the lifted testcase, `gStateBefore`
// matches `gStateAfter`,
std::aligned_storage<sizeof(State), alignof(State)>::type gStateLifted;

// Native state after running the native test case.
std::aligned_storage<sizeof(State), alignof(State)>::type gStateNative;

// Address of the native test to run. The `InvokeTestCase` function saves
// the native program state but then needs a way to figure out where to go
// without storing that information in any register. So what we do is we
// store it here and indrrectly `JMP` into the native test case code after
// saving the machine state to `gStateBefore`.
uintptr_t gTestToRun = 0;

// Used for swapping the stack pointer between `gStack` and the normal
// call stack. This lets us run both native and lifted testcase code on
// the same stack.
Stack *gStackSwitcher = (&gLiftedStack) + 1;

// We need to capture the native flags state, and so we need a `PUSHFQ`.
// Unfortunately, this will be done on the 'recording' stack (`gStack`) in
// the native execution, and no corresponding operation like this is done in
// the lifted execution. What we need to do is save the value just below the
// top of the stack before the `PUSHFQ` clobbers it, then after we've recorded
// the native flags we restore what was clobbered by `PUSHFQ`.
uint64_t gStackSaveSlot = 0;

// Invoke a native test case addressed by `gTestToRun` and store the machine
// state before and after executing the test in `gStateBefore` and
// `gStateAfter`, respectively.
extern void InvokeTestCase(uint64_t, uint64_t, uint64_t);

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

void __mcsema_defer_inlining(void) {}

// Control-flow intrinsics.
void __mcsema_error(State &) {

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

// The `State` structure maintains two versions of the `XMM` registers. One
// version (used by lifted code) is consistent with AVX and AVX512. The other
// version is stored by the `FXSAVE64` into the `FPU` data structure.
static void CopyXMMRegsIntoFPU(State *state) {
  for (auto i = 0; i < IF_64BIT_ELSE(16, 8); ++i) {
    state->fpu.xmm[i] = state->vec[i].xmm;
  }
}

static std::vector<const test::TestInfo *> gTests;

}  // namespace

class InstrTest : public ::testing::TestWithParam<const test::TestInfo *> {};

TEST_P(InstrTest, SemanticsMatchNative) {
  auto info = GetParam();
  auto test_name = reinterpret_cast<const char *>(info->test_name);
  auto lifted_func = reinterpret_cast<LiftedFunc>(info->lifted_func);

  memset(&gLiftedStack, 0, sizeof(gLiftedStack));
  memset(&gStateLifted, 0, sizeof(gStateLifted));
  memset(&gStateNative, 0, sizeof(gStateNative));

  auto lifted_state = reinterpret_cast<State *>(&gStateLifted);
  auto native_state = reinterpret_cast<State *>(&gStateNative);

  // This will execute on `gStack`. The mechanism behind this is that the
  // stack pointer is swapped with `gStackSwitcher`. The idea here is that
  // we want to run the native and lifted testcases on the same stack so that
  // we can compare that they both operate on the stack in the same ways.
  gTestToRun = info->test_begin;
  InvokeTestCase(0, 0, 0);

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memset(&gLiftedStack, 0, sizeof(gLiftedStack));

  // This will execute on our stack but the lifted code will operate on
  // `gStack`. The mechanism behind this is that `gStateBefore` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  lifted_func(lifted_state);

  // Don't compare the program counters. The code that is lifted is equivalent
  // to the code that is tested but because they are part of separate binaries
  // it means that there is not necessarily any relation between their values.
  //
  // This also lets us compare 32-bit-only lifted code with 32-bit only
  // testcases, where the native 32-bit code actually emulates the 32-bit
  // behavior in 64-bit (because all of this code is compiled as 64-bit).
  lifted_state->gpr.rip.qword = 0;
  native_state->gpr.rip.qword = 0;

  CopyXMMRegsIntoFPU(lifted_state);

  std::cerr << "Testing instruction: " << test_name << std::endl;
  std::cerr << "Instruction features:";
  if (test::kFeatureMMX & info->features) std::cerr << " MMX";
  if (test::kFeatureSSE & info->features) std::cerr << " SSE";
  if (test::kFeatureAVX & info->features) std::cerr << " AVX";
  if (test::kFeatureAVX512 & info->features) std::cerr << " AVX512";
  if (test::kFeature64BitOnly & info->features) std::cerr << " (64-bit only)";
  if (test::kFeature32BitOnly & info->features) std::cerr << " (32-bit only)";
  if (!((test::kFeature32BitOnly | test::kFeature64BitOnly) & info->features)) {
    std::cerr << " (32-bit, 64-bit compat)";
  }
  std::cerr << std::endl;

  // Compare the register states.
  EXPECT_TRUE(!memcmp(lifted_state, native_state, sizeof(State)));
  EXPECT_TRUE(!memcmp(&gLiftedStack, &gNativeStack, sizeof(Stack)));
}

INSTANTIATE_TEST_CASE_P(
    GeneralInstrTest,
    InstrTest,
    testing::ValuesIn(gTests));

int main(int argc, char **argv) {

  // Populate the tests vector.
  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    gTests.push_back(&test);
  }

  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
