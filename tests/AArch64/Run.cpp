/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _XOPEN_SOURCE

#include <dlfcn.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <setjmp.h>
#include <signal.h>
#include <ucontext.h>

#include <cfenv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/Runtime/Runtime.h"
#include "tests/AArch64/Test.h"

DECLARE_string(arch);
DECLARE_string(os);

namespace {

struct alignas(128) Stack {
  uint8_t _redzone1[128];
  uint8_t bytes[(SIGSTKSZ / 128) * 128];
  uint8_t _redzone2[128];
};

// Native test case code executes off of `gStack`. The state of the stack
// after executing this code is saved in `gBackupStack`. Lifted test case
// code executes off of the normal runtime stack, but emulates operations
// that act on `gStack`.
static Stack gRandomStack;
static Stack gLiftedStack;
static Stack gNativeStack;
static Stack gSigStack;

static const auto gStackBase =
    reinterpret_cast<uintptr_t>(&(gLiftedStack.bytes[0]));

static const auto gStackLimit =
    reinterpret_cast<uintptr_t>(&(gLiftedStack._redzone2[0]));

template <typename T>
NEVER_INLINE static T &AccessMemory(addr_t addr) {
  if (!(addr >= gStackBase && (addr + sizeof(T)) <= gStackLimit)) {
    EXPECT_TRUE(!"Memory access falls outside the valid range of the stack.");
  }
  return *reinterpret_cast<T *>(static_cast<uintptr_t>(addr));
}

// Used to handle exceptions in instructions.
static sigjmp_buf gJmpBuf;
static sigjmp_buf gUnsupportedInstrBuf;

// Are we running in a native test case or a lifted one?
static bool gInNativeTest = false;

extern "C" {


// Native state before we run the native test case. We then use this as the
// initial state for the lifted testcase. The lifted test case code mutates
// this, and we require that after running the lifted testcase, `gStateBefore`
// matches `gStateAfter`,
std::aligned_storage<sizeof(State), alignof(State)>::type gLiftedState;

// Native state after running the native test case.
std::aligned_storage<sizeof(State), alignof(State)>::type gNativeState;

// Address of the native test to run. The `InvokeTestCase` function saves
// the native program state but then needs a way to figure out where to go
// without storing that information in any register. So what we do is we
// store it here and indirectly `JMP` into the native test case code after
// saving the machine state to `gStateBefore`.
uintptr_t gTestToRun = 0;

// Used for swapping the stack pointer between `gStack` and the normal
// call stack. This lets us run both native and lifted testcase code on
// the same stack.
uint8_t *gStackSwitcher = nullptr;

uint64_t gStackSaveSlots[2] = {0, 0};

// Invoke a native test case addressed by `gTestToRun` and store the machine
// state before and after executing the test in `gStateBefore` and
// `gStateAfter`, respectively.
extern void InvokeTestCase(uint64_t, uint64_t, uint64_t);

#define MAKE_RW_MEMORY(size) \
  NEVER_INLINE uint##size##_t __remill_read_memory_##size(Memory *, \
                                                          addr_t addr) { \
    return AccessMemory<uint##size##_t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_##size(Memory *, addr_t addr, \
                                                    const uint##size##_t in) { \
    AccessMemory<uint##size##_t>(addr) = in; \
    return nullptr; \
  }

#define MAKE_RW_FP_MEMORY(size) \
  NEVER_INLINE float##size##_t __remill_read_memory_f##size(Memory *, \
                                                            addr_t addr) { \
    return AccessMemory<float##size##_t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_f##size(Memory *, addr_t addr, \
                                                     float##size##_t in) { \
    AccessMemory<float##size##_t>(addr) = in; \
    return nullptr; \
  }

MAKE_RW_MEMORY(8)
MAKE_RW_MEMORY(16)
MAKE_RW_MEMORY(32)
MAKE_RW_MEMORY(64)

MAKE_RW_FP_MEMORY(32)
MAKE_RW_FP_MEMORY(64)
MAKE_RW_FP_MEMORY(128)

NEVER_INLINE Memory *__remill_read_memory_f80(Memory *, addr_t addr,
                                              native_float80_t &out) {
  out = AccessMemory<native_float80_t>(addr);
  return nullptr;
}

NEVER_INLINE Memory *__remill_write_memory_f80(Memory *, addr_t addr,
                                               const native_float80_t &in) {
  AccessMemory<native_float80_t>(addr) = in;
  return nullptr;
}

Memory *__remill_compare_exchange_memory_8(Memory *memory, addr_t addr,
                                           uint8_t &expected, uint8_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint8_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_16(Memory *memory, addr_t addr,
                                            uint16_t &expected,
                                            uint16_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint16_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_32(Memory *memory, addr_t addr,
                                            uint32_t &expected,
                                            uint32_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint32_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_64(Memory *memory, addr_t addr,
                                            uint64_t &expected,
                                            uint64_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint64_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_128(Memory *memory, addr_t addr,
                                             uint128_t &expected,
                                             uint128_t &desired) {
#ifdef _GXX_EXPERIMENTAL_CXX0X__
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint128_t *>(addr),
                                         expected, desired);
#endif
  return memory;
}

#define MAKE_ATOMIC_INTRINSIC(intrinsic_name, type_prefix, size) \
  Memory *__remill_##intrinsic_name##_##size(Memory *memory, addr_t addr, \
                                             type_prefix##size##_t &value) { \
    value = __sync_##intrinsic_name( \
        reinterpret_cast<type_prefix##size##_t *>(addr), value); \
    return memory; \
  }

MAKE_ATOMIC_INTRINSIC(fetch_and_add, uint, 8)
MAKE_ATOMIC_INTRINSIC(fetch_and_add, uint, 16)
MAKE_ATOMIC_INTRINSIC(fetch_and_add, uint, 32)
MAKE_ATOMIC_INTRINSIC(fetch_and_add, uint, 64)
MAKE_ATOMIC_INTRINSIC(fetch_and_sub, uint, 8)
MAKE_ATOMIC_INTRINSIC(fetch_and_sub, uint, 16)
MAKE_ATOMIC_INTRINSIC(fetch_and_sub, uint, 32)
MAKE_ATOMIC_INTRINSIC(fetch_and_sub, uint, 64)
MAKE_ATOMIC_INTRINSIC(fetch_and_or, uint, 8)
MAKE_ATOMIC_INTRINSIC(fetch_and_or, uint, 16)
MAKE_ATOMIC_INTRINSIC(fetch_and_or, uint, 32)
MAKE_ATOMIC_INTRINSIC(fetch_and_or, uint, 64)
MAKE_ATOMIC_INTRINSIC(fetch_and_and, uint, 8)
MAKE_ATOMIC_INTRINSIC(fetch_and_and, uint, 16)
MAKE_ATOMIC_INTRINSIC(fetch_and_and, uint, 32)
MAKE_ATOMIC_INTRINSIC(fetch_and_and, uint, 64)
MAKE_ATOMIC_INTRINSIC(fetch_and_xor, uint, 8)
MAKE_ATOMIC_INTRINSIC(fetch_and_xor, uint, 16)
MAKE_ATOMIC_INTRINSIC(fetch_and_xor, uint, 32)
MAKE_ATOMIC_INTRINSIC(fetch_and_xor, uint, 64)

int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {
  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}

Memory *__remill_barrier_load_load(Memory *) {
  return nullptr;
}
Memory *__remill_barrier_load_store(Memory *) {
  return nullptr;
}
Memory *__remill_barrier_store_load(Memory *) {
  return nullptr;
}
Memory *__remill_barrier_store_store(Memory *) {
  return nullptr;
}
Memory *__remill_atomic_begin(Memory *) {
  return nullptr;
}
Memory *__remill_atomic_end(Memory *) {
  return nullptr;
}

Memory *__remill_delay_slot_begin(Memory *) {
  return nullptr;
}
Memory *__remill_delay_slot_end(Memory *) {
  return nullptr;
}

void __remill_defer_inlining(void) {}

Memory *__remill_error(State &, addr_t, Memory *) {
  siglongjmp(gJmpBuf, 0);
}

Memory *__remill_missing_block(State &, addr_t, Memory *memory) {
  return memory;
}

Memory *__remill_sync_hyper_call(State &, Memory *, SyncHyperCall::Name) {
  abort();
}
// Read/write to I/O ports.
uint8_t __remill_read_io_port_8(Memory *, addr_t) {
  abort();
}

uint16_t __remill_read_io_port_16(Memory *, addr_t) {
  abort();
}

uint32_t __remill_read_io_port_32(Memory *, addr_t) {
  abort();
}

Memory *__remill_write_io_port_8(Memory *, addr_t, uint8_t) {
  abort();
}

Memory *__remill_write_io_port_16(Memory *, addr_t, uint16_t) {
  abort();
}

Memory *__remill_write_io_port_32(Memory *, addr_t, uint32_t) {
  abort();
}

Memory *__remill_function_call(State &, addr_t, Memory *) {
  abort();
}

Memory *__remill_function_return(State &, addr_t, Memory *) {
  abort();
}

Memory *__remill_jump(State &, addr_t, Memory *) {
  abort();
}

Memory *__remill_async_hyper_call(State &, addr_t, Memory *) {
  abort();
}

uint8_t __remill_undefined_8(void) {
  return 0;
}

uint16_t __remill_undefined_16(void) {
  return 0;
}

uint32_t __remill_undefined_32(void) {
  return 0;
}

uint64_t __remill_undefined_64(void) {
  return 0;
}

float32_t __remill_undefined_f32(void) {
  return 0.0;
}

float64_t __remill_undefined_f64(void) {
  return 0.0;
}

float80_t __remill_undefined_f80(void) {
  return {0};
}

float128_t __remill_undefined_f128(void) {
  return {0};
}


bool __remill_flag_computation_zero(bool result, ...) {
  return result;
}

bool __remill_flag_computation_sign(bool result, ...) {
  return result;
}

bool __remill_flag_computation_overflow(bool result, ...) {
  return result;
}

bool __remill_flag_computation_carry(bool result, ...) {
  return result;
}

bool __remill_compare_sle(bool result) {
  return result;
}

bool __remill_compare_slt(bool result) {
  return result;
}

bool __remill_compare_sge(bool result) {
  return result;
}

bool __remill_compare_sgt(bool result) {
  return result;
}


bool __remill_compare_ule(bool result) {
  return result;
}

bool __remill_compare_ult(bool result) {
  return result;
}

bool __remill_compare_ugt(bool result) {
  return result;
}

bool __remill_compare_uge(bool result) {
  return result;
}

bool __remill_compare_eq(bool result) {
  return result;
}

bool __remill_compare_neq(bool result) {
  return result;
}


// Marks `mem` as being used. This is used for making sure certain symbols are
// kept around through optimization, and makes sure that optimization doesn't
// perform dead-argument elimination on any of the intrinsics.
void __remill_mark_as_used(void *mem) {
  asm("" ::"m"(mem));
}

}  // extern C

typedef Memory *(LiftedFunc) (State &, addr_t, Memory *);

// Mapping of test name to translated function.
static std::map<uint64_t, LiftedFunc *> gTranslatedFuncs;

static std::vector<const test::TestInfo *> gTests;
}  // namespace

class InstrTest : public ::testing::TestWithParam<const test::TestInfo *> {};

template <typename T>
inline static bool operator==(const T &a, const T &b) {
  return !memcmp(&a, &b, sizeof(a));
}

template <typename T>
inline static bool operator!=(const T &a, const T &b) {
  return !!memcmp(&a, &b, sizeof(a));
}

static void RunWithFlags(const test::TestInfo *info, NZCV flags,
                         std::string desc, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3) {

  DLOG(INFO) << "Testing instruction: " << info->test_name << ": " << desc;
  if (sigsetjmp(gUnsupportedInstrBuf, true)) {
    DLOG(INFO) << "Unsupported instruction " << info->test_name;
    return;
  }

  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));
  memset(&gLiftedState, 0, sizeof(gLiftedState));
  memset(&gNativeState, 0, sizeof(gNativeState));

  auto lifted_state = reinterpret_cast<State *>(&gLiftedState);
  auto native_state = reinterpret_cast<State *>(&gNativeState);

  // Set up the run's info.
  gTestToRun = info->test_begin;
  gStackSwitcher = &(gLiftedStack._redzone2[0]);

  // This will execute on `gStack`. The mechanism behind this is that the
  // stack pointer is swapped with `gStackSwitcher`. The idea here is that
  // we want to run the native and lifted testcases on the same stack so that
  // we can compare that they both operate on the stack in the same ways.
  auto native_test_faulted = false;
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = true;
    asm("msr nzcv, %0" : : "r"(flags));
    InvokeTestCase(arg1, arg2, arg3);
  } else {
    native_test_faulted = true;
  }

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));

  auto lifted_func = gTranslatedFuncs[info->test_begin];

  // Includes the additional injected `adrp` and `add`.
  lifted_state->gpr.pc.aword = static_cast<addr_t>(info->test_begin + 4 + 4);

  // This will execute on our stack but the lifted code will operate on
  // `gLiftedStack`. The mechanism behind this is that `gLiftedState` is the
  // native program state recorded before executing the native testcase,
  // but after swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    std::fesetenv(FE_DFL_ENV);
    gInNativeTest = false;
    (void) lifted_func(*lifted_state, lifted_state->gpr.pc.aword, nullptr);
  } else {
    EXPECT_TRUE(native_test_faulted);
  }

  // The native test doesn't update
  native_state->gpr.pc.qword = info->test_end;

  // Used in the test cases to hold the `State *`.
  lifted_state->gpr.x28.qword = 0;
  native_state->gpr.x28.qword = 0;

  // Link pointer register (i.e. return address).
  lifted_state->gpr.x30.qword = 0;
  native_state->gpr.x30.qword = 0;

  native_state->hyper_call_vector = 0;
  lifted_state->hyper_call_vector = 0;

  native_state->hyper_call = AsyncHyperCall::kInvalid;
  lifted_state->hyper_call = AsyncHyperCall::kInvalid;

  EXPECT_TRUE(lifted_state->gpr == native_state->gpr);

  // The lifted code won't update these.
  native_state->nzcv.flat = 0;
  lifted_state->nzcv.flat = 0;
  native_state->fpcr.flat = 0;
  lifted_state->fpcr.flat = 0;
  native_state->fpsr.flat = 0;
  lifted_state->fpsr.flat = 0;

  if (gLiftedState != gNativeState) {
    LOG(ERROR) << "States did not match for " << desc;
    EXPECT_TRUE(!"Lifted and native states did not match.");

#define DIFF(name, a) EXPECT_EQ(lifted_state->a, native_state->a)

    DIFF(X0, gpr.x0.qword);
    DIFF(X1, gpr.x1.qword);
    DIFF(X2, gpr.x2.qword);
    DIFF(X3, gpr.x3.qword);
    DIFF(X4, gpr.x4.qword);
    DIFF(X5, gpr.x5.qword);
    DIFF(X6, gpr.x6.qword);
    DIFF(X7, gpr.x7.qword);
    DIFF(X8, gpr.x8.qword);
    DIFF(X9, gpr.x9.qword);
    DIFF(X10, gpr.x10.qword);
    DIFF(X11, gpr.x11.qword);
    DIFF(X12, gpr.x12.qword);
    DIFF(X13, gpr.x13.qword);
    DIFF(X14, gpr.x14.qword);
    DIFF(X15, gpr.x15.qword);
    DIFF(X16, gpr.x16.qword);
    DIFF(X17, gpr.x17.qword);
    DIFF(X18, gpr.x18.qword);
    DIFF(X19, gpr.x19.qword);
    DIFF(X20, gpr.x20.qword);
    DIFF(X21, gpr.x21.qword);
    DIFF(X22, gpr.x22.qword);
    DIFF(X23, gpr.x23.qword);
    DIFF(X24, gpr.x24.qword);
    DIFF(X25, gpr.x25.qword);
    DIFF(X26, gpr.x26.qword);
    DIFF(X27, gpr.x27.qword);
    DIFF(X28, gpr.x28.qword);
    DIFF(X29, gpr.x29.qword);
    DIFF(X30, gpr.x30.qword);

    DIFF(IXC, sr.ixc);
    DIFF(OFC, sr.ofc);
    DIFF(UFC, sr.ufc);
    DIFF(IDC, sr.idc);
    DIFF(IOC, sr.ioc);

    DIFF(N, sr.n);
    DIFF(Z, sr.z);
    DIFF(C, sr.c);
    DIFF(V, sr.v);

    auto lifted_state_bytes = reinterpret_cast<uint8_t *>(lifted_state);
    auto native_state_bytes = reinterpret_cast<uint8_t *>(native_state);

    for (size_t i = 0; i < sizeof(State); ++i) {
      LOG_IF(ERROR, lifted_state_bytes[i] != native_state_bytes[i])
          << "Bytes at offset " << i << " are different";
    }
  }

  if (gLiftedStack != gNativeStack) {
    LOG(ERROR) << "Stacks did not match for " << desc;

    for (size_t i = 0; i < sizeof(gLiftedStack.bytes); ++i) {
      if (gLiftedStack.bytes[i] != gNativeStack.bytes[i]) {
        LOG(ERROR) << "Lifted stack at 0x" << std::hex
                   << reinterpret_cast<uintptr_t>(&(gLiftedStack.bytes[i]))
                   << " does not match native stack at 0x" << std::hex
                   << reinterpret_cast<uintptr_t>(&(gNativeStack.bytes[i]))
                   << std::endl;
      }
    }

    EXPECT_TRUE(!"Lifted and native stacks did not match.");
  }
}

TEST_P(InstrTest, SemanticsMatchNative) {
  auto info = GetParam();
  CHECK(0 < info->num_args)
      << "Test " << info->test_name << " must have at least one argument!";

  for (auto args = info->args_begin; args < info->args_end;
       args += info->num_args) {
    std::stringstream ss;
    ss << info->test_name;
    if (1 <= info->num_args) {
      ss << " with X0=" << std::hex << args[0];
      if (2 <= info->num_args) {
        ss << ", X1=" << std::hex << args[1];
        if (3 <= info->num_args) {
          ss << ", X2=" << std::hex << args[3];
        }
      }
    }
    auto desc = ss.str();
    for (uint32_t i = 0; i <= 0xFU; ++i) {
      NZCV flags;
      flags.flat = i << 28;

      std::stringstream ss2;
      ss2 << desc << " and N=" << flags.n << ", Z=" << flags.z
          << ", C=" << flags.c << ", V=" << flags.v;

      RunWithFlags(info, flags, ss2.str(), args[0], args[1], args[2]);
    }
  }
}

std::string NameTest(const testing::TestParamInfo<InstrTest::ParamType> &test) {
  return test.param->test_name;
}

INSTANTIATE_TEST_SUITE_P(GeneralInstrTest, InstrTest, testing::ValuesIn(gTests),
                         NameTest);

// Recover from a signal.
static void RecoverFromError(int sig_num, siginfo_t *, void *context_) {
  if (gInNativeTest) {
    memcpy(&gNativeState, &gLiftedState, sizeof(State));

    auto context = reinterpret_cast<ucontext_t *>(context_);
    auto native_state = reinterpret_cast<State *>(&gNativeState);
    auto &gpr = native_state->gpr;
#ifdef __APPLE__

    //    const auto mcontext = context->uc_mcontext;
    //    const auto &ss = mcontext->__ss;

    (void) context;
    (void) native_state;
    (void) gpr;
    LOG(FATAL) << "Implement apple signal handler.";
#else

    // `mcontext_t` is actually a `struct sigcontext`, defined as:
    //    struct sigcontext {
    //      __u64 fault_address;
    //      /* AArch64 registers */
    //      __u64 regs[31];
    //      __u64 sp;
    //      __u64 pc;
    //      __u64 pstate;
    //      /* 4K reserved for FP/SIMD state and future expansion */
    //      __u8 __reserved[4096] __attribute__((__aligned__(16)));
    //    };

    const auto &mcontext = context->uc_mcontext;
    gpr.x0.qword = mcontext.regs[0];
    gpr.x1.qword = mcontext.regs[1];
    gpr.x2.qword = mcontext.regs[2];
    gpr.x3.qword = mcontext.regs[3];
    gpr.x4.qword = mcontext.regs[4];
    gpr.x5.qword = mcontext.regs[5];
    gpr.x6.qword = mcontext.regs[6];
    gpr.x7.qword = mcontext.regs[7];
    gpr.x8.qword = mcontext.regs[8];
    gpr.x9.qword = mcontext.regs[9];
    gpr.x10.qword = mcontext.regs[10];
    gpr.x11.qword = mcontext.regs[11];
    gpr.x12.qword = mcontext.regs[12];
    gpr.x13.qword = mcontext.regs[13];
    gpr.x14.qword = mcontext.regs[14];
    gpr.x15.qword = mcontext.regs[15];
    gpr.x16.qword = mcontext.regs[16];
    gpr.x17.qword = mcontext.regs[17];
    gpr.x18.qword = mcontext.regs[18];
    gpr.x19.qword = mcontext.regs[19];
    gpr.x20.qword = mcontext.regs[20];
    gpr.x21.qword = mcontext.regs[21];
    gpr.x22.qword = mcontext.regs[22];
    gpr.x23.qword = mcontext.regs[23];
    gpr.x24.qword = mcontext.regs[24];
    gpr.x25.qword = mcontext.regs[25];
    gpr.x26.qword = mcontext.regs[26];
    gpr.x27.qword = mcontext.regs[27];
    gpr.x28.qword = mcontext.regs[28];
    gpr.x29.qword = mcontext.regs[29];
    gpr.x30.qword = mcontext.regs[30];

    gpr.pc.qword = mcontext.pc;
    gpr.sp.qword = mcontext.sp;

    PSTATE pstate;
    pstate.flat = mcontext.pstate;
    native_state->sr.n = !!pstate.N;
    native_state->sr.z = !!pstate.Z;
    native_state->sr.c = !!pstate.C;
    native_state->sr.v = !!pstate.V;
#endif  // __APPLE__
  }
  siglongjmp(gJmpBuf, 0);
}

static void ConsumeTrap(int, siginfo_t *, void *) {}

static void HandleUnsupportedInstruction(int, siginfo_t *, void *) {
  siglongjmp(gUnsupportedInstrBuf, 0);
}

typedef void(SignalHandler)(int, siginfo_t *, void *);
static void HandleSignal(int sig_num, SignalHandler *handler) {
  struct sigaction sig;
  sig.sa_sigaction = handler;
  sig.sa_flags = SA_SIGINFO | SA_ONSTACK;
#ifndef __APPLE__
  sig.sa_restorer = nullptr;
#endif  // __APPLE__
  sigfillset(&(sig.sa_mask));
  sigaction(sig_num, &sig, nullptr);
}

// Set up various signal handlers.
static void SetupSignals(void) {
  HandleSignal(SIGSEGV, RecoverFromError);
  HandleSignal(SIGBUS, RecoverFromError);
  HandleSignal(SIGFPE, RecoverFromError);
  HandleSignal(SIGTRAP, ConsumeTrap);
  HandleSignal(SIGILL, HandleUnsupportedInstruction);
#ifdef SIGSTKFLT
  HandleSignal(SIGSTKFLT, RecoverFromError);
#endif  // SIGSTKFLT
  sigset_t set;
  sigemptyset(&set);
  sigprocmask(SIG_SETMASK, &set, nullptr);

  stack_t sig_stack;
  sig_stack.ss_sp = &gSigStack;
  sig_stack.ss_size = SIGSTKSZ;
  sig_stack.ss_flags = 0;
  sigaltstack(&sig_stack, nullptr);
}

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  auto this_exe = dlopen(nullptr, RTLD_NOW);

  // Populate the tests vector.
  for (auto i = 0U;; ++i) {
    const auto &test = test::__aarch64_test_table_begin[i];
    if (&test >= &(test::__aarch64_test_table_end[0]))
      break;
    gTests.push_back(&test);

    std::stringstream ss;
    ss << test.test_name << "_lifted";
    auto sym_func = dlsym(this_exe, ss.str().c_str());
    if (!sym_func) {
      sym_func = dlsym(this_exe, (std::string("_") + ss.str()).c_str());
    }

    CHECK(nullptr != sym_func)
        << "Could not find code for test case " << test.test_name;

    auto lifted_func = reinterpret_cast<LiftedFunc *>(sym_func);
    gTranslatedFuncs[test.test_begin] = lifted_func;
  }

  // Populate the random stack.
  memset(&gRandomStack, 0, sizeof(gRandomStack));
  for (auto &b : gRandomStack.bytes) {
    b = static_cast<uint8_t>(random());
  }

  testing::InitGoogleTest(&argc, argv);

  SetupSignals();
  return RUN_ALL_TESTS();
}
