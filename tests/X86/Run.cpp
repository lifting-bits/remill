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

#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Runtime.h"
#include "remill/Arch/X86/Runtime/State.h"
#include "tests/X86/Test.h"

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_bool(
    enable_fpu_cs_ds_checking, false,
    "Trace values of fxsave.cs and fxsave.ds for 32-bit instructions. Disabled "
    "by default since it is commonly broken in virtualized environments.");

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

static Flags gRflagsInitial;

static const addr_t g64BitMask = IF_64BIT_ELSE(~0UL, 0UL);

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
// this, and we require that after running the lifted testcase, `gLiftedState`
// matches `gNativeState`,
std::aligned_storage<sizeof(State), alignof(State)>::type gLiftedState;

// Native state after running the native test case.
std::aligned_storage<sizeof(State), alignof(State)>::type gNativeState;

// The RFLAGS to run the test with.
Flags gRflagsForTest = {};

// Address of the native test to run. The `InvokeTestCase` function saves
// the native program state but then needs a way to figure out where to go
// without storing that information in any register. So what we do is we
// store it here and indirectly `JMP` into the native test case code after
// saving the machine state to `gLiftedState`.
uintptr_t gTestToRun = 0;

// Used for swapping the stack pointer between `gStack` and the normal
// call stack. This lets us run both native and lifted testcase code on
// the same stack.
uint8_t *gStackSwitcher = nullptr;

// We need to capture the native flags state, and so we need a `PUSHFQ`.
// Unfortunately, this will be done on the 'recording' stack (`gStack`) in
// the native execution, and no corresponding operation like this is done in
// the lifted execution. What we need to do is save the value just below the
// top of the stack before the `PUSHFQ` clobbers it, then after we've recorded
// the native flags we restore what was clobbered by `PUSHFQ`.
uint64_t gStackSaveSlot = 0;

// Debug registers.
uint64_t DR0;
uint64_t DR1;
uint64_t DR2;
uint64_t DR3;
uint64_t DR4;
uint64_t DR5;
uint64_t DR6;
uint64_t DR7;

// Control registers.
CR0Reg gCR0;
CR1Reg gCR1;
CR2Reg gCR2;
CR3Reg gCR3;
CR4Reg gCR4;
#if 64 == ADDRESS_SIZE_BITS
CR8Reg gCR8;
#endif

// Invoke a native test case addressed by `gTestToRun` and store the machine
// state before and after executing the test in `gLiftedState` and
// `gNativeState`, respectively.
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
//MAKE_RW_FP_MEMORY(80)
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
#if !(defined(__x86_64__) || defined(__i386__) || defined(_M_X86))
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint128_t *>(addr),
                                         expected, desired);
#else
  bool result;
  struct alignas(16) uint128 {
    uint64_t lo;
    uint64_t hi;
  };

  uint128 *oldval = reinterpret_cast<uint128 *>(&expected);
  uint128 *newval = reinterpret_cast<uint128 *>(&desired);

  __asm__ __volatile__(
      "lock; cmpxchg16b %0; setz %1"
      : "=m"(*reinterpret_cast<uint128_t *>(addr)), "=q"(result)
      : "m"(*reinterpret_cast<uint128_t *>(addr)), "d"(oldval->hi),
        "a"(oldval->lo), "c"(newval->hi), "b"(newval->lo)
      : "memory");

  if (!result) {
    expected = *reinterpret_cast<uint128_t *>(addr);
  }
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

Memory *__remill_sync_hyper_call(State &state, Memory *mem,
                                 SyncHyperCall::Name call) {
  switch (call) {
    case SyncHyperCall::kX86CPUID:
      asm volatile("cpuid"
                   : "=a"(state.gpr.rax.aword), "=b"(state.gpr.rbx.aword),
                     "=c"(state.gpr.rcx.aword), "=d"(state.gpr.rdx.aword)
                   : "a"(state.gpr.rax.aword), "b"(state.gpr.rbx.aword),
                     "c"(state.gpr.rcx.aword), "d"(state.gpr.rdx.aword));
      break;

    case SyncHyperCall::kX86ReadTSC:
      asm volatile("rdtsc"
                   : "=a"(state.gpr.rax.dword), "=d"(state.gpr.rdx.dword));
      break;

    case SyncHyperCall::kX86ReadTSCP:
      asm volatile("rdtscp"
                   : "=a"(state.gpr.rax.aword), "=c"(state.gpr.rcx.aword),
                     "=d"(state.gpr.rdx.aword)
                   : "a"(state.gpr.rax.aword), "c"(state.gpr.rcx.aword),
                     "d"(state.gpr.rdx.aword));
      break;

    default: abort();
  }

  return mem;
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

static void InitFlags(void) {
  asm("pushfq;"
      "pop %0;"
      :
      : "m"(gRflagsInitial));
}

#if 32 == ADDRESS_SIZE_BITS

// Check if we are in a mode such that FCS and FDS are deprecated, and
// are thus zeroed out in FXSAVE, XSAVE, and XSAVEOPT.
//
// Per the Intel SDM Vol. 1, Section 8.1.8, this happens when:
//
//    CPUID.(EAX=07H,ECX=0H):EBX[bit 13] = 1
//
// Where "bit 13" is a 0-based index.
static bool AreFCSAndFDSDeprecated(void) {
  uint32_t eax = 0x7;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;

  if (!FLAGS_enable_fpu_cs_ds_checking) {

    // pretend FCS and FDS are deprecated if not checking via cmdline flag
    return true;
  }

  asm volatile("cpuid"
               : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
               : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));

  // Bit 13 of EBX is not zero.
  return (ebx & (1U << 13U)) != 0U;
}

#endif  // 32 == ADDRESS_SIZE_BITS

// Convert some native state, stored in various ways, into the `State` structure
// type.
static void ImportX87State(State *state) {
  auto &fpu = state->x87;

  // Looks like MMX state.
  if (kFPUAbridgedTagValid == fpu.fxsave.ftw.r0 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r1 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r2 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r3 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r4 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r5 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r6 &&
      kFPUAbridgedTagValid == fpu.fxsave.ftw.r7) {

    // Copy over the MMX data. A good guess for MMX data is that the
    // value looks like it's infinity.
    DLOG(INFO) << "Importing MMX state.";
    for (size_t i = 0; i < 8; ++i) {
      if (static_cast<uint16_t>(0xFFFFU) == fpu.fxsave.st[i].infinity) {
        state->mmx.elems[i].val.qwords.elems[0] = fpu.fxsave.st[i].mmx;
      }
    }

    // Looks like X87 state.
  } else {
    DLOG(INFO) << "Importing FPU state.";
    for (size_t i = 0; i < 8; ++i) {
      auto st = *reinterpret_cast<long double *>(&(fpu.fxsave.st[i].st));
      state->st.elems[i].val = static_cast<float80_t>(st);
    }
  }

  state->sw.c0 = fpu.fxsave.swd.c0;

  //  state->sw.c1 = fpu.fxsave.swd.c1;  // currently we do not model C1
  state->sw.c2 = fpu.fxsave.swd.c2;
  state->sw.c3 = fpu.fxsave.swd.c3;
}

// Resets the flags to sane defaults. This will disable the trap flag, the
// alignment check flag, and the CPUID capability flag.
static void ResetFlags(void) {
  asm("push %0; popfq;" : : "m"(gRflagsInitial));
}

// clear the exception flags in mxcsr
// *and* set MXCSR to ignore denormal exceptions
// this is done properly by std::fesetenv(FE_DFL_ENV) in newer (after 2015) glibcs
// but the logic in older versions (like eglibc 2.19, used on some Ubuntu 14.04 installations)
// does not clear exception flags and also does *not* ignore denormal exceptions
// see: https://sourceware.org/ml/libc-alpha/2015-10/msg01020.html
#if !defined(FE_DENORMALOPERAND) && defined(__FE_DENORM)
#  define FE_DENORMALOPERAND __FE_DENORM
#endif
#if !defined(FE_DENORMALOPERAND)
#  warning "Missing FE_DENORMALOPERAND."
#  define FE_DENORMALOPERAND 0x2
#endif
static void FixGlibcMxcsrBug() {
  const uint32_t FE_ALL_EXCEPT_X86 = (FE_ALL_EXCEPT | FE_DENORMALOPERAND);
  uint32_t mxcsr = 0;  // temporarily holds our MXCSR
  asm("stmxcsr %0;" : "=m"(mxcsr));

  // assumes the rest of MXCSR was sanely set by std::fesetenv(FE_DFL_ENV);

  // clear exceptions in MXCSR
  mxcsr &= ~FE_ALL_EXCEPT_X86;

  // set the exception mask for future exceptions
  mxcsr |= (FE_ALL_EXCEPT_X86 << 7);

  asm("ldmxcsr %0;" : : "m"(mxcsr));
}

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

static void RunWithFlags(const test::TestInfo *info, Flags flags,
                         std::string desc, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3) {

  // Can't fit a 64-bit stack address into a 32-bit register.
  auto stack_addr = reinterpret_cast<uintptr_t>(&(gLiftedStack.bytes[0]));
  if (sizeof(addr_t) < sizeof(uintptr_t) &&
      static_cast<uintptr_t>(static_cast<addr_t>(stack_addr)) != stack_addr) {
    return;
  }

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
  gRflagsForTest = flags;

  ResetFlags();

  // This will execute on `gStack`. The mechanism behind this is that the
  // stack pointer is swapped with `gStackSwitcher`. The idea here is that
  // we want to run the native and lifted testcases on the same stack so that
  // we can compare that they both operate on the stack in the same ways.
  auto native_test_faulted = false;
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = true;
    InvokeTestCase(arg1, arg2, arg3);
  } else {
    native_test_faulted = true;
  }

  ImportX87State(native_state);
  ResetFlags();

  // Set up the RIP correctly.
  lifted_state->gpr.rip.aword = static_cast<addr_t>(info->test_begin);
  native_state->gpr.rip.aword = static_cast<addr_t>(info->test_end);

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));

  auto lifted_func = gTranslatedFuncs[info->test_begin];

  // This will execute on our stack but the lifted code will operate on
  // `gStack`. The mechanism behind this is that `gLiftedState` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = false;
    std::fesetenv(FE_DFL_ENV);
    FixGlibcMxcsrBug();
    (void) lifted_func(*lifted_state,
                       static_cast<addr_t>(lifted_state->gpr.rip.aword),
                       nullptr);
  } else {
    EXPECT_TRUE(native_test_faulted);
  }

  ResetFlags();

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"

  // We'll compare the `ST` and `XMM` regs via their other stored forms.
  auto kill_size = sizeof(lifted_state->x87) - offsetof(FPU, fxsave.st);
#pragma clang diagnostic pop

  memset(lifted_state->x87.fxsave.st, 0, kill_size);
  memset(native_state->x87.fxsave.st, 0, kill_size);

#if 32 == ADDRESS_SIZE_BITS

  // If FCS and FDS are deprecated, don't compare them.
  if (AreFCSAndFDSDeprecated()) {
    lifted_state->x87.fxsave.cs = {0};
    lifted_state->x87.fxsave.ds = {0};

    native_state->x87.fxsave.cs = {0};
    native_state->x87.fxsave.ds = {0};
  }
#endif

  // New Intel CPUs have apparently stopped tracking `dp`, even though we track
  // it. E.g., in testing, an i7-4910MQ tracked `dp` but an i7-7920HQ did not.
  lifted_state->x87.fxsave.dp = 0;
  native_state->x87.fxsave.dp = 0;

  // Most machines have `fop` recording disabled, even though we track it.
  lifted_state->x87.fxsave.fop = 0;
  native_state->x87.fxsave.fop = 0;

  // Don't compare the tag words.
  lifted_state->x87.fxsave.ftw.flat = 0;
  native_state->x87.fxsave.ftw.flat = 0;

  // Getting C1 right is hard, so we don't try.
  lifted_state->x87.fxsave.swd.c1 = 0;
  native_state->x87.fxsave.swd.c1 = 0;
  lifted_state->sw.c1 = 0;
  native_state->sw.c1 = 0;

  // Marshal lifted status word info into the native form.
  lifted_state->x87.fxsave.swd.c0 = lifted_state->sw.c0;
  lifted_state->x87.fxsave.swd.c2 = lifted_state->sw.c2;
  lifted_state->x87.fxsave.swd.c3 = lifted_state->sw.c3;
  lifted_state->x87.fxsave.swd.ie = lifted_state->sw.ie;
  lifted_state->x87.fxsave.swd.de = lifted_state->sw.de;
  lifted_state->x87.fxsave.swd.ze = lifted_state->sw.ze;
  lifted_state->x87.fxsave.swd.oe = lifted_state->sw.oe;
  lifted_state->x87.fxsave.swd.ue = lifted_state->sw.ue;
  lifted_state->x87.fxsave.swd.pe = lifted_state->sw.pe;

  lifted_state->x87.fxsave.swd.flat = 0;
  native_state->x87.fxsave.swd.flat = 0;

  // TODO(pag): We don't support these yet.
  lifted_state->x87.fxsave.mxcsr.flat = 0;
  native_state->x87.fxsave.mxcsr.flat = 0;

  // Don't compare EIP on 32-bit because the tests we run natively (on 64-bits)
  // may be different than the 32-bit code that we lift. This is just so that
  // things actually work, e.g. stuff needing the REX.W prefix in the native
  // tests to execute.
#if 32 == ADDRESS_SIZE_BITS
  lifted_state->gpr.rip.aword = 0;
  native_state->gpr.rip.aword = 0;
#endif

  // Copy the aflags state back into the rflags state.
  lifted_state->rflag.cf = lifted_state->aflag.cf;
  lifted_state->rflag.pf = lifted_state->aflag.pf;
  lifted_state->rflag.af = lifted_state->aflag.af;
  lifted_state->rflag.zf = lifted_state->aflag.zf;
  lifted_state->rflag.sf = lifted_state->aflag.sf;
  lifted_state->rflag.df = lifted_state->aflag.df;
  lifted_state->rflag.of = lifted_state->aflag.of;

  // No longer want to compare these.
  memset(&(native_state->aflag), 0, sizeof(native_state->aflag));
  memset(&(lifted_state->aflag), 0, sizeof(lifted_state->aflag));

  // Only compare the non-undefined flags state.
  native_state->rflag.flat |= info->ignored_flags_mask;
  lifted_state->rflag.flat |= info->ignored_flags_mask;

  // Only compare generic flags.
  native_state->rflag.flat &= 0x0ED7UL;
  lifted_state->rflag.flat &= 0x0ED7UL;

  native_state->hyper_call_vector = 0;
  lifted_state->hyper_call_vector = 0;
  native_state->hyper_call = AsyncHyperCall::kInvalid;
  lifted_state->hyper_call = AsyncHyperCall::kInvalid;

  lifted_state->x87.fsave.cwd._rsvd0 = native_state->x87.fsave.cwd._rsvd0 = 0;
  lifted_state->x87.fsave.cwd._rsvd1 = native_state->x87.fsave.cwd._rsvd1 = 0;
  lifted_state->x87.fsave._rsvd0 = native_state->x87.fsave._rsvd0 = 0;
  lifted_state->x87.fsave._rsvd1 = native_state->x87.fsave._rsvd1 = 0;
  lifted_state->x87.fsave._rsvd2 = native_state->x87.fsave._rsvd2 = 0;
  lifted_state->x87.fsave._rsvd3 = native_state->x87.fsave._rsvd3 = 0;
  std::memset(lifted_state->sw._padding, 0, 4);
  std::memset(native_state->sw._padding, 0, 4);

  // Compare the FPU states.
  for (auto i = 0U; i < 8U; ++i) {
    auto lifted_st = lifted_state->st.elems[i].val;
    auto native_st = native_state->st.elems[i].val;
    if (lifted_st != native_st) {
      if (std::abs(lifted_st - native_st) <= 1e-14) {
        lifted_state->st.elems[i].val = native_st;  // Hide the inconsistency.
      }
    }
  }

  // Compare the register states.
  for (auto i = 0UL; i < kNumVecRegisters; ++i) {
    EXPECT_EQ(lifted_state->vec[i], native_state->vec[i]);
  }

  EXPECT_EQ(lifted_state->rflag, native_state->rflag)
      << "Lifted RFLAG after test is " << std::hex << lifted_state->rflag.flat
      << ", native is " << native_state->rflag.flat << std::dec;

  EXPECT_EQ(lifted_state->seg, native_state->seg)
      << "Lifted SEG differs from native SEG";

  EXPECT_EQ(lifted_state->gpr, native_state->gpr)
      << "Lifted GPR differs from native GPR";

  EXPECT_EQ(lifted_state->x87.fxsave.swd, native_state->x87.fxsave.swd)
      << "Lifted X87 status word after test is " << std::hex
      << lifted_state->x87.fxsave.swd.flat << ", native is "
      << native_state->x87.fxsave.swd.flat << std::dec;

  if (gLiftedState != gNativeState) {
    EXPECT_TRUE(false) << "States did not match for " << desc;

#define DIFF(name, a) EXPECT_EQ(lifted_state->a, native_state->a)

    DIFF(RAX, gpr.rax.aword);
    DIFF(RBX, gpr.rbx.aword);
    DIFF(RCX, gpr.rcx.aword);
    DIFF(RDX, gpr.rdx.aword);
    DIFF(RDI, gpr.rdi.aword);
    DIFF(RSI, gpr.rsi.aword);
    DIFF(RBP, gpr.rbp.aword);
    DIFF(RSP, gpr.rsp.aword);
    DIFF(R8, gpr.r8.aword);
    DIFF(R9, gpr.r9.aword);
    DIFF(R10, gpr.r10.aword);
    DIFF(R11, gpr.r11.aword);
    DIFF(R12, gpr.r12.aword);
    DIFF(R13, gpr.r13.aword);
    DIFF(R14, gpr.r14.aword);
    DIFF(R15, gpr.r15.aword);

    DIFF(RFLAG_CF, rflag.cf);
    DIFF(RFLAG_PF, rflag.pf);
    DIFF(RFLAG_AF, rflag.af);
    DIFF(RFLAG_ZF, rflag.zf);
    DIFF(RFLAG_SF, rflag.sf);
    DIFF(RFLAG_DF, rflag.df);
    DIFF(RFLAG_OF, rflag.of);

    DIFF(AFLAG_CF, aflag.cf);
    DIFF(AFLAG_PF, aflag.pf);
    DIFF(AFLAG_AF, aflag.af);
    DIFF(AFLAG_ZF, aflag.zf);
    DIFF(AFLAG_SF, aflag.sf);
    DIFF(AFLAG_DF, aflag.df);
    DIFF(AFLAG_OF, aflag.of);

    DIFF(ST0, st.elems[0].val);
    DIFF(ST1, st.elems[1].val);
    DIFF(ST2, st.elems[2].val);
    DIFF(ST3, st.elems[3].val);
    DIFF(ST4, st.elems[4].val);
    DIFF(ST5, st.elems[5].val);
    DIFF(ST6, st.elems[6].val);
    DIFF(ST7, st.elems[7].val);

    DIFF(MM0, mmx.elems[0].val.qwords.elems[0]);
    DIFF(MM1, mmx.elems[1].val.qwords.elems[0]);
    DIFF(MM2, mmx.elems[2].val.qwords.elems[0]);
    DIFF(MM3, mmx.elems[3].val.qwords.elems[0]);
    DIFF(MM4, mmx.elems[4].val.qwords.elems[0]);
    DIFF(MM5, mmx.elems[5].val.qwords.elems[0]);
    DIFF(MM6, mmx.elems[6].val.qwords.elems[0]);
    DIFF(MM7, mmx.elems[7].val.qwords.elems[0]);

    DIFF(FXSAVE_CWD_IM, x87.fxsave.cwd.im);
    DIFF(FXSAVE_CWD_DM, x87.fxsave.cwd.dm);
    DIFF(FXSAVE_CWD_ZM, x87.fxsave.cwd.zm);
    DIFF(FXSAVE_CWD_OM, x87.fxsave.cwd.om);
    DIFF(FXSAVE_CWD_UM, x87.fxsave.cwd.um);
    DIFF(FXSAVE_CWD_PM, x87.fxsave.cwd.pm);

    DIFF(FXSAVE_SWD_IE, x87.fxsave.swd.ie);
    DIFF(FXSAVE_SWD_DE, x87.fxsave.swd.de);
    DIFF(FXSAVE_SWD_ZE, x87.fxsave.swd.ze);
    DIFF(FXSAVE_SWD_OE, x87.fxsave.swd.oe);
    DIFF(FXSAVE_SWD_UE, x87.fxsave.swd.ue);
    DIFF(FXSAVE_SWD_PE, x87.fxsave.swd.pe);
    DIFF(FXSAVE_SWD_SF, x87.fxsave.swd.sf);
    DIFF(FXSAVE_SWD_ES, x87.fxsave.swd.es);
    DIFF(FXSAVE_SWD_C0, x87.fxsave.swd.c0);
    DIFF(FXSAVE_SWD_C1, x87.fxsave.swd.c1);
    DIFF(FXSAVE_SWD_C2, x87.fxsave.swd.c2);
    DIFF(FXSAVE_SWD_TOP, x87.fxsave.swd.top);
    DIFF(FXSAVE_SWD_C3, x87.fxsave.swd.c3);
    DIFF(FXSAVE_SWD_B, x87.fxsave.swd.b);

    auto lifted_state_bytes = reinterpret_cast<uint8_t *>(lifted_state);
    auto native_state_bytes = reinterpret_cast<uint8_t *>(native_state);

// Ignore "invalid use of offsetof" warnings by clang.
// 1) offsetof still works
// 2) we know its invalid
// 3) this is only used for diagnostics/debugging
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"

    for (size_t i = 0; i < sizeof(State); ++i) {
      LOG_IF(ERROR, lifted_state_bytes[i] != native_state_bytes[i])
          << "Bytes at offset " << i << " are different: "
          << "lifted [" << std::hex
          << static_cast<unsigned int>(lifted_state_bytes[i]) << "] vs native ["
          << std::hex << static_cast<unsigned int>(native_state_bytes[i])
          << "]\n"
          << std::dec << "vec: " << offsetof(State, vec) << "\n"
          << "aflag:" << offsetof(State, aflag) << "\n"
          << "rflag:" << offsetof(State, rflag) << "\n"
          << "seg:" << offsetof(State, seg) << "\n"
          << "addr:" << offsetof(State, addr) << "\n"
          << "gpr:" << offsetof(State, gpr) << "\n"
          << "st:" << offsetof(State, st) << "\n"
          << "mmx:" << offsetof(State, mmx) << "\n"
          << "sw:" << offsetof(State, sw) << "\n"
          << "xcr0:" << offsetof(State, xcr0) << "\n"
          << "x87:" << offsetof(State, x87) << "\n"
          << "seg_caches:" << offsetof(State, seg_caches) << "\n";
    }
#pragma clang diagnostic pop
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
  for (auto args = info->args_begin; args < info->args_end;
       args += info->num_args) {
    std::stringstream ss;
    ss << info->test_name << " with";
    if (1 <= info->num_args) {
      ss << " ARG1=0x" << std::hex << args[0];
      if (2 <= info->num_args) {
        ss << " ARG2=0x" << std::hex << args[1];
        if (3 <= info->num_args) {
          ss << " ARG3=0x" << std::hex << args[3];
        }
      }
    }
    auto desc = ss.str();

    union EFLAGS {
      uint32_t flat;
      struct {
        uint32_t cf : 1;
        uint32_t pf : 1;
        uint32_t af : 1;
        uint32_t zf : 1;
        uint32_t sf : 1;
        uint32_t df : 1;
        uint32_t of : 1;
        uint32_t _0 : 25;
      } __attribute__((packed));
    } __attribute__((packed));

    static_assert(sizeof(EFLAGS) == 4, "Invalid packing of `union EFLAGS`.");

    // Go through all possible flag combinations.
    for (uint32_t i = 0U; i <= 0x7FU; ++i) {
      EFLAGS eflags;
      eflags.flat = i;

      std::stringstream ss2;
      ss2 << desc << " and"
          << " CF=" << eflags.cf << " PF=" << eflags.pf << " AF=" << eflags.af
          << " ZF=" << eflags.zf << " SF=" << eflags.sf << " DF=" << eflags.df
          << " OF=" << eflags.of;

      Flags flags = gRflagsInitial;
      flags.cf = eflags.cf;
      flags.pf = eflags.pf;
      flags.af = eflags.af;
      flags.zf = eflags.zf;
      flags.sf = eflags.sf;
      flags.df = eflags.df;
      flags.of = eflags.of;

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
    auto &fpu = native_state->x87;
#ifdef __APPLE__
    const auto mcontext = context->uc_mcontext;
    const auto &ss = mcontext->__ss;
    gpr.rax.aword = static_cast<addr_t>(ss.__rax);
    gpr.rbx.aword = static_cast<addr_t>(ss.__rbx);
    gpr.rcx.aword = static_cast<addr_t>(ss.__rcx);
    gpr.rdx.aword = static_cast<addr_t>(ss.__rdx);
    gpr.rsi.aword = static_cast<addr_t>(ss.__rsi);
    gpr.rdi.aword = static_cast<addr_t>(ss.__rdi);
    gpr.rbp.aword = static_cast<addr_t>(ss.__rbp);
    gpr.rsp.aword = static_cast<addr_t>(ss.__rsp);
    gpr.r8.aword = static_cast<addr_t>(ss.__r8) & g64BitMask;
    gpr.r9.aword = static_cast<addr_t>(ss.__r9) & g64BitMask;
    gpr.r10.aword = static_cast<addr_t>(ss.__r10) & g64BitMask;
    gpr.r11.aword = static_cast<addr_t>(ss.__r11) & g64BitMask;
    gpr.r12.aword = static_cast<addr_t>(ss.__r12) & g64BitMask;
    gpr.r13.aword = static_cast<addr_t>(ss.__r13) & g64BitMask;
    gpr.r14.aword = static_cast<addr_t>(ss.__r14) & g64BitMask;
    gpr.r15.aword = static_cast<addr_t>(ss.__r15) & g64BitMask;
    native_state->rflag.flat = ss.__rflags;
    memcpy(&fpu, &(mcontext->__fs), sizeof(fpu));
#else
    const auto &mcontext = context->uc_mcontext;
    gpr.rax.aword = static_cast<addr_t>(mcontext.gregs[REG_RAX]);
    gpr.rbx.aword = static_cast<addr_t>(mcontext.gregs[REG_RBX]);
    gpr.rcx.aword = static_cast<addr_t>(mcontext.gregs[REG_RCX]);
    gpr.rdx.aword = static_cast<addr_t>(mcontext.gregs[REG_RDX]);
    gpr.rsi.aword = static_cast<addr_t>(mcontext.gregs[REG_RSI]);
    gpr.rdi.aword = static_cast<addr_t>(mcontext.gregs[REG_RDI]);
    gpr.rbp.aword = static_cast<addr_t>(mcontext.gregs[REG_RBP]);
    gpr.rsp.aword = static_cast<addr_t>(mcontext.gregs[REG_RSP]);
    gpr.r8.aword = static_cast<addr_t>(mcontext.gregs[REG_R8]) & g64BitMask;
    gpr.r9.aword = static_cast<addr_t>(mcontext.gregs[REG_R9]) & g64BitMask;
    gpr.r10.aword = static_cast<addr_t>(mcontext.gregs[REG_R10]) & g64BitMask;
    gpr.r11.aword = static_cast<addr_t>(mcontext.gregs[REG_R11]) & g64BitMask;
    gpr.r12.aword = static_cast<addr_t>(mcontext.gregs[REG_R12]) & g64BitMask;
    gpr.r13.aword = static_cast<addr_t>(mcontext.gregs[REG_R13]) & g64BitMask;
    gpr.r14.aword = static_cast<addr_t>(mcontext.gregs[REG_R14]) & g64BitMask;
    gpr.r15.aword = static_cast<addr_t>(mcontext.gregs[REG_R15]) & g64BitMask;

    native_state->rflag.flat = context->uc_mcontext.gregs[REG_EFL];
    memcpy(&fpu, context->uc_mcontext.fpregs, sizeof(fpu));
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

  InitFlags();

  auto this_exe = dlopen(nullptr, RTLD_NOW);

  // Populate the tests vector.
  for (auto i = 0U;; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0]))
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
