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

#include <cfenv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>

#include <setjmp.h>
#include <signal.h>
#include <ucontext.h>

#include "tests/X86/Test.h"

#include "remill/Arch/Runtime/Runtime.h"
#include "remill/Arch/X86/Runtime/State.h"

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

static Flags gRflagsInitial;

static const addr_t g64BitMask = IF_64BIT_ELSE(~0UL, 0UL);

static const auto gStackBase = reinterpret_cast<uintptr_t>(
    &(gLiftedStack.bytes[0]));

static const auto gStackLimit = reinterpret_cast<uintptr_t>(
    &(gLiftedStack._redzone2[0]));

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

// Long doubles may be represented as 16-byte values depending on LLVM's
// `DataLayout`, so we marshal into this format.
struct alignas(16) LongDoubleStorage {
  float80_t val;
  uint16_t padding;
} __attribute__((packed));

static_assert(16 == sizeof(LongDoubleStorage),
              "Invalid structure packing of `LongDoubleStorage`");

extern "C" {

// Native state before we run the native test case. We then use this as the
// initial state for the lifted testcase. The lifted test case code mutates
// this, and we require that after running the lifted testcase, `gX86StateBefore`
// matches `gX86StateAfter`,
std::aligned_storage<sizeof(X86State), alignof(X86State)>::type gLiftedState;

// Native state after running the native test case.
std::aligned_storage<sizeof(X86State), alignof(X86State)>::type gNativeState;

// The RFLAGS to run the test with.
Flags gRflagsForTest = {};

// Address of the native test to run. The `InvokeTestCase` function saves
// the native program state but then needs a way to figure out where to go
// without storing that information in any register. So what we do is we
// store it here and indirectly `JMP` into the native test case code after
// saving the machine state to `gX86StateBefore`.
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

// Invoke a native test case addressed by `gTestToRun` and store the machine
// state before and after executing the test in `gX86StateBefore` and
// `gX86StateAfter`, respectively.
extern void InvokeTestCase(uint64_t, uint64_t, uint64_t);

#define MAKE_RW_MEMORY(size) \
  NEVER_INLINE uint ## size ## _t  __remill_read_memory_ ## size( \
     Memory *, addr_t addr) {\
    return AccessMemory<uint ## size ## _t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_ ## size( \
      Memory *, addr_t addr, const uint ## size ## _t in) { \
    AccessMemory<uint ## size ## _t>(addr) = in; \
    return nullptr; \
  }

#define MAKE_RW_FP_MEMORY(size) \
  NEVER_INLINE float ## size ## _t __remill_read_memory_f ## size( \
      Memory *, addr_t addr) { \
    return AccessMemory<float ## size ## _t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_f ## size(\
      Memory *, addr_t addr, float ## size ## _t in) { \
    AccessMemory<float ## size ## _t>(addr) = in; \
    return nullptr; \
  }

MAKE_RW_MEMORY(8)
MAKE_RW_MEMORY(16)
MAKE_RW_MEMORY(32)
MAKE_RW_MEMORY(64)

MAKE_RW_FP_MEMORY(32)
MAKE_RW_FP_MEMORY(64)

NEVER_INLINE float64_t __remill_read_memory_f80(Memory *, addr_t addr) {
  LongDoubleStorage storage;
  storage.val = AccessMemory<float80_t>(addr);
  auto val_long = *reinterpret_cast<long double *>(&storage);
  return static_cast<float64_t>(val_long);
}

NEVER_INLINE Memory *__remill_write_memory_f80(
    Memory *memory, addr_t addr, float64_t val) {
  LongDoubleStorage storage;
  auto val_long = static_cast<long double>(val);
  memcpy(&storage, &val_long, sizeof(val_long));
  AccessMemory<float80_t>(addr) = storage.val;
  return memory;
}

int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {
  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}

Memory *__remill_barrier_load_load(Memory *) { return nullptr; }
Memory *__remill_barrier_load_store(Memory *) { return nullptr; }
Memory *__remill_barrier_store_load(Memory *) { return nullptr; }
Memory *__remill_barrier_store_store(Memory *) { return nullptr; }
Memory *__remill_atomic_begin(Memory *) { return nullptr; }
Memory *__remill_atomic_end(Memory *) { return nullptr; }

void __remill_defer_inlining(void) {}

Memory *__remill_error(X86State &, addr_t, Memory *) {
  siglongjmp(gJmpBuf, 0);
}

Memory *__remill_missing_block(X86State &, addr_t, Memory *memory) {
  return memory;
}

Memory *__remill_sync_hyper_call(
    X86State &state, Memory *mem, SyncHyperCall::Name call) {
  auto eax = state.gpr.rax.dword;
  auto ebx = state.gpr.rbx.dword;
  auto ecx = state.gpr.rcx.dword;
  auto edx = state.gpr.rdx.dword;

  switch (call) {
    case SyncHyperCall::kX86CPUID:
      state.gpr.rax.aword = 0;
      state.gpr.rbx.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;

      asm volatile(
          "cpuid"
          : "=a"(state.gpr.rax.dword),
            "=b"(state.gpr.rbx.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
          : "a"(eax),
            "b"(ebx),
            "c"(ecx),
            "d"(edx)
      );
      break;

    case SyncHyperCall::kX86ReadTSC:
      state.gpr.rax.aword = 0;
      state.gpr.rdx.aword = 0;
      asm volatile(
          "rdtsc"
          : "=a"(state.gpr.rax.dword),
            "=d"(state.gpr.rdx.dword)
      );
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
      asm volatile(
          "rdtscp"
          : "=a"(state.gpr.rax.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
      );
      break;

    default:
      __builtin_unreachable();
  }

  return mem;
}

Memory *__remill_function_call(X86State &, addr_t, Memory *) {
  __builtin_unreachable();
}

Memory *__remill_function_return(X86State &, addr_t, Memory *) {
  __builtin_unreachable();
}

Memory *__remill_jump(X86State &, addr_t, Memory *) {
  __builtin_unreachable();
}

Memory *__remill_async_hyper_call(X86State &, addr_t, Memory *) {
  __builtin_unreachable();
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

// Marks `mem` as being used. This is used for making sure certain symbols are
// kept around through optimization, and makes sure that optimization doesn't
// perform dead-argument elimination on any of the intrinsics.
void __remill_mark_as_used(void *mem) {
  asm("" :: "m"(mem));
}

}  // extern C

typedef Memory *(LiftedFunc)(X86State &, addr_t, Memory *);

// Mapping of test name to translated function.
static std::map<uint64_t, LiftedFunc *> gTranslatedFuncs;

static std::vector<const test::TestInfo *> gTests;

static void InitFlags(void) {
  asm(
      "pushfq;"
      "pop %0;"
      :
      : "m"(gRflagsInitial));
}

// Convert some native state, stored in various ways, into the `X86State` structure
// type.
static void ImportX87X86State(X86State *state) {
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

    // Copy over the MMX data. A good guess for MMX data is that the the
    // value looks like its infinity.
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
      state->st.elems[i].val = static_cast<float64_t>(st);
    }
  }

  state->sw.c0 = fpu.fxsave.swd.c0;
//  state->sw.c1 = fpu.fxsave.swd.c1;
  state->sw.c2 = fpu.fxsave.swd.c2;
  state->sw.c3 = fpu.fxsave.swd.c3;
}

// Resets the flags to sane defaults. This will disable the trap flag, the
// alignment check flag, and the CPUID capability flag.
static void ResetFlags(void) {
  asm("push %0; popfq;" : : "m"(gRflagsInitial));
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

static void RunWithFlags(const test::TestInfo *info,
                         Flags flags,
                         std::string desc,
                         uint64_t arg1,
                         uint64_t arg2,
                         uint64_t arg3) {
  DLOG(INFO) << "Testing instruction: " << info->test_name << ": " << desc;
  if (sigsetjmp(gUnsupportedInstrBuf, true)) {
    DLOG(INFO) << "Unsupported instruction " << info->test_name;
    return;
  }

  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));
  memset(&gLiftedState, 0, sizeof(gLiftedState));
  memset(&gNativeState, 0, sizeof(gNativeState));

  auto lifted_state = reinterpret_cast<X86State *>(&gLiftedState);
  auto native_state = reinterpret_cast<X86State *>(&gNativeState);

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

  ImportX87X86State(native_state);
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
  // `gStack`. The mechanism behind this is that `gX86StateBefore` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = false;
    (void) lifted_func(
        *lifted_state,
        static_cast<addr_t>(lifted_state->gpr.rip.aword),
        nullptr);
  } else {
    EXPECT_TRUE(native_test_faulted);
  }

  ResetFlags();

  // We'll compare the `ST` and `XMM` regs via their other stored forms.
  auto kill_size = sizeof(lifted_state->x87) - offsetof(FPU, fxsave.st);
  memset(lifted_state->x87.fxsave.st, 0, kill_size);
  memset(native_state->x87.fxsave.st, 0, kill_size);

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

  // Compare the FPU states.
  for (auto i = 0U; i < 8U; ++i) {
    auto lifted_st = lifted_state->st.elems[i].val;
    auto native_st = native_state->st.elems[i].val;
    if (lifted_st != native_st) {
      if (fabs(lifted_st - native_st) <= 1e-14) {
        lifted_state->st.elems[i].val = native_st;  // Hide the inconsistency.
      }
    }
  }

  // Compare the register states.
  for (auto i = 0UL; i < kNumVecRegisters; ++i) {
    EXPECT_TRUE(lifted_state->vec[i] == native_state->vec[i]);
  }
  EXPECT_TRUE(lifted_state->aflag == native_state->aflag);
  EXPECT_TRUE(lifted_state->rflag == native_state->rflag);
  EXPECT_TRUE(lifted_state->seg == native_state->seg);
  EXPECT_TRUE(lifted_state->gpr == native_state->gpr);
  if (gLiftedState != gNativeState) {
    LOG(ERROR)
        << "States did not match for " << desc;
    EXPECT_TRUE(!"Lifted and native states did not match.");
  }
  if (gLiftedStack != gNativeStack) {
    LOG(ERROR)
        << "Stacks did not match for " << desc;

    for (size_t i = 0; i < sizeof(gLiftedStack.bytes); ++i) {
      if (gLiftedStack.bytes[i] != gNativeStack.bytes[i]) {
        LOG(ERROR)
            << "Lifted stack at 0x" << std::hex
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
  for (auto args = info->args_begin;
       args < info->args_end;
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
        uint32_t cf:1;
        uint32_t pf:1;
        uint32_t af:1;
        uint32_t zf:1;
        uint32_t sf:1;
        uint32_t df:1;
        uint32_t of:1;
        uint32_t _0:25;
      } __attribute__((packed));
    } __attribute__((packed));

    static_assert(sizeof(EFLAGS) == 4, "Invalid packing of `union EFLAGS`.");

    // Go through all possible flag combinations.
    for (uint32_t i = 0U; i <= 0x7FU; ++i) {
      EFLAGS eflags;
      eflags.flat = i;

      std::stringstream ss2;
      ss2 << desc << " and"
         << " CF=" << eflags.cf
         << " PF=" << eflags.pf
         << " AF=" << eflags.af
         << " ZF=" << eflags.zf
         << " SF=" << eflags.sf
         << " DF=" << eflags.df
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

INSTANTIATE_TEST_CASE_P(
    GeneralInstrTest,
    InstrTest,
    testing::ValuesIn(gTests));

// Recover from a signal.
static void RecoverFromError(int sig_num, siginfo_t *, void *context_) {
  if (gInNativeTest) {
    memcpy(&gNativeState, &gLiftedState, sizeof(X86State));

    auto context = reinterpret_cast<ucontext_t *>(context_);
    auto native_state = reinterpret_cast<X86State *>(&gNativeState);
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

static void ConsumeTrap(int, siginfo_t *, void *) {

}

static void HandleUnsupportedInstruction(int, siginfo_t *, void *) {
  siglongjmp(gUnsupportedInstrBuf, 0);
}

typedef void (SignalHandler) (int, siginfo_t *, void *);
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
  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
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
