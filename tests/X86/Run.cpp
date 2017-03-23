/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define _XOPEN_SOURCE

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

DEFINE_string(arch, "", "");
DEFINE_string(os, "", "");

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

static Flags gRflagsOff;
static Flags gRflagsOn;
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

// Used to record the FPU. We will use this to migrate native X87 or MMX
// state into the `State` structure.
FPU gFPU = {};

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

Memory *__remill_barrier_load_load(Memory *) { return nullptr; }
Memory *__remill_barrier_load_store(Memory *) { return nullptr; }
Memory *__remill_barrier_store_load(Memory *) { return nullptr; }
Memory *__remill_barrier_store_store(Memory *) { return nullptr; }
Memory *__remill_atomic_begin(Memory *) { return nullptr; }
Memory *__remill_atomic_end(Memory *) { return nullptr; }

void __remill_defer_inlining(void) {}

Memory *__remill_error(Memory *, State &, addr_t) {
  siglongjmp(gJmpBuf, 0);
}

Memory *__remill_missing_block(Memory *memory, State &, addr_t) {
  return memory;
}

Memory *__remill_sync_hyper_call(
    Memory *mem, State &state, SyncHyperCall::Name call) {
  switch (call) {
    case SyncHyperCall::kX86CPUID:
      asm volatile(
          "cpuid"
          : "=a"(state.gpr.rax.dword),
            "=b"(state.gpr.rbx.dword),
            "=c"(state.gpr.rcx.dword),
            "=d"(state.gpr.rdx.dword)
          : "a"(state.gpr.rax.dword),
            "b"(state.gpr.rbx.dword),
            "c"(state.gpr.rcx.dword),
            "d"(state.gpr.rdx.dword)
      );
      break;

    default:
      __builtin_unreachable();
  }

  return mem;
}

Memory *__remill_function_call(Memory *, State &, addr_t) {
  __builtin_unreachable();
}

Memory *__remill_function_return(Memory *, State &, addr_t) {
  __builtin_unreachable();
}

Memory *__remill_jump(Memory *, State &, addr_t) {
  __builtin_unreachable();
}

Memory *__remill_async_hyper_call(Memory *, State &, addr_t) {
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

typedef Memory *(LiftedFunc)(Memory *, State &, addr_t);

// Mapping of test name to translated function.
static std::map<uint64_t, LiftedFunc *> gTranslatedFuncs;

static std::vector<const test::TestInfo *> gTests;

static void InitFlags(void) {
  asm(
      "pushfq;"
      "pushfq;"
      "pushfq;"
      "pop %0;"
      "pop %1;"
      "pop %2;"
      :
      : "m"(gRflagsOn),
        "m"(gRflagsOff),
        "m"(gRflagsInitial));

  gRflagsOn.cf = true;
  gRflagsOn.pf = true;
  gRflagsOn.af = true;
  gRflagsOn.zf = true;
  gRflagsOn.sf = true;
  gRflagsOn.df = true;
  gRflagsOn.of = true;

  gRflagsOff.cf = false;
  gRflagsOff.pf = false;
  gRflagsOff.af = false;
  gRflagsOff.zf = false;
  gRflagsOff.sf = false;
  gRflagsOff.df = false;
  gRflagsOff.of = false;
}

// Convert some native state, stored in various ways, into the `State` structure
// type.
static void ImportX87State(State *state) {

  // Looks like MMX state.
  if (kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r0 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r1 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r2 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r3 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r4 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r5 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r6 &&
      kFPUAbridgedTagValid == gFPU.ftw.fxsave.abridged.r7) {

    // Copy over the MMX data. A good guess for MMX data is that the the
    // value looks like its infinity.
    DLOG(INFO) << "Importing MMX state.";
    for (size_t i = 0; i < 8; ++i) {
      if (static_cast<uint16_t>(0xFFFFU) == gFPU.st[i].infinity) {
        state->mmx.elems[i].val.qwords.elems[0] = gFPU.st[i].mmx;
      }
    }

  // Looks like X87 state.
  } else {
    DLOG(INFO) << "Importing FPU state.";
    for (size_t i = 0; i < 8; ++i) {
      auto st = *reinterpret_cast<long double *>(&(gFPU.st[i].st));
      state->st.elems[i].val = static_cast<float64_t>(st);
    }
  }

  state->sw.c0 = gFPU.swd.c0;
//  state->sw.c1 = gFPU.swd.c1;
  state->sw.c2 = gFPU.swd.c2;
  state->sw.c3 = gFPU.swd.c3;
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

  auto lifted_state = reinterpret_cast<State *>(&gLiftedState);
  auto native_state = reinterpret_cast<State *>(&gNativeState);

  // This will be used to initialize the native flags state before executing
  // the native test.
  lifted_state->rflag = flags;

  // Set up the run's info.
  gTestToRun = info->test_begin;
  gStackSwitcher = &(gLiftedStack._redzone2[0]);

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

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));

  auto lifted_func = gTranslatedFuncs[info->test_begin];

  // This will execute on our stack but the lifted code will operate on
  // `gStack`. The mechanism behind this is that `gStateBefore` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = false;
    (void) lifted_func(
        nullptr, *lifted_state,
        static_cast<addr_t>(lifted_state->gpr.rip.aword));
  } else {
    EXPECT_TRUE(native_test_faulted);
  }

  ResetFlags();

  // Don't compare the program counters. The code that is lifted is equivalent
  // to the code that is tested but because they are part of separate binaries
  // it means that there is not necessarily any relation between their values.
  //
  // This also lets us compare 32-bit-only lifted code with 32-bit only
  // testcases, where the native 32-bit code actually emulates the 32-bit
  // behavior in 64-bit (because all of this code is compiled as 64-bit).
  lifted_state->gpr.rip.aword = 0;
  native_state->gpr.rip.aword = 0;

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

  native_state->interrupt_vector = 0;
  lifted_state->interrupt_vector = 0;
  native_state->hyper_call = AsyncHyperCall::kInvalid;
  lifted_state->hyper_call = AsyncHyperCall::kInvalid;

  // Compare the FPU states.
  for (auto i = 0U; i < 8U; ++i) {
    auto &lifted_st = lifted_state->st.elems[i].val;
    auto &native_st = native_state->st.elems[i].val;
    if (lifted_st != native_st) {
      if (fabs(lifted_st - native_st) <= 1e-14) {
        lifted_st = native_st;  // Hide the inconsistency.
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
        << "States did not match for " << info->test_name
        << " with arguments " << std::hex << arg1 << ", "
        << std::hex << arg2 << ", " << std::hex << arg3;
    EXPECT_TRUE(!"Lifted and native states did not match.");
  }
  if (gLiftedStack != gNativeStack) {
    LOG(ERROR)
        << "Stacks did not match for " << info->test_name
        << " with arguments " << std::hex << arg1 << ", "
        << std::hex << arg2 << ", " << std::hex << arg3;

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
    if (1 <= info->num_args) {
      ss << "args: 0x" << std::hex << args[0];
      if (2 <= info->num_args) {
        ss << ", 0x" << std::hex << args[1];
        if (3 <= info->num_args) {
          ss << ", 0x" << std::hex << args[3];
        }
      }
      ss << ";" << std::dec;
    }
    auto desc = ss.str();
    RunWithFlags(info, gRflagsOn, desc + " aflags on",
                 args[0], args[1], args[2]);
    RunWithFlags(info, gRflagsOff, desc + " aflags off",
                 args[0], args[1], args[2]);
  }
}

INSTANTIATE_TEST_CASE_P(
    GeneralInstrTest,
    InstrTest,
    testing::ValuesIn(gTests));

// Recover from a signal.
static void RecoverFromError(int sig_num, siginfo_t *, void *context_) {
  if (gInNativeTest) {
    memcpy(&gNativeState, &gLiftedState, sizeof(State));

    auto context = reinterpret_cast<ucontext_t *>(context_);
    auto native_state = reinterpret_cast<State *>(&gNativeState);
    auto &gpr = native_state->gpr;
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
    memcpy(&gFPU, &(mcontext->__fs), sizeof(gFPU));
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
    memcpy(&gFPU, context->uc_mcontext.fpregs, sizeof(gFPU));
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
