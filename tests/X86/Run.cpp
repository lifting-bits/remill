/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define _XOPEN_SOURCE

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <type_traits>
#include <vector>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include <setjmp.h>
#include <signal.h>
#include <ucontext.h>

#include "tests/X86/Test.h"

#include "remill/Arch/X86/Runtime/State.h"

namespace {

typedef void (*LiftedFunc)(State *);

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

// Used to mask the registers from a signal context when we've caught an error.
static uintptr_t gRegMask32 = 0;
static uintptr_t gRegMask64 = 0;

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
NEVER_INLINE addr_t __remill_compute_address(const State &state, addr_t addr,
                                             int address_space) {
  (void) state;
  (void) address_space;
  return addr;
}

NEVER_INLINE addr_t __remill_create_program_counter(addr_t pc) {
  return pc;
}

#define MAKE_RW_MEMORY(size) \
  NEVER_INLINE uint ## size ## _t  __remill_read_memory_ ## size( \
     Memory *, addr_t addr) {\
    return AccessMemory<uint ## size ## _t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_ ## size ( \
      Memory *, addr_t addr, const uint ## size ## _t in) { \
    AccessMemory<uint ## size ## _t>(addr) = in; \
    return nullptr; \
  }

#define MAKE_RW_FP_MEMORY(size) \
  NEVER_INLINE float ## size ## _t __remill_read_memory_f ## size( \
      Memory *, addr_t addr) { \
    return AccessMemory<float ## size ## _t>(addr); \
  } \
  NEVER_INLINE Memory *__remill_write_memory_f ## size (\
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

NEVER_INLINE void __remill_read_memory_f80(Memory *, addr_t, float80_t &) {

}
//MAKE_RW_FP_MEMORY(80)

Memory *__remill_barrier_load_load(Memory *) { return nullptr; }
Memory *__remill_barrier_load_store(Memory *) { return nullptr; }
Memory *__remill_barrier_store_load(Memory *) { return nullptr; }
Memory *__remill_barrier_store_store(Memory *) { return nullptr; }
Memory *__remill_atomic_begin(Memory *) { return nullptr; }
Memory *__remill_atomic_end(Memory *) { return nullptr; }

void __remill_defer_inlining(void) {}

// Control-flow intrinsics.
void __remill_missing_block(State &, Memory *, addr_t) {
  // This is where we want to end up.
}

void __remill_error(State &, Memory *, addr_t) {
  std::cerr << "Caught error!" << std::endl;
  siglongjmp(gJmpBuf, 0);
}

void __remill_read_cpu_features(State &state, Memory *, addr_t) {
  asm volatile(
      "cpuid"
      : "=a"(state.gpr.rax.qword),
        "=b"(state.gpr.rbx.qword),
        "=c"(state.gpr.rcx.qword),
        "=d"(state.gpr.rdx.qword)
      : "a"(state.gpr.rax.qword),
        "b"(state.gpr.rbx.qword),
        "c"(state.gpr.rcx.qword),
        "d"(state.gpr.rdx.qword)
  );
}

void __remill_function_call(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

void __remill_function_return(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

void __remill_jump(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

addr_t __remill_conditional_branch(
    bool cond, addr_t addr_true, addr_t addr_false) {
  return cond ? addr_true : addr_false;
}

void __remill_system_call(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

void __remill_system_return(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

void __remill_interrupt_call(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

void __remill_interrupt_return(State &, Memory *, addr_t) {
  __builtin_unreachable();
}

bool __remill_undefined_bool(void) {
  return false;
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
//
//void __remill_read_f80(const float80_t &in, float64_t &out) {
//  struct alignas(16) LongDoubleStorage {
//    uint8_t bytes[16];
//  } storage;
//
//  memset(&storage, 0, sizeof(storage));
//  memcpy(&storage, &in, sizeof(in));
//  out.val = static_cast<double>(*reinterpret_cast<long double *>(&storage));
//}
//
//void __remill_write_f80(const float64_t &in, float80_t &out) {
//  struct alignas(16) LongDoubleStorage {
//    uint8_t bytes[16];
//  } storage;
//  auto val = static_cast<long double>(in.val);
//  memset(&storage, 0, sizeof(storage));
//  *reinterpret_cast<long double *>(&storage) = val;
//  memcpy(&out, &storage, sizeof(out));
//}

// Marks `mem` as being used. This is used for making sure certain symbols are
// kept around through optimization, and makes sure that optimization doesn't
// perform dead-argument elimination on any of the intrinsics.
void __remill_mark_as_used(void *mem) {
  asm("" :: "m"(mem));
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

static void InitFlags(void) {
  asm("pushfq; pushfq; pop %0; pop %1;" : : "m"(gRflagsOn), "m"(gRflagsOff));

  gRflagsOn.cf = true;
  gRflagsOn.pf = true;
  gRflagsOn.af = true;
  gRflagsOn.zf = true;
  gRflagsOn.sf = true;
  gRflagsOn.df = true;
  gRflagsOn.of = true;

  gRflagsOn.tf = false;
  gRflagsOn.ac = false;
  gRflagsOn.nt = false;
  gRflagsOn.id = false;
  gRflagsOn.iopl = 0;

  gRflagsOff.cf = false;
  gRflagsOff.pf = false;
  gRflagsOff.af = false;
  gRflagsOff.zf = false;
  gRflagsOff.sf = false;
  gRflagsOff.df = false;
  gRflagsOff.of = false;

  gRflagsOff.tf = false;
  gRflagsOff.ac = false;
  gRflagsOff.nt = false;
  gRflagsOff.id = false;
  gRflagsOff.iopl = 0;
}

// Resets the flags to sane defaults. This will disable the trap flag, the
// alignment check flag, and the CPUID capability flag.
static void ResetFlags(void) {
  Flags flags;
  asm("pushfq; pop %0;" : : "m"(flags));
  flags.ac = false;
  flags.id = false;
  flags.tf = false;
  flags.rf = false;
  flags.nt = false;
  flags.iopl = 0;
  asm("push %0; popfq;" : : "m"(flags));
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
  LOG(INFO) << "Testing instruction: " << info->test_name << ": " << desc;
  if (sigsetjmp(gUnsupportedInstrBuf, true)) {
    LOG(INFO) << "Unsupported instruction " << info->test_name;
    return;
  }

  // Set up the GPR mask just in case an error occurs when we execute this
  // instruction.
  if (64 == ADDRESS_SIZE_BITS) {
    gRegMask32 = std::numeric_limits<uint64_t>::max();
    gRegMask64 = gRegMask32;
  } else {
    gRegMask32 = std::numeric_limits<uint32_t>::max();
    gRegMask64 = 0;
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
  ResetFlags();

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memcpy(&gLiftedStack, &gRandomStack, sizeof(gLiftedStack));

  // This will execute on our stack but the lifted code will operate on
  // `gStack`. The mechanism behind this is that `gStateBefore` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    gInNativeTest = false;
    info->lifted_func(lifted_state, nullptr, lifted_state->gpr.rip.qword);
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
  lifted_state->gpr.rip.qword = 0;
  native_state->gpr.rip.qword = 0;

  CopyXMMRegsIntoFPU(lifted_state);

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

  // Don't even bother with the MXCSR (SSE control/status register).
  lifted_state->fpu.mxcsr.flat = native_state->fpu.mxcsr.flat;

  // Compare the register states.
  EXPECT_TRUE(lifted_state->fpu == native_state->fpu);
  for (auto i = 0UL; i < kNumVecRegisters; ++i) {
    EXPECT_TRUE(lifted_state->vec[i] == native_state->vec[i]);
  }
  EXPECT_TRUE(lifted_state->aflag == native_state->aflag);
  EXPECT_TRUE(lifted_state->rflag == native_state->rflag);
  EXPECT_TRUE(lifted_state->seg == native_state->seg);
  EXPECT_TRUE(lifted_state->gpr == native_state->gpr);
  if (gLiftedState != gNativeState) {
    EXPECT_TRUE(!"Lifted and native states did not match.");
  }
  if (gLiftedStack != gNativeStack) {
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
    RunWithFlags(info, gRflagsOn, desc + " aflags on", args[0], args[1], args[2]);
    RunWithFlags(info, gRflagsOff, desc + " aflags off", args[0], args[1], args[2]);
  }
}

INSTANTIATE_TEST_CASE_P(
    GeneralInstrTest,
    InstrTest,
    testing::ValuesIn(gTests));

// Recover from a signal.
static void RecoverFromError(int sig_num, siginfo_t *, void *context_) {
  if (gInNativeTest) {
    std::cerr << "Caught signal " << sig_num << "!" << std::endl;
    memcpy(&gNativeState, &gLiftedState, sizeof(State));

    auto context = reinterpret_cast<ucontext_t *>(context_);
    auto native_state = reinterpret_cast<State *>(&gNativeState);
#ifdef __APPLE__
    const auto mcontext = context->uc_mcontext;
    const auto &ss = mcontext->__ss;
    native_state->gpr.rax.qword = ss.__rax & gRegMask32;
    native_state->gpr.rbx.qword = ss.__rbx & gRegMask32;
    native_state->gpr.rcx.qword = ss.__rcx & gRegMask32;
    native_state->gpr.rdx.qword = ss.__rdx & gRegMask32;
    native_state->gpr.rsi.qword = ss.__rsi & gRegMask32;
    native_state->gpr.rdi.qword = ss.__rdi & gRegMask32;
    native_state->gpr.rbp.qword = ss.__rbp & gRegMask32;
    native_state->gpr.rsp.qword = ss.__rsp & gRegMask32;
    native_state->gpr.r8.qword = ss.__r8 & gRegMask64;
    native_state->gpr.r9.qword = ss.__r9 & gRegMask64;
    native_state->gpr.r10.qword = ss.__r10 & gRegMask64;
    native_state->gpr.r11.qword = ss.__r11 & gRegMask64;
    native_state->gpr.r12.qword = ss.__r12 & gRegMask64;
    native_state->gpr.r13.qword = ss.__r13 & gRegMask64;
    native_state->gpr.r14.qword = ss.__r14 & gRegMask64;
    native_state->gpr.r15.qword = ss.__r15 & gRegMask64;
    native_state->rflag.flat = ss.__rflags;
#else
    const auto &mcontext = context->uc_mcontext;

    native_state->gpr.rax.qword = mcontext.gregs[REG_RAX] & gRegMask32;
    native_state->gpr.rbx.qword = mcontext.gregs[REG_RBX] & gRegMask32;
    native_state->gpr.rcx.qword = mcontext.gregs[REG_RCX] & gRegMask32;
    native_state->gpr.rdx.qword = mcontext.gregs[REG_RDX] & gRegMask32;
    native_state->gpr.rsi.qword = mcontext.gregs[REG_RSI] & gRegMask32;
    native_state->gpr.rdi.qword = mcontext.gregs[REG_RDI] & gRegMask32;
    native_state->gpr.rbp.qword = mcontext.gregs[REG_RBP] & gRegMask32;
    native_state->gpr.rsp.qword = mcontext.gregs[REG_RSP] & gRegMask32;

    native_state->gpr.r8.qword = mcontext.gregs[REG_R8] & gRegMask64;
    native_state->gpr.r9.qword = mcontext.gregs[REG_R9] & gRegMask64;
    native_state->gpr.r10.qword = mcontext.gregs[REG_R10] & gRegMask64;
    native_state->gpr.r11.qword = mcontext.gregs[REG_R11] & gRegMask64;
    native_state->gpr.r12.qword = mcontext.gregs[REG_R12] & gRegMask64;
    native_state->gpr.r13.qword = mcontext.gregs[REG_R13] & gRegMask64;
    native_state->gpr.r14.qword = mcontext.gregs[REG_R14] & gRegMask64;
    native_state->gpr.r15.qword = mcontext.gregs[REG_R15] & gRegMask64;
    native_state->rflag.flat = context->uc_mcontext.gregs[REG_EFL];
#endif  // __APPLE__

    native_state->rflag.nt = false;
    native_state->rflag.rf = false;
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

  InitFlags();

  // Populate the tests vector.
  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    gTests.push_back(&test);
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
