/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>
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

#include "mcsema/Arch/X86/Runtime/State.h"

namespace {

typedef void (*LiftedFunc)(State *);

struct alignas(128) Stack {
  uint8_t bytes[SIGSTKSZ];
};

// Native test case code executes off of `gStack`. The state of the stack
// after executing this code is saved in `gBackupStack`. Lifted test case
// code executes off of the normal runtime stack, but emulates operations
// that act on `gStack`.
static Stack gLiftedStack;
static Stack gNativeStack;
static Stack gSigStack;

static Flags gRflagsOff;
static Flags gRflagsOn;

static const auto gStackBase = reinterpret_cast<uintptr_t>(&gLiftedStack);
static const auto gStackLimit = gStackBase + sizeof(Stack);

template <typename T>
inline static T &AccessMemory(addr_t addr) {
  EXPECT_TRUE(addr > gStackBase && addr < gStackLimit);
  return *reinterpret_cast<T *>(static_cast<uintptr_t>(addr));
}

// Used to handle exceptions in instructions.
static sigjmp_buf gJmpBuf;

// Used to mask the registers from a signal context when we've caught an error.
static uintptr_t gRegMask32 = 0;
static uintptr_t gRegMask64 = 0;

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
addr_t __mcsema_compute_address(const State &state, addr_t addr,
                                int address_space) {
  (void) state;
  (void) address_space;
  return addr;
}

// Memory read intrinsics.
uint8_t __mcsema_read_memory_8(addr_t addr) {
  return AccessMemory<uint8_t>(addr);
}

uint16_t __mcsema_read_memory_16(addr_t addr) {
  return AccessMemory<uint16_t>(addr);
}

uint32_t __mcsema_read_memory_32(addr_t addr) {
  return AccessMemory<uint32_t>(addr);
}

uint64_t __mcsema_read_memory_64(addr_t addr) {
  return AccessMemory<uint64_t>(addr);
}

void __mcsema_read_memory_v64(addr_t addr, vec64_t &out) {
  out = AccessMemory<vec64_t>(addr);
}

void __mcsema_read_memory_v128(addr_t addr, vec128_t &out) {
  out = AccessMemory<vec128_t>(addr);
}
void __mcsema_read_memory_v256(addr_t addr, vec256_t &out) {
  out = AccessMemory<vec256_t>(addr);
}

void __mcsema_read_memory_v512(addr_t addr, vec512_t &out) {
  out = AccessMemory<vec512_t>(addr);
}

// Memory write intrinsics.
void __mcsema_write_memory_8(addr_t addr, uint8_t in) {
  AccessMemory<uint8_t>(addr) = in;
}

void __mcsema_write_memory_16(addr_t addr, uint16_t in) {
  AccessMemory<uint16_t>(addr) = in;
}

void __mcsema_write_memory_32(addr_t addr, uint32_t in) {
  AccessMemory<uint32_t>(addr) = in;
}

void __mcsema_write_memory_64(addr_t addr, uint64_t in) {
  AccessMemory<uint64_t>(addr) = in;
}

void __mcsema_write_memory_v64(addr_t addr, const vec64_t &in) {
  AccessMemory<vec64_t>(addr) = in;
}

void __mcsema_write_memory_v128(addr_t addr, const vec128_t &in) {
  AccessMemory<vec128_t>(addr) = in;
}

void __mcsema_write_memory_v256(addr_t addr, const vec256_t &in) {
  AccessMemory<vec256_t>(addr) = in;
}

void __mcsema_write_memory_v512(addr_t addr, const vec512_t &in) {
  AccessMemory<vec512_t>(addr) = in;
}

void __mcsema_barrier_load_load(addr_t, size_t) {}
void __mcsema_barrier_load_store(addr_t, size_t) {}
void __mcsema_barrier_store_load(addr_t, size_t) {}
void __mcsema_barrier_store_store(addr_t, size_t) {}
void __mcsema_barrier_atomic_begin(addr_t, size_t) {}
void __mcsema_barrier_atomic_end(addr_t, size_t) {}

void __mcsema_defer_inlining(void) {}

void __mcsema_error(State &) {
  std::cerr << "Caught error!" << std::endl;
  siglongjmp(gJmpBuf, 0);
}

// Control-flow intrinsics.
void __mcsema_undefined_block(State &) {
  // This is where we want to end up.
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

static void InitFlags(void) {
  asm("pushfq; pushfq; pop %0; pop %1;" : : "m"(gRflagsOn), "m"(gRflagsOff));
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

  // Set up the GPR mask just in case an error occurs when we execute this
  // instruction.
  if (64 == ADDRESS_SIZE_BITS) {
    gRegMask32 = std::numeric_limits<uint64_t>::max();
    gRegMask64 = gRegMask32;
  } else {
    gRegMask32 = std::numeric_limits<uint32_t>::max();
    gRegMask64 = 0;
  }

  memset(&gLiftedStack, 0, sizeof(gLiftedStack));
  memset(&gLiftedState, 0, sizeof(gLiftedState));
  memset(&gNativeState, 0, sizeof(gNativeState));

  auto lifted_state = reinterpret_cast<State *>(&gLiftedState);
  auto native_state = reinterpret_cast<State *>(&gNativeState);

  // This will be used to initialize the native flags state before executing
  // the native test.
  lifted_state->rflag = flags;

  // This will execute on `gStack`. The mechanism behind this is that the
  // stack pointer is swapped with `gStackSwitcher`. The idea here is that
  // we want to run the native and lifted testcases on the same stack so that
  // we can compare that they both operate on the stack in the same ways.
  auto native_test_faulted = false;
  if (!sigsetjmp(gJmpBuf, true)) {
    gTestToRun = info->test_begin;
    InvokeTestCase(arg1, arg2, arg3);
  } else {
    native_test_faulted = true;
  }

  // Copy out whatever was recorded on the stack so that we can compare it
  // with how the lifted program mutates the stack.
  memcpy(&gNativeStack, &gLiftedStack, sizeof(gLiftedStack));
  memset(&gLiftedStack, 0, sizeof(gLiftedStack));

  // This will execute on our stack but the lifted code will operate on
  // `gStack`. The mechanism behind this is that `gStateBefore` is the native
  // program state recorded before executing the native testcase, but after
  // swapping execution to operate on `gStack`.
  if (!sigsetjmp(gJmpBuf, true)) {
    info->lifted_func(lifted_state);
  } else {
    EXPECT_TRUE(native_test_faulted);
  }

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

  std::cerr << "Testing instruction: " << info->test_name << ": " << desc;
  if (test::kFeatureMMX & info->features) std::cerr << ", MMX";
  if (test::kFeatureSSE & info->features) std::cerr << ", SSE";
  if (test::kFeatureAVX & info->features) std::cerr << ", AVX";
  if (test::kFeatureAVX512 & info->features) std::cerr << ", AVX512";
  if (test::kFeature64BitOnly & info->features) std::cerr << ", 64-bit only";
  if (test::kFeature32BitOnly & info->features) std::cerr << ", 32-bit only";
  if (!((test::kFeature32BitOnly | test::kFeature64BitOnly) & info->features)) {
    std::cerr << " 32-bit (64-bit compat)";
  }
  std::cerr << std::endl;

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
static void RecoverFromError(int signum, siginfo_t *, void *context_) {
  std::cerr << "Caught signal " << signum << "!" << std::endl;
  memcpy(&gNativeState, &gLiftedState, sizeof(State));

  auto context = reinterpret_cast<ucontext_t *>(context_);
  auto native_state = reinterpret_cast<State *>(&gNativeState);
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
  native_state->rflag.rf = false;  // Resume flag.

  siglongjmp(gJmpBuf, 0);
}

extern "C" void sys_sigreturn();
typedef void (SignalHandler) (int, siginfo_t *, void *);
static void HandleSignal(int signum, SignalHandler *handler) {
  struct sigaction sig;
  sig.sa_sigaction = handler;
  sig.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sig.sa_restorer = sys_sigreturn;
  sigfillset(&(sig.sa_mask));
  sigaction(signum, &sig, nullptr);
}

// Set up various signal handlers.
static void SetupSignals(void) {
  HandleSignal(SIGSEGV, RecoverFromError);
  HandleSignal(SIGBUS, RecoverFromError);
  HandleSignal(SIGFPE, RecoverFromError);
  HandleSignal(SIGSTKFLT, RecoverFromError);
  HandleSignal(SIGTRAP, RecoverFromError);
  HandleSignal(SIGILL, RecoverFromError);

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

  testing::InitGoogleTest(&argc, argv);

  SetupSignals();
  return RUN_ALL_TESTS();
}
