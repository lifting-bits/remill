/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <asm/ldt.h>
#include <cerrno>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "tools/vmill/Arch/X86/Linux32.h"
#include "tools/vmill/OS/Linux32/System.h"
#include "tools/vmill/Snapshot/File.h"
#include "tools/vmill/Snapshot/Snapshot.h"

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 1
#define ADDRESS_SIZE_BITS 64
#include "remill/Arch/X86/Runtime/State.h"

namespace remill {
namespace vmill {
namespace x86 {
namespace {

static const uint8_t gZeroData[4096] = {};

class Int0x80SystemCall : public SystemCall32 {
 public:
  explicit Int0x80SystemCall(State *state_)
     : state(state_) {}


  virtual ~Int0x80SystemCall(void) {}

  void SetReturn(int ret_val) const override {
    state->gpr.rax.dword = static_cast<uint32_t>(ret_val);
  }

  int GetSystemCallNum(void) const override {
    return static_cast<int>(state->gpr.rax.dword);
  }

 protected:
  bool TryGetArgValue(int arg_num, size_t value_size,
                      void *value) const override {
    memset(value, 0, value_size);
    switch (arg_num) {
      case 0:
        memcpy(value, &(state->gpr.rbx.dword), 4);
        return true;
      case 1:
        memcpy(value, &(state->gpr.rcx.dword), 4);
        return true;
      case 2:
        memcpy(value, &(state->gpr.rdx.dword), 4);
        return true;
      case 3:
        memcpy(value, &(state->gpr.rsi.dword), 4);
        return true;
      case 4:
        memcpy(value, &(state->gpr.rdi.dword), 4);
        return true;
      case 5:
        memcpy(value, &(state->gpr.rbp.dword), 4);
        return true;
      default:
        return false;
    }
  }

 private:
  Int0x80SystemCall(void) = delete;

  State *state;
};

}  // namespace

// Returns the size of the `State` structure for all X86 variants. This is
// actually the same across the board, but we always treat it as if the
// `State` structure is for a 64-bit application.
//
// Note: This is rounded up to a multiple of 4096.
uint64_t StateSize(void) {
  return (sizeof(State) + 4095ULL) & ~4095ULL;
}

// Copy the register state from the tracee with PID `pid` into the file
// with FD `fd`.
void CopyTraceeState(pid_t pid, int fd) {
  State state = {};
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  auto &gpr = state.gpr;
  gpr.rax.qword = regs.rax;
  gpr.rbx.qword = regs.rbx;
  gpr.rcx.qword = regs.rcx;
  gpr.rdx.qword = regs.rdx;
  gpr.rsi.qword = regs.rsi;
  gpr.rdi.qword = regs.rdi;
  gpr.rsp.qword = regs.rsp;
  gpr.rbp.qword = regs.rbp;
  gpr.r8.qword = regs.r8;
  gpr.r9.qword = regs.r9;
  gpr.r10.qword = regs.r10;
  gpr.r11.qword = regs.r11;
  gpr.r12.qword = regs.r12;
  gpr.r13.qword = regs.r13;
  gpr.r14.qword = regs.r14;
  gpr.r15.qword = regs.r15;
  gpr.rip.qword = regs.rip - 1;  // Subtract off size of `int3`.

  auto &seg = state.seg;
  seg.cs = regs.cs;
  seg.ds = regs.ds;
  seg.fs = regs.fs;
  seg.gs = regs.gs;
  seg.es = regs.es;
  seg.ss = regs.ss;

  auto &addr = state.addr;
  addr.fs_base.qword = regs.fs_base;
  addr.gs_base.qword = regs.gs_base;

  // 32-bit Linux programs use `GS` to index into their TLS, and on a 64-bit
  // host, the TLS entry is 12 in the GDT [1].
  //
  // [1] http://lxr.free-electrons.com/source/arch/x86/um/os-Linux/tls.c#L18
  errno = 0;
  struct user_desc area = {};
  ptrace(static_cast<enum __ptrace_request>(25 /* PTRACE_GET_THREAD_AREA */),
         pid, 12, &area);
  if (!errno) {
    addr.gs_base.dword = area.base_addr;
  }

  static_assert(sizeof(struct user_fpregs_struct) == sizeof(FPU),
                "Remill X86 FPU state structure doesn't match the OS.");

  FPU fpregs;  // Our FPU structure is better organized ;-)
  ptrace(PTRACE_GETFPREGS, pid, NULL, &fpregs);
  auto &st = state.st;
  auto &mmx = state.mmx;

  // Opportunistic copying of MMX regs.
  for (size_t i = 0; i < 8; ++i) {
    if (static_cast<uint16_t>(0xFFFFU) == fpregs.st[i].infinity) {
      mmx.elems[i].val.qwords.elems[0] = fpregs.st[i].mmx;
    }
  }

  // Opportunistic copying of ST(i) regs.
  for (size_t i = 0; i < 8; ++i) {
    auto entry = *reinterpret_cast<long double *>(&(fpregs.st[i].st));
    st.elems[i].val = static_cast<float64_t>(entry);
  }

  write(fd, &state, sizeof(State));

  LOG(INFO)
      << "Wrote " << sizeof(State) << "-byte State struct to snapshot file";

  // Pad the file out to be a multiple of the page size.
  if (0 != (sizeof(State) % 4096)) {
    auto total_size = (sizeof(State) + 4095ULL) & ~4095ULL;
    auto missing_size = total_size - sizeof(State);
    write(fd, &(gZeroData[0]), missing_size);

    LOG(INFO)
        << "Write " << missing_size << " padding bytes to snapshot file.";
  }
}

// 32-bit x86 thread state structure.
class X86Thread32 final : public Thread32 {
 public:
  explicit X86Thread32(const Snapshot *snapshot, void *state_)
      : Thread32(snapshot->file->process_id, snapshot->file->thread_id) {
    memcpy(&state, state_, sizeof(state));
  }

  virtual ~X86Thread32(void) = default;

  uint64_t ProgramCounter(void) const override {
    return static_cast<uint64_t>(state.gpr.rip.dword);
  }

  void *MachineState(void) override {
    return &state;
  }
 protected:
  AsyncHyperCall::Name GetHyperCall(void) const override {
    return state.hyper_call;
  }
  int GetInterruptVector(void) const override {
    return state.interrupt_vector;
  }

  void DoSystemCall(
      AsyncHyperCall::Name name, SystemCallHandler handler) override;
 private:
  State state;
};

void X86Thread32::DoSystemCall(AsyncHyperCall::Name name,
                               SystemCallHandler handler) {

  if (AsyncHyperCall::kX86SysEnter == name) {
    // TODO(pag): Suppress `sysenter` in the hopes that there is an
    //            `int 0x80` following it.

  } else if (AsyncHyperCall::kX86IntN == name &&
             0x80 == state.interrupt_vector) {
    Int0x80SystemCall abi(&state);
    handler(abi);

  } else {
    LOG(FATAL)
        << "Unable to handle system call type.";
  }
}

Thread32 *CreateThread32(const Snapshot *snapshot) {
  auto state_mmap = mmap(nullptr, StateSize(), PROT_READ,
                         MAP_PRIVATE | MAP_FILE, snapshot->fd,
                         sizeof(SnapshotFile));
  CHECK(MAP_FAILED != state_mmap)
      << "Could not mmap 32-bit X86 State structure from snapshot "
      << snapshot->path << ": " << strerror(errno);

  auto thread = new X86Thread32(snapshot, state_mmap);
  munmap(state_mmap, StateSize());
  return thread;
}

}  // namespace x86
}  // namespace vmill
}  // namespace remill
