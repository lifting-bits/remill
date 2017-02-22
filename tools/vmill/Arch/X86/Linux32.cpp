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
#define ADDRESS_SIZE_BITS 64  // ptrace process state will be 64 bit.
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

class SysEnterSystemCall : public SystemCall32 {
 public:
  explicit SysEnterSystemCall(State *state_)
     : state(state_) {}

  virtual ~SysEnterSystemCall(void) {}

  void SetReturn(int ret_val) const override {
    state->gpr.rax.dword = static_cast<uint32_t>(ret_val);
  }

  int GetSystemCallNum(void) const override {
    return static_cast<int>(state->gpr.rax.dword);
  }

 protected:
  bool TryGetArgValue(int arg_num, size_t value_size,
                      void *value) const override {
    uint32_t arg_val = 0;
    switch (arg_num) {
      case 0:
        arg_val = state->gpr.rbx.dword;
        break;
      case 1:
        arg_val = state->gpr.rcx.dword;
        break;
      case 2:
        arg_val = state->gpr.rdx.dword;
        break;
      case 3:
        arg_val = state->gpr.rsi.dword;
        break;
      case 4:
        arg_val = state->gpr.rdi.dword;
        break;
      case 5:
        if (!Process::gCurrent->TryRead(state->gpr.rbp.dword, &arg_val)) {
          return false;
        }
        break;
      default:
        return false;
    }

    memcpy(value, &arg_val, value_size);
    return true;
  }

 private:
  SysEnterSystemCall(void) = delete;

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

  // Copy in the flags.
  state.rflag.flat = regs.eflags;
  state.aflag.pf = state.rflag.pf;
  state.aflag.af = state.rflag.af;
  state.aflag.zf = state.rflag.zf;
  state.aflag.sf = state.rflag.sf;
  state.aflag.df = state.rflag.df;
  state.aflag.of = state.rflag.of;

  // Copy in the general-purpose registers.
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

  // Copy in the segments.
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

  DLOG(INFO)
      << "Wrote " << sizeof(State) << "-byte State struct to snapshot file";

  // Pad the file out to be a multiple of the page size.
  if (0 != (sizeof(State) % 4096)) {
    auto total_size = (sizeof(State) + 4095ULL) & ~4095ULL;
    auto missing_size = total_size - sizeof(State);
    write(fd, &(gZeroData[0]), missing_size);

    DLOG(INFO)
        << "Wrote " << missing_size << " padding bytes to snapshot file.";
  }

  LOG(INFO)
      << "Copying register state" << std::endl
      << "Register state:" << std::endl
      << "  rax = " << std::hex << gpr.rax.qword << std::endl
      << "  rbx = " << std::hex << gpr.rbx.qword << std::endl
      << "  rcx = " << std::hex << gpr.rcx.qword << std::endl
      << "  rdx = " << std::hex << gpr.rdx.qword << std::endl
      << "  rsi = " << std::hex << gpr.rsi.qword << std::endl
      << "  rdi = " << std::hex << gpr.rdi.qword << std::endl
      << "  rsp = " << std::hex << gpr.rsp.qword << std::endl
      << "  rbp = " << std::hex << gpr.rbp.qword << std::endl
      << "  r8  = " << std::hex << gpr.r8.qword << std::endl
      << "  r9  = " << std::hex << gpr.r9.qword << std::endl
      << "  r10 = " << std::hex << gpr.r10.qword << std::endl
      << "  r11 = " << std::hex << gpr.r11.qword << std::endl
      << "  r12 = " << std::hex << gpr.r12.qword << std::endl
      << "  r13 = " << std::hex << gpr.r13.qword << std::endl
      << "  r14 = " << std::hex << gpr.r14.qword << std::endl
      << "  r15 = " << std::hex << gpr.r15.qword << std::endl
      << "  rip = " << std::hex << gpr.rip.qword;
}

// 32-bit x86 thread state structure.
class X86Thread32 final : public Thread32 {
 public:
  explicit X86Thread32(const Snapshot *snapshot, void *state_)
      : Thread32(snapshot->file->process_id, snapshot->file->thread_id) {
    memcpy(&state, state_, sizeof(state));
  }

  virtual ~X86Thread32(void) = default;

  uint64_t NextProgramCounter(void) const override {
    return static_cast<uint64_t>(state.gpr.rip.dword);
  }

  void *MachineState(void) override {
    return &state;
  }
 protected:
  AsyncHyperCall::Name PendingHyperCall(void) const override {
    return state.hyper_call;
  }
  int PendingInterruptVector(void) const override {
    return state.interrupt_vector;
  }

  void DoSystemCall(
      AsyncHyperCall::Name name, SystemCallHandler handler) override;
 private:
  State state;
};

namespace {

// One example of this in practice:
//  0xf7fd8be0 <+0>:    push   ecx
//  0xf7fd8be1 <+1>:    push   edx
//  0xf7fd8be2 <+2>:    push   ebp
//  0xf7fd8be3 <+3>:    mov    ebp,esp
//  0xf7fd8be5 <+5>:    sysenter
//  0xf7fd8be7 <+7>:    int    0x80
//  0xf7fd8be9 <+9>:    pop    ebp
//  0xf7fd8bea <+10>:   pop    edx
//  0xf7fd8beb <+11>:   pop    ecx
//  0xf7fd8bec <+12>:   ret

static Addr32 FindVDSO32SysEnterReturn(void) {
  auto pc = static_cast<Addr32>(Process::gCurrent->NextProgramCounter());
  auto reader = Process::gCurrent->ExecutableByteReader();
  uint8_t bytes[] = {0, 0};

  // Search forward for some NOPs. These may be used to align the `int 0x80`
  // (the restart point) to a reasonable place.
  for (Addr32 i = 0; i < 7; ++i, ++pc) {
    if (!reader(pc, &(bytes[0])) || 0x90 != bytes[0]) {
      break;
    }
  }

  // Now try to find the `int 0x80`, which is the backup/restart path.
  if (reader(pc, &(bytes[0])) && reader(pc + 1, &(bytes[1]))) {
    if (0xcd == bytes[0] && 0x80 == bytes[1]) {
      return pc + 2;
    }
  }

  return pc;
}

}  // namespace

void X86Thread32::DoSystemCall(AsyncHyperCall::Name name,
                               SystemCallHandler handler) {
  auto pc = NextProgramCounter();

  if (AsyncHyperCall::kX86IntN == name && 0x80 == state.interrupt_vector) {
    Int0x80SystemCall abi(&state);
    handler(abi);

  } else if (AsyncHyperCall::kX86SysEnter == name) {
    SysEnterSystemCall abi(&state);
    handler(abi);
    state.gpr.rip.dword = FindVDSO32SysEnterReturn();

  } else {
    LOG(FATAL)
        << "Unable to handle system call at " << std::hex << pc;
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
