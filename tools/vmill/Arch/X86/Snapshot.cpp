/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <asm/ldt.h>
#include <cerrno>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>

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

}  // namespace

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

  lseek(fd, 0, SEEK_END);
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

  DLOG(INFO)
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

}  // namespace x86
}  // namespace vmill
}  // namespace remill
