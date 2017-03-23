/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "pin.H"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "tools/vmill/Snapshot/File.h"

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 32
#include "remill/Arch/X86/Runtime/State.h"

KNOB<unsigned> gBreakpoint(
    KNOB_MODE_WRITEONCE, "pintool", "breakpoint", "0",
    "Starting instrumentation address");

KNOB<std::string> gWorkspace(
    KNOB_MODE_WRITEONCE, "pintool", "workspace", ".",
    "Directory of the workspace.");

KNOB<std::string> gTraceFile(
    KNOB_MODE_WRITEONCE, "pintool", "trace_file", "",
    "Output file for the program counter trace.");

enum {
  kAlignedStateSize = (sizeof(State) + 4095UL) & ~4095UL
};

static std::string gSnapshotPath;

static std::ofstream gTraceFileStream;

static remill::vmill::SnapshotFile gFileInfo = {};
static State gState = {};
static uint8_t gZeroData[kAlignedStateSize] = {};

static uint64_t gStackBase = 0;
static uint64_t gStackLimit = 0;

// Parse a line from `/proc/<pid>/maps` and fill in a `PageInfo` structure.
static bool ReadPageInfoLine(const std::string &line,
                             remill::vmill::PageInfo *info) {
  auto cline = line.c_str();
  uint64_t begin = 0;
  uint64_t end = 0;
  char r = '-';
  char w = '-';
  char x = '-';
  char p = '-';

  if (6 != sscanf(cline, "%llx-%llx %c%c%c%c", &begin, &end, &r, &w, &x, &p)) {
    return false;
  }

  std::cerr
      << "Page info: " << line << std::endl;

  info->base_address = begin;
  info->limit_address = end;

  auto is_r = 'r' == r;
  auto is_w = 'w' == w;
  auto is_x = 'x' == x;

  if (is_r && is_w && is_x) {
    info->perms = remill::vmill::PagePerms::kReadWriteExec;

  } else if (is_r && is_w && !is_x) {
    info->perms = remill::vmill::PagePerms::kReadWrite;

  } else if (is_r && !is_w && is_x) {
    info->perms = remill::vmill::PagePerms::kReadExec;

  } else if (is_r && !is_w && !is_x) {
    info->perms = remill::vmill::PagePerms::kReadOnly;

  } else if (!is_r && is_w && !is_x) {
    info->perms = remill::vmill::PagePerms::kWriteOnly;

  // TODO(pag): These actually come up quite a bit, and it may be important
  //            to include them in the future so that they are not permitted
  //            to be allocated by `mmap`s.
  } else {
    std::cerr << "Unrecognized page permissions!" << std::endl;
    return false;
  }

  if (strstr(cline, "[stack]")) {
    if (gStackBase) {
      std::cerr
          << "Cannot snapshot a program with more than one stack." << std::endl;
      PIN_ExitProcess(-1);
    }

    gStackBase = info->base_address;
    gStackLimit = info->limit_address;

    struct rlimit limit;
    getrlimit(RLIMIT_STACK, &limit);
    std::cerr
        << "Current stack size limit is " << limit.rlim_cur << std::endl;

    std::cerr
        << "Absolute maximum stack size is " << limit.rlim_max << std::endl;

    limit.rlim_max = std::min<rlim_t>(limit.rlim_cur, 16UL << 20UL);
    limit.rlim_max = std::max<rlim_t>(
        limit.rlim_cur, info->limit_address - info->base_address);

    std::cerr
        << "New stack size is " << limit.rlim_max << std::endl;
    info->base_address = info->limit_address - limit.rlim_max;
  }

  return true;
}

// Get the size of the snapshot header, include the architecture-specific
// state structure.
static uint64_t HeaderSize(void) {
  return sizeof(remill::vmill::SnapshotFile) + kAlignedStateSize;
}

// Read out the ranges of mapped pages.
static void ReadTraceePageMaps(pid_t pid) {
  std::stringstream ss;
  ss << "/proc/" << pid << "/maps";

  std::ifstream maps_file(ss.str().c_str());
  std::string line;
  auto i = 0;
  auto file_size = HeaderSize();
  while (std::getline(maps_file, line)) {
    if (i >= remill::vmill::SnapshotFile::kMaxNumPageInfos) {
      std::cerr << "Too many pages ranges in memory map!" << std::endl;
    }

    auto &page_info = gFileInfo.pages[i];
    if (ReadPageInfoLine(line, &page_info)) {
      page_info.offset_in_file = file_size;
      file_size += (page_info.limit_address - page_info.base_address);
      i += 1;
    }
  }
}

// Copy memory from the tracee into the snapshot file.
static void CopyTraceeMemory(pid_t pid, int snapshot_fd) {
  std::cerr
      << "Copying tracee memory into " << gSnapshotPath << std::endl;

  // Figure out how much memory we want to snapshot.
  uint64_t memory_size = 0;
  for (const auto &info : gFileInfo.pages) {
    memory_size += (info.limit_address - info.base_address);
  }

  // Resize file to fit all memory to be snapshotted.
  auto file_size = gFileInfo.pages[0].offset_in_file + memory_size;
  if (syscall(SYS_ftruncate, snapshot_fd, file_size)) {
    std::cerr
        << "Unable to resize snapshot file " << gSnapshotPath
        << " to contain the memory to be snapshotted.";
    PIN_ExitProcess(-1);
  }

  // Map the snapshot file into memory, so we can directly read the tracee's
  // memory into the snapshot file.
  auto base_offset = gFileInfo.pages[0].offset_in_file;
  auto data = mmap(nullptr, memory_size, PROT_WRITE,
                   MAP_SHARED | MAP_FILE, snapshot_fd,
                   base_offset);
  if (MAP_FAILED == data) {
    std::cerr
        << "Unable to map the memory of " << gSnapshotPath
        << ": " << strerror(errno) << std::endl;
    PIN_ExitProcess(-1);
  }

  for (const auto &info : gFileInfo.pages) {
    if (remill::vmill::PagePerms::kInvalid == info.perms) {
      break;
    }

    // Adjust when we are copying data from the stack, and the maximum possible
    // stack size does not match the mapped stack size.
    auto base_addr = info.base_address;
    auto offset = 0ULL;
    if (gStackLimit == info.limit_address && gStackBase != info.base_address) {
      offset = gStackBase - info.base_address;
      base_addr = gStackBase;
    }

    auto dest = reinterpret_cast<void *>(
        reinterpret_cast<uintptr_t>(data) + info.offset_in_file +
        offset - base_offset);
    auto size_to_copy = info.limit_address - base_addr;

    std::cerr
        << "Copying " << size_to_copy << " bytes from the tracee's memory from "
        << std::hex << base_addr << " to " << std::hex << info.limit_address
        << " into the snapshot file." << std::endl;

    auto copied_size = PIN_SafeCopy(
        dest, reinterpret_cast<void *>(base_addr), size_to_copy);

    if (copied_size != size_to_copy) {
      std::cerr
          << "Error copying bytes from " << std::hex
          << (base_addr + copied_size) << std::endl;
    }
  }

  munmap(data, memory_size);
}

static void CopyTraceeState(CONTEXT *ctx, int fd) {
  gState.rflag.flat = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EFLAGS);

  auto &aflag = gState.aflag;
  aflag.cf = gState.rflag.cf;
  aflag.pf = gState.rflag.pf;
  aflag.af = gState.rflag.af;
  aflag.zf = gState.rflag.zf;
  aflag.sf = gState.rflag.sf;
  aflag.of = gState.rflag.of;
  aflag.df = gState.rflag.df;

  auto &gpr = gState.gpr;
  gpr.rax.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
  gpr.rbx.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
  gpr.rcx.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX);
  gpr.rdx.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX);
  gpr.rsi.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);
  gpr.rdi.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
  gpr.rsp.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESP);
  gpr.rbp.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBP);
  gpr.rip.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EIP);

  auto &seg = gState.seg;
  seg.cs = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_CS);
  seg.ds = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_DS);
  seg.fs = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_FS);
  seg.gs = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_GS);
  seg.es = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_ES);
  seg.ss = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_SS);

  auto &addr = gState.addr;
  addr.fs_base.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_FS_BASE);
  addr.gs_base.dword = PIN_GetContextReg(ctx, LEVEL_BASE::REG_SEG_GS_BASE);

  // TODO(pag): ST, MMX, XMM.

  write(fd, &gState, sizeof(State));

  std::cerr
      << "Wrote " << sizeof(State) << "-byte State struct to snapshot file"
      << std::endl;

  // Pad the file out to be a multiple of the page size.
  if (0 != (sizeof(State) % 4096)) {
    auto missing_size = kAlignedStateSize - sizeof(State);
    write(fd, &(gZeroData[0]), missing_size);
    std::cerr
        << "Wrote " << missing_size << " padding bytes to snapshot file."
        << std::endl;
  }

  std::cerr
      << "Copying register state" << std::endl
      << "Register state:" << std::endl
      << "  eax = " << std::hex << gpr.rax.dword << std::endl
      << "  ebx = " << std::hex << gpr.rbx.dword << std::endl
      << "  ecx = " << std::hex << gpr.rcx.dword << std::endl
      << "  edx = " << std::hex << gpr.rdx.dword << std::endl
      << "  esi = " << std::hex << gpr.rsi.dword << std::endl
      << "  edi = " << std::hex << gpr.rdi.dword << std::endl
      << "  esp = " << std::hex << gpr.rsp.dword << std::endl
      << "  ebp = " << std::hex << gpr.rbp.dword << std::endl
      << "  eip = " << std::hex << gpr.rip.dword  << std::endl;
}

// Create a snapshot file of the tracee.
static void SnapshotTracee(pid_t pid, CONTEXT *ctx) {
  auto fd = open(
      gSnapshotPath.c_str(), O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
      0666);

  if (-1 == fd) {
    std::cerr
        << "Unable to create snapshot file " << gSnapshotPath
        << ": " << strerror(errno) << std::endl;
    PIN_ExitProcess(-1);
  }

  ReadTraceePageMaps(pid);

  std::cerr
      << "Writing memory map info into " << gSnapshotPath << std::endl;

  gFileInfo.arch_name = remill::kArchX86;
  gFileInfo.os_name = remill::kOSLinux;

  write(fd, &gFileInfo, sizeof(gFileInfo));
  CopyTraceeMemory(pid, fd);
  CopyTraceeState(ctx, fd);
  close(fd);
}

VOID TakeSnapshot(CONTEXT *ctx) {
  static bool gSnapshotted = false;
  if (gSnapshotted) {
    return;
  }

  if (gBreakpoint.Value() &&
      PIN_GetContextReg(ctx, LEVEL_BASE::REG_EIP) != gBreakpoint.Value()) {
    return;
  }

  gSnapshotted = true;
  SnapshotTracee(PIN_GetPid(), ctx);
}

struct RegInfo final {
  const char *name;
  LEVEL_BASE::REG reg;
};

static const struct RegInfo gGprs[] = {
  {"eip", LEVEL_BASE::REG_EIP},
  {"eax", LEVEL_BASE::REG_EAX},
  {"ebx", LEVEL_BASE::REG_EBX},
  {"ecx", LEVEL_BASE::REG_ECX},
  {"edx", LEVEL_BASE::REG_EDX},
  {"esi", LEVEL_BASE::REG_ESI},
  {"edi", LEVEL_BASE::REG_EDI},
  {"ebp", LEVEL_BASE::REG_EBP},
  {"esp", LEVEL_BASE::REG_ESP},
};

VOID PrintContext(CONTEXT *ctx) {
  static bool gPrinting = false;
  if (!gPrinting &&
      PIN_GetContextReg(ctx, LEVEL_BASE::REG_EIP) == gBreakpoint.Value()) {
    gPrinting = true;
  }

  if (!gPrinting) {
    return;
  }

  const char *sep = "";
  for (auto &gpr : gGprs) {
    gTraceFileStream
        << sep << gpr.name << "=" << std::hex
        << PIN_GetContextReg(ctx, gpr.reg);
    sep = " ";
  }
  gTraceFileStream << std::endl;

  Flags flags;
  flags.flat = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EFLAGS);

  gTraceFileStream
      << "cf=" << flags.cf << " "
      << "pf=" << flags.pf << " "
      << "af=" << flags.af << " "
      << "zf=" << flags.zf << " "
      << "sf=" << flags.sf << " "
      << "df=" << flags.df << " "
      << "of=" << flags.of
      << std::endl << std::endl;
}

VOID InstrumentInstruction(INS ins, VOID *) {
  INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)TakeSnapshot, IARG_CONTEXT, IARG_END);
  INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)PrintContext, IARG_CONTEXT, IARG_END);
}

int main(int argc, char *argv[]) {
  PIN_Init(argc, argv);

  gSnapshotPath = gWorkspace.Value() + "/snapshot";
  gTraceFileStream.open(
      gTraceFile.Value().c_str(), std::ios_base::out | std::ios_base::trunc);

  INS_AddInstrumentFunction(InstrumentInstruction, nullptr);
  PIN_StartProgram();
  return 0;
}
