/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstring>
#include <fcntl.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include "tools/CGC/Snapshot.h"
#include "tools/CGC/Process.h"

DECLARE_string(snapshot_dir);

namespace granary {

enum : uintptr_t {
  kPageSize = 4096,
  k1GiB = 1ULL << 30ULL,
  kProcessSize = k1GiB * 4ULL,
  k1MiB = 1048576,
  kStackSize = 8 * k1MiB,
  kStackLimitPage = 0xbaaaa000U,
  kStackEnd = kStackLimitPage + kPageSize,
  kStackBegin = kStackEnd - kStackSize,
  kMaxAddress = 0xB8000000U,
  kReserveNumRanges = 32UL,
  kMagicPageBegin = 0x4347c000U,
  kMagicPageEnd = kMagicPageBegin + kPageSize,
  kTaskSize = 0xFFFFe000U
};

// A range of mapped memory.
struct MappedRange32 final {
 public:
  inline size_t Size(void) const {
    return end - begin;
  }

  off_t fd_offs;
  uint32_t begin;
  uint32_t end;
  bool is_r;
  bool is_w;
  bool is_x;
};

// On-disk layout of a snapshot file.
struct alignas(kPageSize) Snapshot32File final {
 public:
  struct Meta {
    struct {
      char magic[4];
      int exe_num;
    } __attribute__((packed));
    struct user_regs_struct gregs;
    struct user_fpregs_struct fpregs;
  };

  Meta meta;

  enum {
    kNumPages = 4,
    kNumBytes = kNumPages * kPageSize,

    kMaxNumMappedRanges = (kNumBytes - sizeof(Meta)) / sizeof(MappedRange32)
  };

  MappedRange32 ranges[kMaxNumMappedRanges];
};

static_assert(
    sizeof(FPU) == sizeof(struct user_fpregs_struct),
    "Invalid structure packing of `FPU` or `struct user_fpregs_struct`.");

}  // namespace granary
namespace cgc {

void LoadMemoryFromSnapshot(Process *process, int pid) {
  using namespace granary;

  auto base = mmap64(
      nullptr,
      kProcessSize,
      PROT_NONE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
      -1,
      0);

  process->base = reinterpret_cast<uintptr_t>(base);
  process->limit = process->base + kProcessSize;

  const char *begin = "";
  if ('/' != FLAGS_snapshot_dir[0]) {
    begin = ".";
  }

  std::stringstream file_name;
  file_name << FLAGS_snapshot_dir << begin
            << "/grr.snapshot." << pid << ".persist";

  // Open the snapshot file.
  auto fd = open(file_name.str().c_str(), O_RDONLY | O_LARGEFILE);
  LOG_IF(FATAL, -1 == fd)
    << "Unable to open snapshot file: " << file_name.str();

  auto file = reinterpret_cast<Snapshot32File *>(
      mmap64(nullptr, sizeof(Snapshot32File),
             PROT_READ, MAP_POPULATE | MAP_PRIVATE, fd, 0));

  // Map each page range into the process memory.
  for (const auto &range : file->ranges) {
    auto range_base = reinterpret_cast<void *>(process->base + range.begin);
    mmap64(
        range_base,
        range.end - range.begin,
        (range.is_w ? PROT_READ | PROT_WRITE : PROT_READ),
        MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE,
        fd,
        range.fd_offs);
  }

  // Initialize the XMM registers.
  memcpy(&(process->state->fpu), &(file->meta.fpregs), sizeof(FPU));
  for (auto i = 0; i < 16; ++i) {
    process->state->vec[i].xmm = process->state->fpu.xmm[i];
  }

  // Initialize the flags.
  process->state->rflag.flat = file->meta.gregs.eflags;
  process->state->aflag.af = process->state->rflag.af;
  process->state->aflag.cf = process->state->rflag.cf;
  process->state->aflag.df = process->state->rflag.df;
  process->state->aflag.of = process->state->rflag.of;
  process->state->aflag.pf = process->state->rflag.pf;
  process->state->aflag.sf = process->state->rflag.sf;
  process->state->aflag.zf = process->state->rflag.zf;

  // Initialize the registers.
  process->state->gpr.rax.qword = file->meta.gregs.rax;
  process->state->gpr.rbx.qword = file->meta.gregs.rbx;
  process->state->gpr.rcx.qword = file->meta.gregs.rcx;
  process->state->gpr.rdi.qword = file->meta.gregs.rdi;
  process->state->gpr.rdx.qword = file->meta.gregs.rdx;
  process->state->gpr.rip.qword = file->meta.gregs.rip;
  process->state->gpr.rsi.qword = file->meta.gregs.rsi;
  process->state->gpr.rsp.qword = file->meta.gregs.rsp;
}

}  // namespace cgc
