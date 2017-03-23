/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif  // _GNU_SOURCE

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <linux/futex.h>
#include <linux/net.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace {

enum : size_t {
  kIOBufferSize = 4096UL,
  kOldOldUTSNameLen = 8UL,
  kOldUTSNameLen = 64UL,
  kNewUTSNameLen = 64UL
};

// Intermediate buffer for copying data to/from the runtime memory and the
// emulated process memory.
static uint8_t gIOBuffer[kIOBufferSize] = {};

// Intermediate buffer for holding file system paths, used in various syscalls.
static char gPath[PATH_MAX + 1] = {};

// Intermediate buffer for holding host names.
static char gHostName[HOST_NAME_MAX + 1] = {};

struct linux32_iovec {
  addr32_t iov_base;
  uint32_t iov_len;
};

struct linux32_msghdr {
  addr32_t msg_name;  // `void *`.
  uint32_t msg_namelen;
  addr32_t msg_iov;  // `struct linux32_iovec *`.
  uint32_t msg_iovlen;
  addr32_t msg_control;  // `void *`.
  uint32_t msg_controllen;
  int32_t msg_flags;
};

struct linux32_mmsghdr {
  linux32_msghdr msg_hdr;
  uint32_t msg_len;
};

struct linux32_cmsghdr {
  uint32_t cmsg_len;
  int32_t cmsg_level;
  int32_t cmsg_type;
};

struct linux64_msghdr {
  addr64_t msg_name;  // `void *`.
  uint32_t msg_namelen;
  addr64_t msg_iov;
  uint64_t msg_iovlen;
  addr64_t msg_control;
  uint64_t msg_controllen;
  int32_t msg_flags;
};

struct linux64_mmsghdr {
  linux64_msghdr msg_hdr;
  uint32_t msg_len;
};

struct linux64_cmsghdr {
  uint64_t cmsg_len;
  int32_t cmsg_level;
  int32_t cmsg_type;
};

struct linux32_timespec {
  uint32_t tv_sec;
  uint32_t tv_nsec;
};

struct linux32_timeval {
  uint32_t tv_sec;
  uint32_t tv_usec;
};

struct linux32_timezone {
  int32_t tz_minuteswest;
  int32_t tz_dsttime;
};

struct linux32_stat {
  uint64_t st_dev;
  uint16_t __pad1;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint16_t __pad2;
  int64_t st_size;
  int32_t st_blksize;
  int64_t st_blocks;
  struct linux32_timespec st_atim;
  struct linux32_timespec st_mtim;
  struct linux32_timespec st_ctim;
  uint64_t st_ino;
} __attribute__((packed));

static_assert(sizeof(linux32_stat) == 88,
              "Invalid packing of `struct linux32_stat`.");

struct linux32_stat64 {
  uint64_t st_dev;
  uint32_t __pad1;
  uint32_t __st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint32_t __pad2;
  int64_t st_size;
  int32_t st_blksize;
  int64_t st_blocks;
  struct linux32_timespec st_atim;
  struct linux32_timespec st_mtim;
  struct linux32_timespec st_ctim;
  uint64_t st_ino;
} __attribute__((packed));

static_assert(sizeof(linux32_stat64) == 96,
              "Invalid packing of `struct linux32_stat64`.");

struct linux_oldold_utsname {
  char sysname[kOldOldUTSNameLen + 1];
  char nodename[kOldOldUTSNameLen + 1];
  char release[kOldOldUTSNameLen + 1];
  char version[kOldOldUTSNameLen + 1];
  char machine[kOldOldUTSNameLen + 1];
};

struct linux_old_utsname {
  char sysname[kOldUTSNameLen + 1];
  char nodename[kOldUTSNameLen + 1];
  char release[kOldUTSNameLen + 1];
  char version[kOldUTSNameLen + 1];
  char machine[kOldUTSNameLen + 1];
};

struct linux_new_utsname {
  char sysname[kNewUTSNameLen + 1];
  char nodename[kNewUTSNameLen + 1];
  char release[kNewUTSNameLen + 1];
  char version[kNewUTSNameLen + 1];
  char machine[kNewUTSNameLen + 1];
  char domainname[kNewUTSNameLen + 1];
};

}  // namespace

#include "tools/vmill/Runtime/Linux/Clock.cpp"
#include "tools/vmill/Runtime/Linux/FS.cpp"
#include "tools/vmill/Runtime/Linux/Futex.cpp"
#include "tools/vmill/Runtime/Linux/IO.cpp"
#include "tools/vmill/Runtime/Linux/MM.cpp"
#include "tools/vmill/Runtime/Linux/Net.cpp"
#include "tools/vmill/Runtime/Linux/Sys.cpp"

namespace {

// 32-bit system call dispatcher for `int 0x80` and `sysenter` system call
// entry points.
static Memory *SystemCall32(Memory *memory, State *state,
                            const SystemCallABI &syscall) {
  switch (auto syscall_num = syscall.GetSystemCallNum(memory, state)) {
    case 1: return SysExit(memory, state, syscall);
    case 3: return SysRead(memory, state, syscall);
    case 4: return SysWrite(memory, state, syscall);
    case 5: return SysOpen(memory, state, syscall);
    case 6: return SysClose(memory, state, syscall);
    case 24: return SysGetUserId(memory, state, syscall);
    case 33: return SysAccess(memory, state, syscall);
    case 45: return SysBrk(memory, state, syscall);
    case 47: return SysGetGroupId(memory, state, syscall);
    case 49: return SysGetEffectiveUserId(memory, state, syscall);
    case 50: return SysGetEffectiveGroupId(memory, state, syscall);
    case 54: return SysIoctl(memory, state, syscall);
    case 59: return SysUname<linux_oldold_utsname>(memory, state, syscall);
    case 74: return SysSetHostName(memory, state, syscall);
    case 78: return SysGetTimeOfDay32(memory, state, syscall);
    case 79: return SysSetTimeOfDay32(memory, state, syscall);
    case 91: return SysMunmap(memory, state, syscall);
    case 102: return SysSocketCall<uint32_t>(memory, state, syscall);
    case 106: return SysStat<linux32_stat>(memory, state, syscall);
    case 107: return SysLstat<linux32_stat>(memory, state, syscall);
    case 108: return SysFstat<linux32_stat>(memory, state, syscall);
    case 109: return SysUname<linux_old_utsname>(memory, state, syscall);
    case 122: return SysUname<linux_new_utsname>(memory, state, syscall);
    case 125: return SysMprotect(memory, state, syscall);
    case 140: return SysLlseek(memory, state, syscall);
    case 174:  // SYS_sys_rt_sigaction, don't handle for now.
    case 175:  // SYS_sys_rt_sigprocmask, don't handle for now.
      return syscall.SetReturn(memory, state, 0);
    case 192: return SysMmap(memory, state, syscall);
    case 195: return SysStat<linux32_stat64>(memory, state, syscall);
    case 196: return SysLstat<linux32_stat64>(memory, state, syscall);
    case 197: return SysFstat<linux32_stat64>(memory, state, syscall);
    case 240: return SysFutex<linux32_timespec>(memory, state, syscall);
    default:
      return syscall.SetReturn(memory, state, -ENOSYS);
  }
}

}  // namespace
