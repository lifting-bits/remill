/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cerrno>
#include <ctime>
#include <linux/net.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

#include "tools/vmill/OS/Linux32/System.h"

namespace remill {
namespace vmill {
namespace {

static int kSocketCallNumArgs[] = {
  [SYS_SOCKET] = 3,
  [SYS_BIND] = 3,
  [SYS_CONNECT] = 3,
  [SYS_LISTEN] = 2,
  [SYS_ACCEPT] = 3,
  [SYS_GETSOCKNAME] = 3,
  [SYS_GETPEERNAME] = 3,
  [SYS_SOCKETPAIR] = 4,
  [SYS_SEND] = 4,
  [SYS_RECV] = 4,
  [SYS_SENDTO] = 6,
  [SYS_RECVFROM] = 6,
  [SYS_SHUTDOWN] = 2,
  [SYS_SETSOCKOPT] = 5,
  [SYS_GETSOCKOPT] = 5,
  [SYS_SENDMSG] = 3,
  [SYS_RECVMSG] = 3,
  [SYS_ACCEPT4] = 4,
  [SYS_RECVMMSG] = 5,
  [SYS_SENDMMSG] = 4
};

static int kSocketCallNr[] = {
  [SYS_SOCKET] = SYS_socket,
  [SYS_BIND] = SYS_bind,
  [SYS_CONNECT] = SYS_connect,
  [SYS_LISTEN] = SYS_listen,
  [SYS_ACCEPT] = SYS_accept,
  [SYS_GETSOCKNAME] = SYS_getsockname,
  [SYS_GETPEERNAME] = SYS_getpeername,
  [SYS_SOCKETPAIR] = SYS_socketpair,
  [SYS_SEND] = SYS_sendto,
  [SYS_RECV] = SYS_recvfrom,
  [SYS_SENDTO] = SYS_sendto,
  [SYS_RECVFROM] = SYS_recvfrom,
  [SYS_SHUTDOWN] = SYS_shutdown,
  [SYS_SETSOCKOPT] = SYS_setsockopt,  // TODO(pag): This isn't handled right.
  [SYS_GETSOCKOPT] = SYS_getsockopt,  // TODO(pag): This isn't handled right.
  [SYS_SENDMSG] = SYS_sendmsg,
  [SYS_RECVMSG] = SYS_recvmsg,
  [SYS_ACCEPT4] = SYS_accept4,
  [SYS_RECVMMSG] = SYS_sendmmsg,
  [SYS_SENDMMSG] = SYS_recvmmsg
};

//static const char *kSocketCallName[] = {
//  [SYS_SOCKET] = "socket",
//  [SYS_BIND] = "bind",
//  [SYS_CONNECT] = "connect",
//  [SYS_LISTEN] = "listen",
//  [SYS_ACCEPT] = "accept",
//  [SYS_GETSOCKNAME] = "getsockname",
//  [SYS_GETPEERNAME] = "getpeername",
//  [SYS_SOCKETPAIR] = "socketpair",
//  [SYS_SEND] = "sendto",
//  [SYS_RECV] = "recvfrom",
//  [SYS_SENDTO] = "sendto",
//  [SYS_RECVFROM] = "recvfrom",
//  [SYS_SHUTDOWN] = "shutdown",
//  [SYS_SETSOCKOPT] = "setsockopt",  // TODO(pag): This isn't handled right.
//  [SYS_GETSOCKOPT] = "getsockopt",  // TODO(pag): This isn't handled right.
//  [SYS_SENDMSG] = "sendmsg",
//  [SYS_RECVMSG] = "recvmsg",
//  [SYS_ACCEPT4] = "accept4",
//  [SYS_RECVMMSG] = "sendmmsg",
//  [SYS_SENDMMSG] = "recvmmsg",
//};

// Translate the argument pack of the `socketcall`. We don't need to translate
// pointers, because we load in our snapshotted program "at the same spot" as
// it originally was, but now we need to add in the compatibility handling
// flags to "tell" the kernel to treat the passed in pointer arguments in
// a special way.
static void DoSocketCall(Process32 *process, SystemCall32 &abi) {
  uint32_t args_32[] = {0, 0, 0, 0, 0, 0};
  uint64_t args[] = {0, 0, 0, 0, 0, 0};
  Addr32 varargs_ptr = abi.GetUInt32(1);
  const auto call = abi.GetUInt32(0);

  // Check for a bad socket call.
  if (!(SYS_SOCKET <= call && call <= SYS_SENDMMSG)) {
    abi.SetReturn(-EINVAL);
    return;
  }

  // Copy in the arguments.
  for (auto i = 0; i < kSocketCallNumArgs[call]; ++i) {
    if (!process->TryReadDword(varargs_ptr + (i * 4), &(args_32[i]))) {
      abi.SetReturn(-EFAULT);
      return;
    } else {
      args[i] = args_32[i];
    }
  }

  switch (call) {
    case SYS_RECV:
    case SYS_SENDMMSG:
    case SYS_RECVMMSG:
    case SYS_GETSOCKOPT:
      args[3] |= 0x80000000ULL  /* MSG_CMSG_COMPAT */;
      break;

    case SYS_RECVMSG:
    case SYS_SENDMSG:
      args[2] |= 0x80000000ULL  /* MSG_CMSG_COMPAT */;
      break;

    default:  // Don't need to add in any compatibility flags.
      break;
  }

  auto ret = syscall(kSocketCallNr[call], args[0], args[1],
                     args[2], args[3], args[4], args[5]);

  abi.SetReturn(static_cast<int>(ret));
}

struct linux32_timespec {
  int32_t tv_sec;
  int32_t tv_nsec;
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

static void SetInodeNumber(linux32_stat *info32, const struct stat *info) {
  info32->st_ino = info->st_ino;
}

static void SetInodeNumber(linux32_stat64 *info32, const struct stat *info) {
  info32->__st_ino = static_cast<uint32_t>(info->st_ino);
  info32->st_ino = info->st_ino;
}

template <typename T>
void CopyStat(Process32 *process, SystemCall32 &abi, struct stat &info) {
  T info32 = {};
  Addr32 info32_addr = abi.GetUInt32(1);
  if (!process->TryRead(info32_addr, &info32)) {
    abi.SetReturn(-EFAULT);
    return;
  }

  SetInodeNumber(&info32, &info);

  info32.st_dev = info.st_dev;
  info32.st_mode = info.st_mode;
  info32.st_nlink = info.st_nlink;
  info32.st_uid = info.st_uid;
  info32.st_gid = info.st_gid;
  info32.st_rdev = info.st_rdev;
  info32.st_size = info.st_size;
  info32.st_blksize = info.st_blksize;
  info32.st_blocks = info.st_blocks;

  info32.st_atim.tv_sec = static_cast<uint32_t>(info.st_atim.tv_sec);
  info32.st_atim.tv_nsec = static_cast<uint32_t>(info.st_atim.tv_nsec);

  info32.st_mtim.tv_sec = static_cast<uint32_t>(info.st_mtim.tv_sec);
  info32.st_mtim.tv_nsec = static_cast<uint32_t>(info.st_mtim.tv_nsec);

  info32.st_ctim.tv_sec = static_cast<uint32_t>(info.st_ctim.tv_sec);
  info32.st_ctim.tv_nsec = static_cast<uint32_t>(info.st_ctim.tv_nsec);

  if (!process->TryWrite(info32_addr, info32)) {
    abi.SetReturn(-EFAULT);
    return;
  }
  abi.SetReturn(0);
}

template <typename T>
static void DoLStat(Process32 *process, SystemCall32 &abi) {
  struct stat info = {};
  auto path = reinterpret_cast<const char *>(
      static_cast<uintptr_t>(abi.GetUInt32(0)));
  if (lstat(path, &info)) {
    abi.SetReturn(-errno);
    return;
  }
  CopyStat<T>(process, abi, info);
}

template <typename T>
static void DoFStat(Process32 *process, SystemCall32 &abi) {
  auto fd = abi.GetInt32(0);
  struct stat info = {};

  if (fstat(fd, &info)) {
    abi.SetReturn(-errno);
    return;
  }
  CopyStat<T>(process, abi, info);
}

// void *mmap (void *__addr, size_t __len, int __prot,
//             int __flags, int __fd, __off_t __offset);
static void DoMMap(SystemCall32 &abi, int num) {
  auto ret = syscall(
      num, abi.GetUInt32(0), abi.GetUInt32(1), abi.GetUInt32(2),
      abi.GetUInt32(3) | MAP_32BIT, abi.GetInt32(4),
      static_cast<uint64_t>(abi.GetUInt32(5) /* zero-extend */ ));
  abi.SetReturn(ret);
}

// int _llseek(unsigned int fd, unsigned long offset_high,
//             unsigned long offset_low, loff_t *result,
//             unsigned int whence);
static void DoLlseek(Process32 *process, SystemCall32 &abi) {
  auto fd = abi.GetInt32(0);
  auto offset_high = static_cast<uint64_t>(abi.GetUInt32(1));
  auto offset_low = static_cast<uint64_t>(abi.GetUInt32(2));
  auto offset = (offset_high << 32) | offset_low;
  auto result_ptr = abi.GetUInt32(3);
  auto whence = abi.GetInt32(4);
  auto res = lseek64(fd, offset, whence);
  if (-1 == res) {
    abi.SetReturn(-errno);
  } else if (!process->TryWriteQword(result_ptr, static_cast<uint64_t>(res))) {
    abi.SetReturn(-EFAULT);
  } else {
    abi.SetReturn(0);
  }
}


static void DoGetTimeOfDay(Process32 *process, SystemCall32 &abi) {
  struct compat_timeval {
    uint32_t tv_sec;
    uint32_t tv_usec;
  } compat_time = {};
  struct timeval curr_time = {};
  auto tz_addr = static_cast<uintptr_t>(abi.GetUInt32(1));
  if (gettimeofday(&curr_time, reinterpret_cast<struct timezone *>(tz_addr))) {
    abi.SetReturn(-errno);
    return;
  }

  compat_time.tv_sec = static_cast<uint32_t>(curr_time.tv_sec);
  compat_time.tv_usec = static_cast<uint32_t>(curr_time.tv_usec);
  auto tv_addr = abi.GetUInt32(0);
  if (tv_addr && !process->TryWrite(tv_addr, compat_time)) {
    abi.SetReturn(-EFAULT);
  } else {
    abi.SetReturn(0);
  }
}

static void PassThrough0(SystemCall32 &abi, int num) {
  abi.SetReturn(syscall(num));
}

static void PassThrough1(SystemCall32 &abi, int num) {
  auto ret = syscall(num, abi.GetUInt32(0));
  abi.SetReturn(static_cast<int>(ret));
}

static void PassThrough2(SystemCall32 &abi, int num) {
  auto ret = syscall(num, abi.GetUInt32(0), abi.GetUInt32(1));
  abi.SetReturn(static_cast<int>(ret));
}

static void PassThrough3(SystemCall32 &abi, int num) {
  auto ret = syscall(num, abi.GetUInt32(0), abi.GetUInt32(1), abi.GetUInt32(2));
  abi.SetReturn(static_cast<int>(ret));
}

//static void PassThrough4(SystemCall32 &abi, int num) {
//  auto ret = syscall(num, abi.GetUInt32(0), abi.GetUInt32(1), abi.GetUInt32(2),
//                     abi.GetUInt32(3));
//  abi.SetReturn(static_cast<int>(ret));
//}
//
//static void PassThrough5(SystemCall32 &abi, int num) {
//  auto ret = syscall(num, abi.GetUInt32(0), abi.GetUInt32(1), abi.GetUInt32(2),
//                     abi.GetUInt32(3), abi.GetUInt32(4));
//  abi.SetReturn(static_cast<int>(ret));
//}

static void PassThrough6(SystemCall32 &abi, int num) {
  auto ret = syscall(num, abi.GetUInt32(0), abi.GetUInt32(1), abi.GetUInt32(2),
                     abi.GetUInt32(3), abi.GetUInt32(4), abi.GetUInt32(5));
  abi.SetReturn(static_cast<int>(ret));
}

}  // namespace

void Process32::DoSystemCall(SystemCall32 &syscall) {
  switch (auto syscall_num = syscall.GetSystemCallNum()) {
    case 1:
      DLOG(INFO)
          << "Subporcess exiting with status " << syscall.GetInt32(0);
      Kill();
      break;

    case 3:
      PassThrough3(syscall, SYS_read);
      break;

    case 4:
      PassThrough3(syscall, SYS_write);
      break;

    case 5:
      PassThrough3(syscall, SYS_open);
      break;

    case 6:
      PassThrough1(syscall, SYS_close);
      break;

    case 33:
      PassThrough2(syscall, SYS_access);
      break;

    case 45:  // SYS_brk, make the program fall back on `mmap`.
      syscall.SetReturn(0);
      break;

    case 54:
      PassThrough6(syscall, SYS_ioctl);
      break;

    case 74:  // __NR_sethostname
      PassThrough2(syscall, SYS_sethostname);
      break;

    case 78:  // __NR_gettimeofday
      DoGetTimeOfDay(this, syscall);
      break;

    case 91:
      PassThrough2(syscall, SYS_munmap);
      break;

    case 102:
      DoSocketCall(this, syscall);
      break;

    case 106:  // __NR__stat
      DoFStat<linux32_stat>(this, syscall);
      break;

    case 107:  // __NR__lstat
      DoLStat<linux32_stat>(this, syscall);
      break;

    case 108:  // __NR__fstat
      DoFStat<linux32_stat>(this, syscall);
      break;

    case 122:
      PassThrough1(syscall, SYS_uname);
      break;

    case 125:
      PassThrough3(syscall, SYS_mprotect);
      break;

    case 140:  // __NR__llseek.
      DoLlseek(this, syscall);
      break;

    case 174:  // SYS_sys_rt_sigaction, don't handle for now.
    case 175:  // SYS_sys_rt_sigprocmask, don't handle for now.
      syscall.SetReturn(0);
      break;

    case 192:
      DoMMap(syscall, SYS_mmap);
      break;

    case 195:  // __NR__stat64
      DoFStat<linux32_stat64>(this, syscall);
      break;

    case 196:  // __NR__lstat64
      DoLStat<linux32_stat64>(this, syscall);
      break;

    case 197:  // __NR__fstat64
      DoFStat<linux32_stat64>(this, syscall);
      break;

    case 199:
      PassThrough0(syscall, SYS_getuid);
      break;

    // TODO(pag): This is totally wrong for any blocking futex operation
    //            where the timeout argument is used, because the `timespec`
    //            in 32- and 64-bit are different sizes.
    case 240:
      PassThrough6(syscall, SYS_futex);
      break;

    default:
      LOG(ERROR)
            << "Unsupported system call " << syscall_num;
      Kill();
      break;
  }
}

}  // namespace vmill
}  // namespace remill
