/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cerrno>
#include <linux/net.h>
#include <sys/syscall.h>

#include "tools/vmill/OS/System32.h"

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

}  // namespace

void Process32::DoSystemCall(SystemCall32 &syscall) {
  switch (auto syscall_num = syscall.GetSystemCallNum()) {
    case 102:  // __NR_socketcall
      DoSocketCall(this, syscall);
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
