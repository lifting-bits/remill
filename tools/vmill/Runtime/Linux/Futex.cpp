/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

extern "C" {
int futex(int *uaddr, int op, int val, const struct timespec *timeout,
          int *uaddr2, int val3) {
  auto ret = static_cast<int>(
      syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3));
  if (0 > ret) {
    errno = -ret;
    return -1;
  } else {
    errno = 0;
    return ret;
  }
}
}  // extern C

namespace {

// Emulate a `futex` system call.
//
// TODO(pag): Change this to emulate in terms of pthread-related function
//            calls (for portability to non-Linux platforms). Alternatively,
//            call out to a VMill scheduler of some kind.
template <typename T>
static Memory *SysFutex(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t uaddr = 0;
  int op = -1;
  int val = 0;
  addr_t timeout = 0;
  addr_t uaddr2 = 0;
  int val3 = 0;

  if (!syscall.TryGetArgs(memory, state, &uaddr, &op, &val,
                          &timeout, &uaddr2, &val3)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  int uaddr_val = 0;
  int uaddr2_val = 0;
  struct timespec timeout_val = {};

  if (uaddr) {
    if (!TryReadMemory(memory, uaddr, &uaddr_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (uaddr2) {
    if (!TryReadMemory(memory, uaddr2, &uaddr2_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (timeout) {
    T timeout_compat_val = {};
    if (!TryReadMemory(memory, timeout, &timeout_compat_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    timeout_val.tv_sec = static_cast<time_t>(timeout_compat_val.tv_sec);
    timeout_val.tv_nsec = static_cast<decltype(timeout_val.tv_nsec)>(
        timeout_compat_val.tv_nsec);
  }

  auto ret = futex(
      (uaddr ? &uaddr_val : nullptr), op, val,
      (timeout ? &timeout_val : nullptr),
      (uaddr2 ? &uaddr2_val : nullptr), val3);

  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

}  // namespace
