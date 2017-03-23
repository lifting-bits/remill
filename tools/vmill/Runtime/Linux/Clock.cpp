/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

// Emulate a 32-bit `gettimeofday` system call.
static Memory *SysGetTimeOfDay32(Memory *memory, State *state,
                                 const SystemCallABI &syscall) {
  addr_t tv_addr = 0;
  addr_t tz_addr = 0;

  if (!syscall.TryGetArgs(memory, state, &tv_addr, &tz_addr)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timeval tv = {};
  struct timezone tz = {};
  gettimeofday(&tv, &tz);
  auto ret = errno;

  if (tv_addr) {
    linux32_timeval tv_compat = {
        .tv_sec = static_cast<uint32_t>(tv.tv_sec),
        .tv_usec = static_cast<uint32_t>(tv.tv_usec),
    };
    if (!TryWriteMemory(memory, tv_addr, &tv_compat)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (tz_addr) {
    linux32_timezone tz_compat = {
        .tz_minuteswest = tz.tz_minuteswest,
        .tz_dsttime = tz.tz_dsttime
    };
    if (!TryWriteMemory(memory, tz_addr, &tz_compat)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  return syscall.SetReturn(memory, state, -ret);
}


// Emulate a 32-bit `settimeofday` system call.
static Memory *SysSetTimeOfDay32(Memory *memory, State *state,
                                 const SystemCallABI &syscall) {
  addr_t tv_addr = 0;
  addr_t tz_addr = 0;

  if (!syscall.TryGetArgs(memory, state, &tv_addr, &tz_addr)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct timeval tv = {};
  struct timezone tz = {};
  gettimeofday(&tv, &tz);

  if (tv_addr) {
    linux32_timeval tv_compat = {};
    if (!TryReadMemory(memory, tv_addr, &tv_compat)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tv.tv_sec = static_cast<time_t>(tv_compat.tv_sec);
    tv.tv_usec = static_cast<suseconds_t>(tv_compat.tv_usec);
  }

  if (tz_addr) {
    linux32_timezone tz_compat = {};
    if (!TryReadMemory(memory, tz_addr, &tz_compat)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    tz.tz_minuteswest = tz_compat.tz_minuteswest;
    tz.tz_dsttime = tz_compat.tz_dsttime;
  }

  settimeofday(&tv, &tz);
  return syscall.SetReturn(memory, state, -errno);
}

}  // namespace
