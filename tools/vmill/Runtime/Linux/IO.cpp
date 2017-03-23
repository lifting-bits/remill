/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <fcntl.h>
#include <unistd.h>

namespace {

// Emulate a `read` system call.
static Memory *SysRead(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t size = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &size)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanWriteMemory(memory, buf, size)) {
    syscall.SetReturn(memory, state, -EFAULT);
    return memory;
  }

  ssize_t read_bytes = 0;
  for (auto max_bytes = static_cast<ssize_t>(size); read_bytes < max_bytes; ) {
    errno = 0;
    auto num_bytes = read(fd, gIOBuffer, kIOBufferSize);
    if (0 >= num_bytes) {
      if (read_bytes) {
        return syscall.SetReturn(memory, state, read_bytes);
      } else {
        return syscall.SetReturn(memory, state, -errno);
      }
    } else {
      memory = CopyToMemory(memory, buf, gIOBuffer,
                            static_cast<size_t>(num_bytes));
      buf += static_cast<size_t>(num_bytes);
      read_bytes += num_bytes;
    }
  }

  return syscall.SetReturn(memory, state, read_bytes);
}

// Emulate a `read` system call.
static Memory *SysWrite(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t size = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &size)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  // TODO(pag): Not 100% right; can have partial reads at the page granularity.
  if (!CanReadMemory(memory, buf, size)) {
    syscall.SetReturn(memory, state, -EFAULT);
    return memory;
  }

  ssize_t written_bytes = 0;
  for (auto max_bytes = static_cast<ssize_t>(size);
       written_bytes < max_bytes; ) {

    auto num_bytes_left = size - static_cast<size_t>(written_bytes);
    auto num_to_copy = std::min<size_t>(kIOBufferSize, num_bytes_left);
    CopyFromMemory(memory, gIOBuffer, buf, num_to_copy);

    errno = 0;
    auto num_bytes = write(fd, gIOBuffer, num_to_copy);
    if (0 >= num_bytes) {
      if (written_bytes) {
        return syscall.SetReturn(memory, state, written_bytes);
      } else {
        return syscall.SetReturn(memory, state, -errno);
      }
    } else {
      written_bytes += num_bytes;
    }
  }

  return syscall.SetReturn(memory, state, written_bytes);
}

// Emulate an `open` system call.
static Memory *SysOpen(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t path = 0;
  int oflag = 0;
  mode_t mode = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &oflag, &mode)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto path_len = CopyStringFromMemory(memory, path, gPath, PATH_MAX);
  gPath[PATH_MAX] = '\0';

  if (path_len >= PATH_MAX) {
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);

  // The string read does not end in a NUL-terminator; i.e. we read less
  // than `PATH_MAX`, but as much as we could without faulting, and we didn't
  // read the NUL char.
  } else if ('\0' != gPath[path_len]) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto fd = open(gPath, oflag, mode);
  if (-1 == fd) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, fd);
  }
}

// Emulate a `close` system call.
static Memory *SysClose(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  if (!syscall.TryGetArgs(memory, state, &fd)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = close(fd);
  return syscall.SetReturn(memory, state, ret * errno);
}

// Emulate a `close` system call.
static Memory *SysIoctl(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  unsigned long request = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &request)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  switch (request) {
    case TCGETS:
    case TCSETS:
      return syscall.SetReturn(memory, state, -ENOTTY);
    default:
      return syscall.SetReturn(memory, state, -EINVAL);
  }
}

}  // namespace
