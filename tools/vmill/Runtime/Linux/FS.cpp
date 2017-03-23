/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

// Emulate an `access` system call.
static Memory *SysAccess(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t path = 0;
  int type = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &type)) {
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

  auto ret = access(gPath, type);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

// Emulate an `llseek` system call.
static Memory *SysLlseek(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t offset_high = 0;
  addr_t offset_low = 0;
  addr_t result_addr = 0;
  int whence = 0;

  if (!syscall.TryGetArgs(memory, state, &fd, &offset_high, &offset_low,
                          &result_addr, &whence)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  off64_t offset = (off64_t(offset_high) << 32UL) | off64_t(offset_low);
  offset = lseek64(fd, offset, whence);
  if (static_cast<off64_t>(-1LL) == offset) {
    return syscall.SetReturn(memory, state, -errno);
  }

  if (!TryWriteMemory(memory, result_addr, offset)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return syscall.SetReturn(memory, state, 0);
}

static void SetInodeNumber(const struct stat &info, linux32_stat *info32) {
  info32->st_ino = info.st_ino;
}

static void SetInodeNumber(const struct stat &info, linux32_stat64 *info32) {
  info32->__st_ino = static_cast<uint32_t>(info.st_ino);
  info32->st_ino = info.st_ino;
}

template <typename T>
void CopyStat(const struct stat &info, T *info32) {
  SetInodeNumber(info, info32);

  info32->st_dev = info.st_dev;
  info32->st_mode = info.st_mode;
  info32->st_nlink = static_cast<uint32_t>(info.st_nlink);
  info32->st_uid = info.st_uid;
  info32->st_gid = info.st_gid;
  info32->st_rdev = info.st_rdev;
  info32->st_size = info.st_size;
  info32->st_blksize = static_cast<int32_t>(info.st_blksize);
  info32->st_blocks = info.st_blocks;

  info32->st_atim.tv_sec = static_cast<uint32_t>(info.st_atim.tv_sec);
  info32->st_atim.tv_nsec = static_cast<uint32_t>(info.st_atim.tv_nsec);

  info32->st_mtim.tv_sec = static_cast<uint32_t>(info.st_mtim.tv_sec);
  info32->st_mtim.tv_nsec = static_cast<uint32_t>(info.st_mtim.tv_nsec);

  info32->st_ctim.tv_sec = static_cast<uint32_t>(info.st_ctim.tv_sec);
  info32->st_ctim.tv_nsec = static_cast<uint32_t>(info.st_ctim.tv_nsec);
}

// Emulate a 32-bit `stat` system call.
template <typename T>
static Memory *SysStat(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t path = 0;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &buf)) {
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (!path || !buf) {
    return syscall.SetReturn(memory, state, -EINVAL);
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

  struct stat info = {};
  if (stat(gPath, &info)) {
    return syscall.SetReturn(memory, state, -errno);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    return syscall.SetReturn(memory, state, 0);
  } else {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate a 32-bit `lstat` system call.
template <typename T>
static Memory *SysLstat(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t path = 0;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &path, &buf)) {
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (!path || !buf) {
    return syscall.SetReturn(memory, state, -EINVAL);
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

  struct stat info = {};
  if (lstat(gPath, &info)) {
    return syscall.SetReturn(memory, state, -errno);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    return syscall.SetReturn(memory, state, 0);
  } else {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate a 32-bit `fstat` system call.
template <typename T>
static Memory *SysFstat(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  } else if (0 > fd) {
    return syscall.SetReturn(memory, state, -EBADFD);
  } else if (!buf) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  struct stat info = {};
  if (fstat(fd, &info)) {
    return syscall.SetReturn(memory, state, -errno);
  }

  T info32 = {};
  CopyStat(info, &info32);

  if (TryWriteMemory(memory, buf, info32)) {
    return syscall.SetReturn(memory, state, 0);
  } else {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

}  // namespace
