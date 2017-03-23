/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

static Memory *SysExit(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int exit_code = EXIT_SUCCESS;
  if (!syscall.TryGetArgs(memory, state, &exit_code)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  } else {
    exit(exit_code);
    return memory;
  }
}

//// Emulate an `gethostname` system call.
//static Memory *SysGetHostName(Memory *memory, State *state,
//                              const SystemCallABI &syscall) {
//  addr_t name = 0;
//  int len = 0;
//  if (!syscall.TryGetArgs(memory, state, &name, &len)) {
//    return syscall.SetReturn(memory, state, -EFAULT);
//  } else if (0 > len || HOST_NAME_MAX < len) {
//    return syscall.SetReturn(memory, state, -EINVAL);
//  }
//
//  gethostname(gHostName, HOST_NAME_MAX);
//  gHostName[HOST_NAME_MAX] = '\0';
//
//  auto actual_len = strlen(gHostName);
//  if (len < actual_len) {
//    return syscall.SetReturn(memory, state, -ENAMETOOLONG);
//  }
//
//  // Copy the maximum length host name, regardless of if the specified host
//  // name length is shorter.
//  auto copied_len = CopyStringToMemory(memory, name, gHostName, actual_len);
//  if (copied_len != actual_len) {
//    return syscall.SetReturn(memory, state, -EFAULT);
//  }
//
//  syscall.SetReturn(memory, state, 0);
//}


// Emulate an `sethostname` system call.
static Memory *SysSetHostName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  addr_t name = 0;
  size_t len = 0;
  if (!syscall.TryGetArgs(memory, state, &name, &len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  } else if (HOST_NAME_MAX < len) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Copy the maximum length host name, regardless of if the specified host
  // name length is shorter.
  auto name_len = CopyStringFromMemory(memory, name, gHostName, HOST_NAME_MAX);
  gHostName[HOST_NAME_MAX] = '\0';

  // The hostname passed to `sethostname` is a C string, and it is shorter
  // than the explicitly specified length.
  if (name_len < len) {
    return syscall.SetReturn(memory, state, -ENAMETOOLONG);
  }

  (void) sethostname(gHostName, len);
  return syscall.SetReturn(memory, state, -errno);
}

//static void SetDomainName(const struct utsname &, linux_oldold_utsname *) {}
//static void SetDomainName(const struct utsname &, linux_old_utsname *) {}
static void SetDomainName(const struct utsname &info,
                          linux_new_utsname *info_compat) {
  memcpy(&(info_compat->domainname[0]), &(info.domainname[0]),
         sizeof(info_compat->domainname));
}

// Emulate the `uname` system calls.
template <typename T>
static Memory *SysUname(Memory *memory, State *state,
                        const SystemCallABI &syscall) {
  addr_t buf = 0;
  if (!syscall.TryGetArgs(memory, state, &buf)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct utsname info = {};
  if (-1 == uname(&info)) {
    return syscall.SetReturn(memory, state, -errno);
  }

  linux_new_utsname compat = {};
  memcpy(&(compat.sysname[0]), &(info.sysname[0]), sizeof(compat.sysname));
  memcpy(&(compat.nodename[0]), &(info.nodename[0]), sizeof(compat.nodename));
  memcpy(&(compat.release[0]), &(info.release[0]), sizeof(compat.release));
  memcpy(&(compat.version[0]), &(info.version[0]), sizeof(compat.version));
  memcpy(&(compat.machine[0]), &(info.machine[0]), sizeof(compat.machine));
  SetDomainName(info, &compat);

  if (TryWriteMemory(memory, buf, info)) {
    return syscall.SetReturn(memory, state, 0);
  } else {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
}

// Emulate an `getuid` system call.
static Memory *SysGetUserId(Memory *memory, State *state,
                            const SystemCallABI &syscall) {
  return syscall.SetReturn(memory, state, getuid());
}

// Emulate an `geteuid` system call.
static Memory *SysGetEffectiveUserId(Memory *memory, State *state,
                                     const SystemCallABI &syscall) {
  return syscall.SetReturn(memory, state, geteuid());
}


// Emulate an `getgid` system call.
static Memory *SysGetGroupId(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  return syscall.SetReturn(memory, state, getgid());
}

// Emulate an `getegid` system call.
static Memory *SysGetEffectiveGroupId(Memory *memory, State *state,
                                      const SystemCallABI &syscall) {
  return syscall.SetReturn(memory, state, getegid());
}

}  // namespace
