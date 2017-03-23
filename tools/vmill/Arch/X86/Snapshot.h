/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_ARCH_X86_SNAPSHOT_H_
#define TOOLS_VMILL_ARCH_X86_SNAPSHOT_H_

namespace remill {
namespace vmill {
namespace x86 {

// Copy the register state from the tracee with PID `pid` into the file
// with FD `fd`.
void CopyTraceeState(pid_t pid, int fd);

}  // namespace x86
}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_ARCH_X86_SNAPSHOT_H_
