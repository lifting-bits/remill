/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_ARCH_X86_SYSTEM32_H_
#define TOOLS_VMILL_ARCH_X86_SYSTEM32_H_

#include <unistd.h>

#include "remill/Arch/Runtime/HyperCall.h"
#include "tools/vmill/OS/System32.h"

namespace remill {

struct ArchState;

namespace vmill {

class Snapshot;
class Thread32;

namespace x86 {

// Returns the size of the `State` structure for all X86 variants. This is
// actually the same across the board, but we always treat it as if the
// `State` structure is for a 64-bit application.
//
// Note: This is rounded up to a multiple of 4096.
uint64_t StateSize(void);

// Copy the register state from the tracee with PID `pid` into the file
// with FD `fd`.
void CopyTraceeState(pid_t pid, int fd);

// Create a 32-bit thread.
Thread32 *CreateThread32(const Snapshot *snapshot);

}  // namespace x86
}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_ARCH_X86_SYSTEM32_H_
