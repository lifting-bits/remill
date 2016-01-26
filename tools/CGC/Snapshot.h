/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_CGC_SNAPSHOT_H_
#define TOOLS_CGC_SNAPSHOT_H_

namespace cgc {

struct Process;

void LoadMemoryFromSnapshot(Process *process, int pid);

}  // namespace cgc

#endif  // TOOLS_CGC_SNAPSHOT_H_
