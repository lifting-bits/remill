/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_ABI_H_
#define REMILL_BC_ABI_H_

namespace llvm {
class Function;
}  // namespace
namespace remill {

// Describes the arguments to a basic block function.
enum : size_t {
  kNumBlockArgs = 3,
  kStatePointerArgNum = 0,
  kMemoryPointerArgNum = 1,
  kPCArgNum = 2
};

}  // namespace remill

#endif  // REMILL_BC_ABI_H_
