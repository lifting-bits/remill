/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_CFG_CFG_H_
#define REMILL_CFG_CFG_H_

#include <string>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"

// this is copied inside the build directory by the protobuf macros
#include <CFG.pb.h>

#pragma clang diagnostic pop
class Module;

namespace llvm {
class Module;
}  // namespace llvm

namespace remill {

class Arch;

const cfg::Module *ReadCFG(std::string cfg_file_name);

}  // namespace remill

#endif  // REMILL_CFG_CFG_H_
