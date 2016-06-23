/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_CFG_CFG_H_
#define REMILL_CFG_CFG_H_

#include <string>

#include "generated/CFG/CFG.pb.h"

class Module;

namespace llvm {
class Module;
}  // namespace llvm

namespace remill {

class Arch;

const cfg::Module *ReadCFG(std::string cfg_file_name);

}  // namespace remill

#endif  // REMILL_CFG_CFG_H_
