/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_CFG_CFG_H_
#define MCSEMA_CFG_CFG_H_

#include <string>

#include "generated/CFG/CFG.pb.h"

class Module;

namespace llvm {
class Module;
}  // namespace llvm

namespace mcsema {

class Arch;

const cfg::Module *ReadCFG(std::string cfg_file_name);

}  // namespace mcsema

#endif  // MCSEMA_CFG_CFG_H_
