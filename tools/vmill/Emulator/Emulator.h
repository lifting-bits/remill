/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_EMULATOR_H_
#define TOOLS_VMILL_EMULATOR_EMULATOR_H_

#include <cstdint>

namespace remill {
namespace vmill {

class Process32;
class Thread32;
class Translator;

using Addr32 = uint32_t;
using Addr64 = uint64_t;
using CodeVersion = uint64_t;

class Emulator {
 public:
  enum Status {
    kCannotContinue,
    kPaused,
    kStoppedAtAsyncHyperCall,
    kStoppedAtSyncHyperCall,
    kStoppedAtError
  };

  virtual ~Emulator(void);

  virtual Status Emulate(Process32 *process, Thread32 *thread) = 0;

 protected:
  explicit Emulator(CodeVersion code_version_);

  Translator * const translator;
  const CodeVersion code_version;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_EMULATOR_H_
