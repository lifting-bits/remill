/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_NATIVEEXEC_EMULATOR_H_
#define TOOLS_VMILL_EMULATOR_NATIVEEXEC_EMULATOR_H_

#include "tools/vmill/Emulator/Emulator.h"

namespace remill {
namespace vmill {

class NativeExecutor : public Emulator {
 public:
  virtual ~NativeExecutor(void);

  explicit NativeExecutor(CodeVersion code_version_);
  Status Emulate(Process32 *process, Thread32 *thread) override;

 protected:

 private:
  NativeExecutor(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_NATIVEEXEC_EMULATOR_H_
