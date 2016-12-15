/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/Emulator/Emulator.h"

namespace remill {
namespace vmill {

Emulator::Emulator(CodeVersion code_version_)
    : translator(Translator::Create(code_version_)),
      code_version(code_version_) {}

Emulator::~Emulator(void) {
  delete translator;
}

}  // namespace vmill
}  // namespace remill
