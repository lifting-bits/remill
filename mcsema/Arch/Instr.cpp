/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Instr.h"

namespace mcsema {

Instr::Instr(const cfg::Instr *instr_)
    : instr(instr_) {}

Instr::~Instr(void) {}

}  // namespace mcsema
