/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_DECODE_H_
#define REMILL_ARCH_X86_DECODE_H_

#include "remill/Arch/X86/XED.h"

namespace remill {
namespace cfg {
class Instr;
}  // namespace

enum ArchName : unsigned;

namespace x86 {

xed_decoded_inst_t DecodeInstruction(
    const cfg::Instr &instr, ArchName arch_name);

}  // namespace x86
}  // namespace remill

#endif  // REMILL_ARCH_X86_DECODE_H_
