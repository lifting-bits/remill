/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_DECODE_H_
#define MCSEMA_ARCH_X86_DECODE_H_

#include "mcsema/Arch/X86/XED.h"

namespace mcsema {
namespace cfg {
class Instr;
}  // namespace

enum ArchName : unsigned;

namespace x86 {

xed_decoded_inst_t DecodeInstruction(
    const cfg::Instr &instr, ArchName arch_name);

}  // namespace x86
}  // namespace mcsema

#endif  // MCSEMA_ARCH_X86_DECODE_H_
