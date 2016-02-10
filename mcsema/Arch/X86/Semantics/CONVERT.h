/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_
#define MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_

DEF_ISEL_SEM(CBW) {
  W(state.gpr.rax.word) = static_cast<uint16_t>(static_cast<int16_t>(
      static_cast<int8_t>(R(state.gpr.rax.byte.low))));
}

DEF_ISEL_SEM(CWDE) {
  W(state.gpr.rax.dword) = static_cast<uint32_t>(static_cast<int32_t>(
      static_cast<int16_t>(R(state.gpr.rax.word))));
}

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(CDQE) {
  W(state.gpr.rax.qword) = static_cast<uint64_t>(static_cast<int64_t>(
      static_cast<int32_t>(R(state.gpr.rax.dword))));
}
#endif

#endif  // MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_
