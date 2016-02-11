/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_
#define MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_

DEF_ISEL_SEM(CBW) {
  W(state.gpr.rax.word) = static_cast<uint16_t>(static_cast<int16_t>(
      static_cast<int8_t>(R(state.gpr.rax.byte.low))));
}

// Note: Need to write to the whole register so that high bits of RAX are
//       cleared even though the write is to EAX.
DEF_ISEL_SEM(CWDE) {
  W(state.gpr.rax) = static_cast<uint32_t>(static_cast<int32_t>(
      static_cast<int16_t>(R(state.gpr.rax.word))));
}

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(CDQE) {
  W(state.gpr.rax) = static_cast<uint64_t>(static_cast<int64_t>(
      static_cast<int32_t>(R(state.gpr.rax.dword))));
}
#endif

DEF_ISEL_SEM(CWD) {
  const uint16_t sign = R(state.gpr.rax.word) >> 15U;
  W(state.gpr.rdx.word) = ~(sign - 1_u16);
}

// Note: Need to write to the whole register so that high bits of RDX are
//       cleared even though the write is to EDX.
DEF_ISEL_SEM(CDQ) {
  const uint32_t sign = R(state.gpr.rax.dword) >> 31U;
  W(state.gpr.rdx) = ~(sign - 1_u32);
}

#if 64 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(CQO) {
  const uint64_t sign = R(state.gpr.rax.qword) >> 63U;
  W(state.gpr.rdx) = ~(sign - 1_u64);
}
#endif

#endif  // MCSEMA_ARCH_X86_SEMANTICS_CONVERT_H_
