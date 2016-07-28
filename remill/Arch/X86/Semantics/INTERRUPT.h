/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_
#define REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_

namespace {

#if 32 == ADDRESS_SIZE_BITS
template <typename S1, typename S2>
DEF_SEM(BOUND, S1 src1, S2 src2) {
  auto index = Read(src1);
  auto lower_bound = Read(src2);
  auto upper_bound = Read(GetElementPtr(src2, Literal<S2>(1)));
  INTERRUPT_VECTOR = 5;
  INTERRUPT_TAKEN = BOr(UCmpLt(index, lower_bound), UCmpLt(upper_bound, index));
}
#endif

}  // namespace

DEF_ISEL_SEM(INT_IMMb, I8 num) {
  INTERRUPT_VECTOR = Read(num);
  INTERRUPT_TAKEN = true;
}

DEF_ISEL_SEM(INT1) {
  INTERRUPT_VECTOR = 1;
  INTERRUPT_TAKEN = true;
}

DEF_ISEL_SEM(INT3) {
  INTERRUPT_VECTOR = 3;
  INTERRUPT_TAKEN = true;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(INTO) {
  INTERRUPT_TAKEN = FLAG_OF;
  INTERRUPT_VECTOR = 4;
}

DEF_ISEL(BOUND_GPRv_MEMa16_16) = BOUND<R16, M16>;
DEF_ISEL(BOUND_GPRv_MEMa32_32) = BOUND<R32, M32>;
#endif  // 32 == ADDRESS_SIZE_BITS

#endif  // REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_
