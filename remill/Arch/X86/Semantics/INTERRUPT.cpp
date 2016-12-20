/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_
#define REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_

namespace {

#if 32 == ADDRESS_SIZE_BITS
template <typename S1, typename S2>
DEF_SEM(BOUND, R8W cond, S1 src1, S2 src2) {
  auto index = Read(src1);
  auto lower_bound = Read(src2);
  auto upper_bound = Read(GetElementPtr(src2, Literal<S2>(1)));
  HYPER_CALL = AsyncHyperCall::kX86Bound;
  INTERRUPT_VECTOR = 5;
  Write(cond, BOr(UCmpLt(index, lower_bound), UCmpLt(upper_bound, index)));
}
#endif

DEF_SEM(DoINT_IMMb, I8 num) {
  INTERRUPT_VECTOR = Read(num);
  HYPER_CALL = AsyncHyperCall::kX86IntN;
}

DEF_SEM(DoINT1) {
  INTERRUPT_VECTOR = 1;
  HYPER_CALL = AsyncHyperCall::kX86Int1;
}

DEF_SEM(DoINT3) {
  INTERRUPT_VECTOR = 3;
  HYPER_CALL = AsyncHyperCall::kX86Int3;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_SEM(DoINTO, R8W cond) {
  Write(cond, FLAG_OF);
  INTERRUPT_VECTOR = 4;
  HYPER_CALL = AsyncHyperCall::kX86IntO;
}

#endif  // 32 == ADDRESS_SIZE_BITS
}  // namespace

DEF_ISEL(INT_IMMb) = DoINT_IMMb;
DEF_ISEL(INT1) = DoINT1;
DEF_ISEL(INT3) = DoINT3;

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL(INTO) = DoINTO;
DEF_ISEL(BOUND_GPRv_MEMa16_16) = BOUND<R16, M16>;
DEF_ISEL(BOUND_GPRv_MEMa32_32) = BOUND<R32, M32>;
#endif  // 32 == ADDRESS_SIZE_BITS

#endif  // REMILL_ARCH_X86_SEMANTICS_INTERRUPT_H_
