/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_SEMANTICS_INTERRUPT_H_
#define MCSEMA_ARCH_X86_SEMANTICS_INTERRUPT_H_

namespace {

#if 32 == ADDRESS_SIZE_BITS
template <typename S1, typename S2>
DEF_SEM(BOUND, S1 idx_, S2 bounds) {
  const auto idx = R(idx_);
  const auto lb = R(bounds);
  const auto ub = R(S2{A(bounds) + sizeof(idx)});
  if (idx < lb || ub < idx) {
    state.interrupt_vector = 5;
    __mcsema_interrupt_call(state, next_pc);
  }
}
#endif

}  // namespace

DEF_ISEL_SEM(INT_IMMb, I8 num) {
  state.interrupt_vector = R(num);
}

DEF_ISEL_SEM(INT1) {
  state.interrupt_vector = 1;
}

DEF_ISEL_SEM(INT3) {
  state.interrupt_vector = 3;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(INTO) {
  if (state.aflag.of) {
    state.interrupt_vector = 4;
    __mcsema_interrupt_call(state, next_pc);
  }
}

DEF_ISEL(BOUND_GPRv_MEMa16_16) = BOUND<R16, M16>;
DEF_ISEL(BOUND_GPRv_MEMa32_32) = BOUND<R32, M32>;
#endif  // 32 == ADDRESS_SIZE_BITS

#endif  // MCSEMA_ARCH_X86_SEMANTICS_INTERRUPT_H_
