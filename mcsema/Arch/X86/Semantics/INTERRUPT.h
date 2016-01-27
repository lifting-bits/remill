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
    state.interrupt.next_pc = next_pc;
    state.interrupt.vector = 5;
    state.interrupt.trigger = true;
  } else {
    state.interrupt.next_pc = next_pc;
    state.interrupt.trigger = false;
  }
}
#endif

}  // namespace

DEF_ISEL_SEM(INT_IMMb, I8 num) {
  state.interrupt.next_pc = next_pc;
  state.interrupt.vector = R(num);
  state.interrupt.trigger = true;
}

DEF_ISEL_SEM(INT1) {
  INT_IMMb(state, next_pc, {1});
  state.interrupt.trigger = true;
}

DEF_ISEL_SEM(INT3) {
  INT_IMMb(state, next_pc, {3});
  state.interrupt.trigger = true;
}

#if 32 == ADDRESS_SIZE_BITS
DEF_ISEL_SEM(INTO) {
  if (state.aflag.of) {
    INT_IMMb(state, next_pc, {4});
  } else {
    state.interrupt.next_pc = next_pc;
    state.interrupt.trigger = false;
  }
}

DEF_ISEL(BOUND_GPRv_MEMa16_16) = BOUND<R16, M16>;
DEF_ISEL(BOUND_GPRv_MEMa32_32) = BOUND<R32, M32>;
#endif  // 32 == ADDRESS_SIZE_BITS

#endif  // MCSEMA_ARCH_X86_SEMANTICS_INTERRUPT_H_
