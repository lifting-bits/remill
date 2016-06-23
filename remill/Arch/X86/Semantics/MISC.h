/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_MISC_H_
#define REMILL_ARCH_X86_SEMANTICS_MISC_H_

namespace {

template <typename D, typename S>
DEF_SEM(LEA, D dst, S src) {
  W(dst) = A(src);  // `src` will be a memory type.
}

DEF_SEM(LEAVE_16BIT) {
  const auto prev_bp = R(state.gpr.rbp);
  Mn<uint16_t> bp_addr = {prev_bp};

  state.gpr.rbp.word = R(bp_addr);
  W(state.gpr.rsp) = prev_bp + sizeof(uint16_t);
}

template <typename T>
DEF_SEM(LEAVE_FULL) {
  static_assert(sizeof(T) == sizeof(R(state.gpr.rbp)),
                "Invalid specialization of `LEAVE_FULL`.");
  const auto prev_bp = R(state.gpr.rbp);
  Mn<T> bp_addr = {prev_bp};

  W(state.gpr.rbp) = R(bp_addr);
  W(state.gpr.rsp) = prev_bp + sizeof(T);
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8>;
IF_64BIT( DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8>; )

DEF_ISEL(LEAVE_16) = LEAVE_16BIT;
DEF_ISEL_RI32or64(LEAVE, LEAVE_FULL);

namespace {

// TODO(pag): Handle the case where the operand size and address size disagree.
//            This can happen when using the 66H or 67H prefixes to override the
//            operand or address sizes. For example, and operand size of 32 with
//            an address size of 16 will read `[BP]` instead of `[EBP]`.
template <typename T>
DEF_SEM(ENTER, I16 alloc_size_, I8 nesting_level_) {
  const auto alloc_size = R(alloc_size_);
  const auto nesting_level = R(nesting_level_) % 32;
  auto frame_temp = R(state.gpr.rsp) - sizeof(T);

  // Detect failure. This should really happen at the end of `ENTER` but we
  // do it here. This is why `frame_temp` is created before the `PUSH` of
  // `RBP`, but displaced to mimick the `PUSH`.
  auto next_rsp = frame_temp - (sizeof(T) * (nesting_level)) - alloc_size;
  Mn<T> next_read = {next_rsp};
  MnW<T> next_write = {next_rsp};
  W(next_write) = R(next_read);

  __remill_barrier_compiler();

  auto rbp_temp = R(state.gpr.rbp);
  PushValue<T>(state, static_cast<T>(rbp_temp));

  if (nesting_level) {
    if (1 < nesting_level) {
      for (auto i = 1; i <= (nesting_level - 1); ++i) {
        rbp_temp -= sizeof(T);  // TODO(pag): Should be affected by 67H prefix.
        Mn<T> display_entry = {rbp_temp};
        PushValue<T>(state, R(display_entry));
      }
    }
    PushValue<T>(state, frame_temp);
  }
  W(state.gpr.rbp) = frame_temp;
  W(state.gpr.rsp) = R(state.gpr.rsp) - alloc_size;
}

}  // namespace

DEF_ISEL(ENTER_IMMw_IMMb_16) = ENTER<uint16_t>;
IF_32BIT(DEF_ISEL(ENTER_IMMw_IMMb_32) = ENTER<uint32_t>;)
IF_64BIT(DEF_ISEL(ENTER_IMMw_IMMb_64) = ENTER<uint64_t>;)

// A `NOP` with a `REP` prefix for hinting. Used for busy-wait loops.
DEF_ISEL_SEM(PAUSE) {}

// A kind of NOP.
DEF_ISEL_SEM(CLFLUSH_MEMmprefetch, M8) {}

// Good reference for memory barriers and their relationships to instructions:
// http://g.oswego.edu/dl/jmm/cookbook.html

DEF_ISEL_SEM(MFENCE) {
  __remill_memory_order = __remill_barrier_store_load(__remill_memory_order);
}

DEF_ISEL_SEM(SFENCE) {
  __remill_memory_order = __remill_barrier_store_store(__remill_memory_order);
}

DEF_ISEL_SEM(LFENCE) {
  __remill_memory_order = __remill_barrier_load_load(__remill_memory_order);
}

DEF_ISEL_SEM(XLAT) {
  const addr_t rbx = R(state.gpr.rbx);
  const addr_t al = state.gpr.rax.byte.low;
  M8 val = {rbx + al};
  W(state.gpr.rax.byte.low) = R(val);
}

// Implemented via the `__remill_read_cpu_features` intrinsic.
DEF_ISEL_SEM(CPUID) {
  W(state.gpr.rip) = R(next_pc);
}

/*
230 INVPCID INVPCID_GPR64_MEMdq MISC INVPCID INVPCID ATTRIBUTES: NOTSX RING0
231 INVPCID INVPCID_GPR32_MEMdq MISC INVPCID INVPCID ATTRIBUTES: NOTSX RING0
639 MONITOR MONITOR MISC SSE3 SSE3 ATTRIBUTES: NOTSX RING0
1924 MWAIT MWAIT MISC SSE3 SSE3 ATTRIBUTES: NOTSX RING0
 */

#endif  // REMILL_ARCH_X86_SEMANTICS_MISC_H_
