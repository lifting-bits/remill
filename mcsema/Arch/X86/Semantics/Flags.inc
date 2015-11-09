/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

template <typename T, typename R>
__attribute__((noinline, const))
extern bool CarryFlag(T lhs, T rhs, R result);

template <typename T, typename R>
__attribute__((noinline, const))
extern bool ParityFlag(T lhs, T rhs, R result);

template <typename T, typename R>
__attribute__((noinline, const))
extern bool AuxCarryFlag(T lhs, T rhs, R result);

template <typename T, typename R>
__attribute__((noinline, const))
extern bool ZeroFlag(T lhs, T rhs, R result);

template <typename T, typename R>
__attribute__((noinline, const))
extern bool SignFlag(T lhs, T rhs, R result);

template <typename T, typename R>
__attribute__((noinline, const))
extern bool OverflowFlag(T lhs, T rhs, R result);

__attribute__((always_inline, const))
inline static bool Undefined(void) {
  bool undefined;  // Ideally should produce an LLVM `undef` value.
  return undefined;
}

#define SET_AFLAGS(lhs, rhs, result) \
    state.aflag.of = OverflowFlag(lhs, rhs, result); \
    state.aflag.sf = SignFlag(lhs, rhs, result); \
    state.aflag.zf = ZeroFlag(lhs, rhs, result); \
    state.aflag.af = AuxCarryFlag(lhs, rhs, result); \
    state.aflag.pf = ParityFlag(lhs, rhs, result); \
    state.aflag.of = OverflowFlag(lhs, rhs, result)

#define CLEAR_AFLAGS() \
    state.aflag.of = Undefined(); \
    state.aflag.sf = Undefined(); \
    state.aflag.zf = Undefined(); \
    state.aflag.af = Undefined(); \
    state.aflag.pf = Undefined(); \
    state.aflag.of = Undefined()
