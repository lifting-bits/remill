/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

extern "C" {

#define MAKE_FLAG(name, size) \
    [[gnu::const]] extern bool __mcsema_flag_ ## name ## _ ## size ( \
        uint ## size ## _t, uint ## size ## _t, uint ## size ## _t)

#define DEFINE_FLAG(name) \
    IF_64BIT( MAKE_FLAG(name, 128) ; ) \
    MAKE_FLAG(name, 64) ; \
    MAKE_FLAG(name, 32); \
    MAKE_FLAG(name, 16); \
    MAKE_FLAG(name, 8) \

// Create the intrinsics for every flag for every operand size.
DEFINE_FLAG(carry);
DEFINE_FLAG(parity);
DEFINE_FLAG(aux_carry);
DEFINE_FLAG(zero);
DEFINE_FLAG(sign);
DEFINE_FLAG(overflow);

#undef MAKE_FLAG

}  // extern C
namespace {

template <typename T, bool (*compute)(T, T, T)>
[[gnu::const, gnu::gnu_inline, gnu::flatten]]
inline static bool MakeFlag(T src1, T src2, T dst) {
  return compute(src1, src2, dst);
}

#define MAKE_FLAG(name, size) \
  template <typename T, \
            typename std::enable_if<sizeof(T)==(size/8),int>::type=0> \
  [[gnu::const, gnu::gnu_inline, gnu::flatten]] \
  inline static bool __mcsema_flag_ ## name (T src1, T src2, T dst) { \
    typedef uint ## size ## _t DT; \
    return MakeFlag<uint ## size ## _t, __mcsema_flag_ ## name ## _ ## size>( \
        static_cast<DT>(src1), static_cast<DT>(src2), static_cast<DT>(dst)); \
  }

DEFINE_FLAG(carry)
DEFINE_FLAG(parity)
DEFINE_FLAG(aux_carry)
DEFINE_FLAG(zero)
DEFINE_FLAG(sign)
DEFINE_FLAG(overflow)
#undef DEFINE_FLAG

}  // namespace

// Arithmetic flags (e.g. ADD, SUB)
#define SET_AFLAGS_OSZAPC(lhs, rhs, result) \
    state.aflag.of = __mcsema_flag_overflow(lhs, rhs, result); \
    state.aflag.sf = __mcsema_flag_sign(lhs, rhs, result); \
    state.aflag.zf = __mcsema_flag_zero(lhs, rhs, result); \
    state.aflag.af = __mcsema_flag_aux_carry(lhs, rhs, result); \
    state.aflag.pf = __mcsema_flag_parity(lhs, rhs, result); \
    state.aflag.cf = __mcsema_flag_carry(lhs, rhs, result)

// Arithmetic flags (e.g. INC, DEC)
#define SET_AFLAGS_OSZAP(lhs, rhs, result) \
    state.aflag.of = __mcsema_flag_overflow(lhs, rhs, result); \
    state.aflag.sf = __mcsema_flag_sign(lhs, rhs, result); \
    state.aflag.zf = __mcsema_flag_zero(lhs, rhs, result); \
    state.aflag.af = __mcsema_flag_aux_carry(lhs, rhs, result); \
    state.aflag.pf = __mcsema_flag_parity(lhs, rhs, result)

// Bitwise flags.
//
// Note: We'll leave the auxiliary carry flag as-is.
#define SET_AFLAGS_SZAP(lhs, rhs, result) \
    state.aflag.of = __mcsema_undefined_bool(); \
    state.aflag.sf = __mcsema_flag_sign(lhs, rhs, result); \
    state.aflag.zf = __mcsema_flag_zero(lhs, rhs, result); \
    state.aflag.pf = __mcsema_flag_parity(lhs, rhs, result); \
    state.aflag.cf = __mcsema_undefined_bool()

#define SET_AFLAGS_OSC(lhs, rhs, result) \
    state.aflag.of = __mcsema_flag_overflow(lhs, rhs, result); \
    state.aflag.sf = __mcsema_flag_sign(lhs, rhs, result); \
    state.aflag.zf = __mcsema_undefined_bool(); \
    state.aflag.af = __mcsema_undefined_bool(); \
    state.aflag.pf = __mcsema_undefined_bool(); \
    state.aflag.cf = __mcsema_flag_carry(lhs, rhs, result)

#define CLEAR_AFLAGS() \
    state.aflag.of = __mcsema_undefined_bool(); \
    state.aflag.sf = __mcsema_undefined_bool(); \
    state.aflag.zf = __mcsema_undefined_bool(); \
    state.aflag.af = __mcsema_undefined_bool(); \
    state.aflag.pf = __mcsema_undefined_bool(); \
    state.aflag.of = __mcsema_undefined_bool()
