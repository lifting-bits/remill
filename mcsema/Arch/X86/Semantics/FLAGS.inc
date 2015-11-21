/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool CarryFlag(S1 lhs, S2 rhs, R result);

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool ParityFlag(S1 lhs, S2 rhs, R result);

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool AuxCarryFlag(S1 lhs, S2 rhs, R result);

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool ZeroFlag(S1 lhs, S2 rhs, R result);

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool SignFlag(S1 lhs, S2 rhs, R result);

template <typename S1, typename S2, typename R>
[[gnu::const]]
extern bool OverflowFlag(S1 lhs, S2 rhs, R result);

// Arithmetic flags (e.g. ADD, SUB)
#define SET_AFLAGS_OSZAPC(lhs, rhs, result) \
    state.aflag.of = OverflowFlag(lhs, rhs, result); \
    state.aflag.sf = SignFlag(lhs, rhs, result); \
    state.aflag.zf = ZeroFlag(lhs, rhs, result); \
    state.aflag.af = AuxCarryFlag(lhs, rhs, result); \
    state.aflag.pf = ParityFlag(lhs, rhs, result); \
    state.aflag.cf = CarryFlag(lhs, rhs, result)

// Arithmetic flags (e.g. INC, DEC)
#define SET_AFLAGS_OSZAP(lhs, rhs, result) \
    state.aflag.of = OverflowFlag(lhs, rhs, result); \
    state.aflag.sf = SignFlag(lhs, rhs, result); \
    state.aflag.zf = ZeroFlag(lhs, rhs, result); \
    state.aflag.af = AuxCarryFlag(lhs, rhs, result); \
    state.aflag.pf = ParityFlag(lhs, rhs, result)

// Bitwise flags.
//
// Note: We'll leave the auxiliary carry flag as-is.
#define SET_AFLAGS_SZAP(lhs, rhs, result) \
    state.aflag.of = __mcsema_undefined_bool(); \
    state.aflag.sf = SignFlag(lhs, rhs, result); \
    state.aflag.zf = ZeroFlag(lhs, rhs, result); \
    state.aflag.pf = ParityFlag(lhs, rhs, result); \
    state.aflag.cf = __mcsema_undefined_bool()

#define SET_AFLAGS_OSC(lhs, rhs, result) \
    state.aflag.of = OverflowFlag(lhs, rhs, result); \
    state.aflag.sf = SignFlag(lhs, rhs, result); \
    state.aflag.zf = __mcsema_undefined_bool(); \
    state.aflag.af = __mcsema_undefined_bool(); \
    state.aflag.pf = __mcsema_undefined_bool(); \
    state.aflag.cf = CarryFlag(lhs, rhs, result)

#define CLEAR_AFLAGS() \
    state.aflag.of = __mcsema_undefined_bool(); \
    state.aflag.sf = __mcsema_undefined_bool(); \
    state.aflag.zf = __mcsema_undefined_bool(); \
    state.aflag.af = __mcsema_undefined_bool(); \
    state.aflag.pf = __mcsema_undefined_bool(); \
    state.aflag.of = __mcsema_undefined_bool()
