/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

// Used to select specializations of flags computations based on what operator
// is executed.
enum : uint32_t {
  kLHS = 2415899639U,
  kRHS = 70623199U
};

// Zero flags, tells us whether or not a value is zero.
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool ZeroFlag(T res) {
  __mcsema_defer_inlining();
  return static_cast<T>(0) == res;
}

// Sign flag, tells us if a result is signed or unsigned.
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool SignFlag(T res) {
  typedef typename SignedIntegerType<T>::Type ST;
  __mcsema_defer_inlining();
  return 0 > static_cast<ST>(res);
}

// Auxiliary carry flag. This is used for binary coded decimal operations and
// is the 5th bit (where each binary decimal is 4 bits).
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool AuxCarryFlag(T lhs, T rhs, T res) {
  __mcsema_defer_inlining();
  return ((res ^ lhs ^ rhs) & static_cast<T>(0x10));
}

// Tests whether there is an even number of bits in the low order byte.
[[gnu::const]]
NEVER_INLINE static bool ParityFlag(uint8_t r0) {
  __mcsema_defer_inlining();
  auto r1 = r0 >> 1;
  auto r2 = r1 >> 1;
  auto r3 = r2 >> 1;
  auto r4 = r3 >> 1;
  auto r5 = r4 >> 1;
  auto r6 = r5 >> 1;
  auto r7 = r6 >> 1;

  return !(1 & (r0 ^ r1 ^ r2 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7));
}

// Tests whether there is an even number of bits or not.
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool ParityFlag(T x) {
  return ParityFlag(static_cast<uint8_t>(x));
}

// Generic overflow flag.
template <uint32_t kSel>
struct Overflow;

// Computes an overflow flag when two numbers are added together.
template <>
struct Overflow<kLHS + kRHS> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for addition.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    __mcsema_defer_inlining();
    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_res) + (sign_rhs ^ sign_res);
  }
};

// Computes an overflow flag when one number is subtracted from another.
template <>
struct Overflow<kLHS - kRHS> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T res) {
  static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for "
                  "subtraction.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    __mcsema_defer_inlining();
    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_rhs) + (sign_lhs ^ sign_res);
  }
};

// Computes an overflow flag when one number is multiplied with another.
template <>
struct Overflow<kLHS * kRHS> {

  // Integer multiplication overflow check, where result is twice the width of
  // the operands.
  template <typename T, typename R>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(
      T, T, R res,
      typename std::enable_if<sizeof(T) < sizeof(R),int>::type=0) {

    __mcsema_defer_inlining();
    return static_cast<R>(static_cast<T>(res)) != res;
  }

  // Signed integer multiplication overflow check, where the result is
  // truncated to the size of the operands.
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(
      T lhs, T rhs, T res,
      typename std::enable_if<std::is_signed<T>::value,int>::type=0) {
    typedef typename NextLargerIntegerType<T>::Type WT;

    __mcsema_defer_inlining();
    auto lhs_wide = static_cast<WT>(lhs);
    auto rhs_wide = static_cast<WT>(rhs);
    return Flag<T, WT>(lhs, rhs, lhs_wide * rhs_wide);
  }
};

// Generic overflow flag.
template <uint32_t kSel>
struct Carry;

// Computes an overflow flag when two numbers are added together.
template <>
struct Carry<kLHS + kRHS> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    __mcsema_defer_inlining();
    return res < lhs;
  }
};

// Computes an overflow flag when one number is subtracted from another.
template <>
struct Carry<kLHS - kRHS> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    __mcsema_defer_inlining();
    return lhs < rhs;
  }
};

}  // namespace

// Arithmetic flags (e.g. ADD, SUB)
#define SET_AFLAGS_ADD_SUB(lhs, op, rhs, T, dst_op) \
    { const auto __lhs = (lhs); \
      const auto __rhs = (rhs); \
      const auto __lhs_T = static_cast<T>(__lhs); \
      const auto __rhs_T = static_cast<T>(__rhs); \
      const auto __res_T = static_cast<T>(__lhs_T op __rhs_T); \
      \
      W(dst_op) = __res_T; \
      \
      __mcsema_compiler_barrier(); \
      \
      const auto new_cf = Carry<kLHS op kRHS>::Flag(__lhs, __rhs, __res_T); \
      const auto new_pf = ParityFlag(__res_T); \
      const auto new_af = AuxCarryFlag(__lhs_T, __rhs_T, __res_T); \
      const auto new_zf = ZeroFlag(__res_T); \
      const auto new_sf = SignFlag(__res_T); \
      const auto new_of = Overflow<kLHS op kRHS>::Flag(__lhs, __rhs, __res_T); \
      \
      state.aflag.cf = new_cf; \
      state.aflag.pf = new_pf; \
      state.aflag.af = new_af; \
      state.aflag.zf = new_zf; \
      state.aflag.sf = new_sf; \
      state.aflag.df = state.aflag.df; \
      state.aflag.of = new_of; }

// Arithmetic flags (e.g. INC, DEC)
#define SET_AFLAGS_INC_DEC(lhs, op, rhs, T, dst_op) \
    { const auto __lhs = (lhs); \
      const auto __rhs = (rhs); \
      const auto __lhs_T = static_cast<T>(__lhs); \
      const auto __rhs_T = static_cast<T>(__rhs); \
      const auto __res_T = static_cast<T>(__lhs_T op __rhs_T); \
      \
      W(dst_op) = __res_T; \
      \
      __mcsema_compiler_barrier(); \
      \
      const auto new_pf = ParityFlag(__res_T); \
      const auto new_af = AuxCarryFlag(__lhs_T, __rhs_T, __res_T); \
      const auto new_zf = ZeroFlag(__res_T); \
      const auto new_sf = SignFlag(__res_T); \
      const auto new_of = Overflow<kLHS op kRHS>::Flag(__lhs, __rhs, __res_T); \
      \
      state.aflag.cf = state.aflag.cf; \
      state.aflag.pf = new_pf; \
      state.aflag.af = new_af; \
      state.aflag.zf = new_zf; \
      state.aflag.sf = new_sf; \
      state.aflag.df = state.aflag.df; \
      state.aflag.of = new_of; }

// Bitwise flags (AND, OR, XOR, TEST).
//
// Note: We'll leave the auxiliary carry flag as-is.
#define SET_AFLAGS_LOGICAL(lhs, op, rhs, T, dst_op) \
    { const auto __lhs = (lhs); \
      const auto __rhs = (rhs); \
      const auto __lhs_T = static_cast<T>(__lhs); \
      const auto __rhs_T = static_cast<T>(__rhs); \
      const auto __res_T = static_cast<T>(__lhs_T op __rhs_T); \
      \
      W(dst_op) = __res_T; \
      \
      __mcsema_compiler_barrier(); \
      \
      const auto new_pf = ParityFlag(__res_T); \
      const auto new_zf = ZeroFlag(__res_T); \
      const auto new_sf = SignFlag(__res_T); \
      \
      state.aflag.cf = false; \
      state.aflag.pf = new_pf; \
      state.aflag.af = state.aflag.af; \
      state.aflag.zf = new_zf; \
      state.aflag.sf = new_sf; \
      state.aflag.df = state.aflag.df; \
      state.aflag.of = false; }

#define CLEAR_AFLAGS() \
    { __mcsema_compiler_barrier(); \
      state.aflag.cf = __mcsema_undefined_bool(); \
      state.aflag.pf = __mcsema_undefined_bool(); \
      state.aflag.af = __mcsema_undefined_bool(); \
      state.aflag.zf = __mcsema_undefined_bool(); \
      state.aflag.sf = __mcsema_undefined_bool(); \
      state.aflag.df = state.aflag.df; \
      state.aflag.of = __mcsema_undefined_bool(); }
