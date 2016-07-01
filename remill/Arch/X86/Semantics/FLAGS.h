/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_SEMANTICS_FLAGS_H_
#define REMILL_ARCH_X86_SEMANTICS_FLAGS_H_

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
  __remill_defer_inlining();
  return T(0) == res;
}

// Zero flags, tells us whether or not a value is zero.
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool NotZeroFlag(T res) {
  __remill_defer_inlining();
  return T(0) != res;
}

// Sign flag, tells us if a result is signed or unsigned.
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool SignFlag(T res) {
  __remill_defer_inlining();
  return 0 > Signed(res);
}

// Auxiliary carry flag. This is used for binary coded decimal operations and
// is the 5th bit (where each binary decimal is 4 bits).
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool AuxCarryFlag(T lhs, T rhs, T res) {
  __remill_defer_inlining();
  return ((res ^ lhs ^ rhs) & T(0x10));
}

// Auxiliary carry flag. This is used for binary coded decimal operations and
// is the 5th bit (where each binary decimal is 4 bits).
template <typename T>
[[gnu::const]]
NEVER_INLINE static bool AuxCarryFlag(T lhs, T rhs, T carry, T res) {
  __remill_defer_inlining();
  return ((res ^ lhs ^ carry ^ rhs) & T(0x10));
}

// Tests whether there is an even number of bits in the low order byte.
[[gnu::const]]
NEVER_INLINE static bool ParityFlag(uint8_t r0) {
  __remill_defer_inlining();
  auto r1 = r0 >> 1_u8;
  auto r2 = r1 >> 1_u8;
  auto r3 = r2 >> 1_u8;
  auto r4 = r3 >> 1_u8;
  auto r5 = r4 >> 1_u8;
  auto r6 = r5 >> 1_u8;
  auto r7 = r6 >> 1_u8;

  return !(1 & (r0 ^ r1 ^ r2 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7));
}

// Tests whether there is an even number of bits or not.
template <typename T>
[[gnu::const]]
ALWAYS_INLINE static bool ParityFlag(T x) {
  return ParityFlag(static_cast<uint8_t>(x));
}

struct tag_add {};
struct tag_sub {};
struct tag_div {};
struct tag_mul {};

// Generic overflow flag.
template <typename T>
struct Overflow;

// Computes an overflow flag when two numbers are added together.
template <>
struct Overflow<tag_add> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for addition.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    __remill_defer_inlining();
    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_res) + (sign_rhs ^ sign_res);
  }
};

// Computes an overflow flag when one number is subtracted from another.
template <>
struct Overflow<tag_sub> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T res) {
  static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for "
                  "subtraction.");
    enum {
      kSignShift = sizeof(T) * 8 - 1
    };

    __remill_defer_inlining();
    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return 2 == (sign_lhs ^ sign_rhs) + (sign_lhs ^ sign_res);
  }
};

// Computes an overflow flag when one number is multiplied with another.
template <>
struct Overflow<tag_mul> {

  // Integer multiplication overflow check, where result is twice the width of
  // the operands.
  template <typename T, typename R>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(
      T, T, R res,
      typename std::enable_if<sizeof(T) < sizeof(R),int>::type=0) {

    __remill_defer_inlining();
    return static_cast<R>(static_cast<T>(res)) != res;
  }

  // Signed integer multiplication overflow check, where the result is
  // truncated to the size of the operands.
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(
      T lhs, T rhs, T res,
      typename std::enable_if<std::is_signed<T>::value,int>::type=0) {
    __remill_defer_inlining();
    auto lhs_wide = SExt(lhs);
    auto rhs_wide = SExt(rhs);
    return Flag<T, decltype(lhs_wide)>(lhs, rhs, lhs_wide * rhs_wide);
  }
};

// Generic carry flag.
template <typename Tag>
struct Carry;

// Computes an carry flag when two numbers are added together.
template <>
struct Carry<tag_add> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    __remill_defer_inlining();
    return res < lhs || res < rhs;
  }
};

// Computes an carry flag when one number is subtracted from another.
template <>
struct Carry<tag_sub> {
  template <typename T>
  [[gnu::const]]
  NEVER_INLINE static bool Flag(T lhs, T rhs, T) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    __remill_defer_inlining();
    return lhs < rhs;
  }
};

}  // namespace

#define ClearArithFlags() \
    do { \
      state.aflag.cf = __remill_undefined_bool(); \
      state.aflag.pf = __remill_undefined_bool(); \
      state.aflag.af = __remill_undefined_bool(); \
      state.aflag.zf = __remill_undefined_bool(); \
      state.aflag.sf = __remill_undefined_bool(); \
      state.aflag.of = __remill_undefined_bool(); \
    } while (false)

#endif  // REMILL_ARCH_X86_SEMANTICS_FLAGS_H_
