/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

namespace {

// Zero flags, tells us whether or not a value is zero.
template <typename T, typename S1, typename S2>
[[gnu::const]] ALWAYS_INLINE static bool ZeroFlag(T res, S1 lhs, S2 rhs) {
  return __remill_flag_computation_zero(T(0) == res, lhs, rhs, res);
}

// Zero flags, tells us whether or not a value is zero.
template <typename T, typename S1, typename S2>
[[gnu::const]] ALWAYS_INLINE static bool NotZeroFlag(T res, S1 lhs, S2 rhs) {
  return !__remill_flag_computation_zero(T(0) == res, lhs, rhs, res);
}

// Sign flag, tells us if a result is signed or unsigned.
template <typename T, typename S1, typename S2>
[[gnu::const]] ALWAYS_INLINE static bool SignFlag(T res, S1 lhs, S2 rhs) {
  return __remill_flag_computation_sign(0 > Signed(res), lhs, rhs, res);
}

// Tests whether there is an even number of bits in the low order byte.
[[gnu::const]] ALWAYS_INLINE static bool ParityFlag(uint8_t r0) {
  return !__builtin_parity(static_cast<unsigned>(r0));

  //  auto r1 = r0 >> 1_u8;
  //  auto r2 = r1 >> 1_u8;
  //  auto r3 = r2 >> 1_u8;
  //  auto r4 = r3 >> 1_u8;
  //  auto r5 = r4 >> 1_u8;
  //  auto r6 = r5 >> 1_u8;
  //  auto r7 = r6 >> 1_u8;
  //
  //  return !(1 & (r0 ^ r1 ^ r2 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7));
}

struct tag_add {};
struct tag_sub {};
struct tag_sdiv {};
struct tag_udiv {};
struct tag_mul {};

// Generic overflow flag.
template <typename T>
struct Overflow;

// Computes an overflow flag when two numbers are added together.
template <>
struct Overflow<tag_add> {
  template <typename T>
  [[gnu::const]] ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for addition.");
    enum { kSignShift = sizeof(T) * 8 - 1 };

    // Overflow occurs on addition if both operands have the same sign and
    // the sign of the sum is different.

    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return __remill_flag_computation_overflow(
        2 == ((sign_lhs ^ sign_res) + (sign_rhs ^ sign_res)), lhs, rhs, res);
  }
};

// Computes an overflow flag when one number is subtracted from another.
template <>
struct Overflow<tag_sub> {
  template <typename T>
  [[gnu::const]] ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Overflow::Flag` for "
                  "subtraction.");
    enum { kSignShift = sizeof(T) * 8 - 1 };

    // Overflow occurs on subtraction if the operands have different signs and
    // the sign of the difference differs from the sign of r[rs1].

    const T sign_lhs = lhs >> kSignShift;
    const T sign_rhs = rhs >> kSignShift;
    const T sign_res = res >> kSignShift;
    return __remill_flag_computation_overflow(
        2 == ((sign_lhs ^ sign_rhs) + (sign_lhs ^ sign_res)), lhs, rhs, res);
  }
};

// Computes an overflow flag when one number is multiplied with another.
template <>
struct Overflow<tag_mul> {

  // Integer multiplication overflow check, where result is twice the width of
  // the operands.
  template <typename T, typename R>
  [[gnu::const]] ALWAYS_INLINE static bool
  Flag(T lhs, T rhs, R res,
       typename std::enable_if<sizeof(T) < sizeof(R), int>::type = 0) {

    return __remill_flag_computation_overflow(
        static_cast<R>(static_cast<T>(res)) != res, lhs, rhs, res);
  }

  // Signed integer multiplication overflow check, where the result is
  // truncated to the size of the operands.
  template <typename T>
  [[gnu::const]] ALWAYS_INLINE static bool
  Flag(T lhs, T rhs, T,
       typename std::enable_if<std::is_signed<T>::value, int>::type = 0) {
    auto lhs_wide = SExt(lhs);
    auto rhs_wide = SExt(rhs);
    return Flag<T, decltype(lhs_wide)>(lhs, rhs, lhs_wide * rhs_wide);
  }
};

// Computes an overflow flag when one number is divided by another.
template <>
struct Overflow<tag_sdiv> {
  template <typename T, typename R>
  [[gnu::const]] ALWAYS_INLINE static bool
  Flag(T lhs, T rhs, R res,
       typename std::enable_if<sizeof(T) < sizeof(R), int>::type = 0) {

    enum { kSignShift = sizeof(T) * 8 - 1 };

    return __remill_flag_computation_overflow(
        (SExt(res << kSignShift) > 0) || (SExt(res << kSignShift) < -1), lhs,
        rhs, res);
  }

  template <typename T, typename R>
  [[gnu::const]] ALWAYS_INLINE static R
  Value(T lhs, T rhs, R res,
        typename std::enable_if<sizeof(T) < sizeof(R), int>::type = 0) {

    enum { kSignShift = sizeof(T) * 8 - 1 };

    enum : R { kValueMax = static_cast<R>(1) << sizeof(T) * 8 };

    if (SExt(res << kSignShift) > 0) {
      return kValueMax - 1;
    } else if (SExt(res << kSignShift) < -1) {
      return SNeg(kValueMax);
    } else {
      return res;
    }
  }
};

template <>
struct Overflow<tag_udiv> {
  template <typename T, typename R>
  [[gnu::const]] ALWAYS_INLINE static bool
  Flag(T lhs, T rhs, R res,
       typename std::enable_if<sizeof(T) < sizeof(R), int>::type = 0) {

    enum { kShift = sizeof(T) * 8 };

    return __remill_flag_computation_overflow((SExt(res << kShift) > 0), lhs,
                                              rhs, res);
  }

  template <typename T, typename R>
  [[gnu::const]] ALWAYS_INLINE static R
  Value(T lhs, T rhs, R res,
        typename std::enable_if<sizeof(T) < sizeof(R), int>::type = 0) {

    enum { kShift = sizeof(T) * 8 };

    enum : R { kValueMax = static_cast<R>(1) << sizeof(T) * 8 };

    if (SExt(res << kShift) > 0) {
      return kValueMax - 1;
    } else {
      return res;
    }
  }
};

// Generic carry flag.
template <typename Tag>
struct Carry;

// Computes an carry flag when two numbers are added together.
template <>
struct Carry<tag_add> {
  template <typename T>
  [[gnu::const]] ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    return __remill_flag_computation_carry(res < lhs || res < rhs, lhs, rhs,
                                           res);
  }
};

// Computes an carry flag when one number is subtracted from another.
template <>
struct Carry<tag_sub> {
  template <typename T>
  [[gnu::const]] ALWAYS_INLINE static bool Flag(T lhs, T rhs, T res) {
    static_assert(std::is_unsigned<T>::value,
                  "Invalid specialization of `Carry::Flag` for addition.");
    return __remill_flag_computation_carry(lhs < rhs, lhs, rhs, res);
  }
};

ALWAYS_INLINE void SetFPSRStatusFlags(State &state, int mask) {
  state.fsr.aexc |= static_cast<uint8_t>(mask & FE_ALL_EXCEPT);
  state.fsr.cexc = static_cast<uint8_t>(mask & FE_ALL_EXCEPT);
}

}  // namespace
