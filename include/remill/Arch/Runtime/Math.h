/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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

#include "Definitions.h"
#include "Builtin.h"
#include "Int.h"

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

typedef double float128_t;
static_assert(8 == sizeof(float128_t), "Invalid `float128_t` size.");

// a long double can be anything from a 128-bit float (on AArch64/Linux) to a 64-bit double (AArch64 MacOS)
// to an 80-bit precision wrapped with padding (x86/x86-64). We do not do a static assert on the size
// since there are too  many options.

// A "native_float80_t" is a native type that is closes to approximating
// an x86 80-bit float.
// when building against CUDA, default to 64-bit float80s
#if !defined(__CUDACC__) && !defined(WIN32) && (defined(__x86_64__) || defined(__i386__) || defined(_M_X86))
  #if defined(__float80)
  typedef __float80 native_float80_t;
  #else
  typedef long double native_float80_t;
  #endif
static_assert(10 <= sizeof(native_float80_t), "Invalid `native_float80_t` size.");
#else
  typedef double native_float80_t;
  static_assert(8 == sizeof(native_float80_t), "Invalid `native_float80_t` size.");
#endif

static const int kEightyBitsInBytes = 10;
union union_ld {
  struct {
    uint8_t data[kEightyBitsInBytes];
    // when building against CUDA, default to 64-bit float80s
#if !defined(__CUDACC__) && !defined(WIN32) && (defined(__x86_64__) || defined(__i386__) || defined(_M_X86))
    // We are doing x86 on x86, so we have native x86 FP80s, but they
    // are not available in raw 80-bit native form.
    //
    // To get to the internal FP80 representation, we have to use a
    // `long double` which is (usually! but not always)
    //  an FP80 padded to a 12 or 16 byte boundary
    //
    uint8_t padding[sizeof(native_float80_t) - kEightyBitsInBytes];
#else
    // The closest native FP type that we can easily deal with is a 64-bit double
    // this is less than the size of an FP80, so the data variable above will already
    // enclose it. No extra padding is needed
#endif
  } lds __attribute__((packed));
  native_float80_t ld;
} __attribute__((packed));

static void *memset_impl(void *b, int c, std::size_t len) {
  auto *p = static_cast<int *>(b);
  for (std::size_t i = 0; i < len; ++i) {
    p[i] = c;
  }
  return b;
}

static void *memcpy_impl(void *dst, const void *src, std::size_t n) {
  auto *d = static_cast<int *>(dst);
  const auto *s = static_cast<const int *>(src);
  for (std::size_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
}

struct float80_t final {
  uint8_t data[kEightyBitsInBytes];

  inline ~float80_t(void) = default;
  inline float80_t(void) : data{0,} {}

  float80_t(const float80_t &) = default;
  float80_t &operator=(const float80_t &) = default;

  inline float80_t(native_float80_t ld) {
    union_ld ldu;
    memset_impl(&ldu, 0, sizeof(ldu)); // zero out ldu to make padding consistent
    ldu.ld = ld; // assign native value
    // copy the representation to this object
    memcpy_impl(&data[0], &ldu.lds.data[0], sizeof(data));
  }

  operator native_float80_t() {
    union_ld ldu;
    memset_impl(&ldu, 0, sizeof(ldu)); // zero out ldu to make padding consistent
    // copy the internal representation into the union
    memcpy_impl(&ldu.lds.data[0], &data[0], sizeof(data));
    // extract the native backing type from it
    return ldu.ld;
  }
} __attribute__((packed));

union nan32_t {
  float32_t f;
  uint32_t flat;
  struct {
    uint32_t payload : 22;
    uint32_t is_quiet_nan : 1;
    uint32_t exponent : 8;
    uint32_t is_negative : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(float32_t) == sizeof(nan32_t),
              "Invalid packing of `nan32_t`.");

union nan64_t {
  float64_t d;
  uint64_t flat;
  struct {
    uint64_t payload : 51;
    uint64_t is_quiet_nan : 1;
    uint64_t exponent : 11;
    uint64_t is_negative : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(float64_t) == sizeof(nan64_t),
              "Invalid packing of `nan64_t`.");

union nan80_t {
  float80_t d;
  struct {
    uint64_t payload : 62;
    uint64_t  is_quiet_nan : 1;
    uint64_t  interger_bit : 1;
    uint64_t exponent : 15;
    uint64_t is_negative : 1;
  } __attribute__((packed));
} __attribute__((packed));

//static_assert(sizeof(float80_t) == sizeof(nan80_t), "Invalid packing of `nan80_t`.");

#if __has_include(<cmath>)
#  include <cmath>
#else

#ifndef FP_NORMAL
#  define FP_NORMAL 4
#endif

#ifndef FP_SUBNORMAL
#  define FP_SUBNORMAL 3
#endif

#ifndef FP_ZERO
#  define FP_ZERO 2
#endif

#ifndef FP_INFINITE
#  define FP_INFINITE 1
#endif

#ifndef FP_NAN
#  define FP_NAN 0
#endif

namespace remill_std {

ALWAYS_INLINE static bool signbit(float arg) {
#  if __has_builtin(__builtin_signbitf)
  return __builtin_signbitf(arg);
#  else
  nan32_t x = {arg};
  return x.is_negative;
#  endif
}

ALWAYS_INLINE static bool signbit(double arg) {
#  if __has_builtin(__builtin_signbit)
  return __builtin_signbit(arg);
#  else
  nan64_t x = {arg};
  return x.is_negative;
#  endif
}

ALWAYS_INLINE static bool signbit(long double arg) {
#  if __has_builtin(__builtin_signbitl)
  return __builtin_signbitl(arg);
#  else
#    error "Unsupported operation"
#  endif
}

template <typename T>
ALWAYS_INLINE static bool signbit(T val) {
  return (val >> (sizeof(T) - 1u)) & 1;
}

ALWAYS_INLINE static int fpclassify(float32_t x) {
#if __has_builtin(__builtin_fpclassify)
  return __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x);
#else
  nan32_t bits = {x};

#if __has_builtin(__builtin_isnan)
  if (__builtin_isnan(x)) {
#else
  if ((0x7F800001u <= bits.flat && bits.flat <= 0x7FBFFFFFu) ||
             (0xFF800001u <= bits.flat && bits.flat <= 0xFFBFFFFFu) ||
             (0x7FC00000u <= bits.flat && bits.flat <= 0x7FFFFFFFu) ||
             (0xFFC00000u <= bits.flat && bits.flat <= 0xFFFFFFFFu)) {
#endif
    return FP_NAN;

#if __has_builtin(__builtin_isinf)
  } else if (__builtin_isinf(x)) {
#else
  } else if (0x7F800000u == bits.flat || 0xFF800000u == bits.flat) {
#endif
    return FP_INFINITE;

  } else if (!x) {
    return FP_ZERO;
#if __has_builtin(__builtin_isnormal)
  } else if (!__builtin_isnormal(x)) {
#else
  } else if (!bits.exponent) {
#endif
  }
    return FP_SUBNORMAL;
  } else {
    return FP_NORMAL;
  }
#endif
}

ALWAYS_INLINE static int fpclassify(float64_t x) {
#if __has_builtin(__builtin_fpclassify)
  return __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL, FP_ZERO, x);
#else
  nan64_t bits = {x};

#if __has_builtin(__builtin_isnan)
  if (__builtin_isnan(x)) {
#else
  if ((0x7FF0000000000001 <= bits.flat &&
       bits.flat <= 0x7FF7FFFFFFFFFFFFull) ||
      (0xFFF0000000000001ull <= bits.flat &&
       bits.flat <= 0xFFF7FFFFFFFFFFFFull) ||
      (0x7FF8000000000000ull <= bits.flat &&
       bits.flat <= 0x7FFFFFFFFFFFFFFFull) ||
      (0xFFF8000000000000ull <= bits.flat &&
       bits.flat <= 0xFFFFFFFFFFFFFFFFull)) {
#endif
    return FP_NAN;

#if __has_builtin(__builtin_isinf)
  } else if (__builtin_isinf(x)) {
#else
  } else if (0x7FF0000000000000ull == bits.flat ||
             0xFFF0000000000000ull == bits.flat) {
#endif
  }
    return FP_INFINITE;

  } else if (!x) {
    return FP_ZERO;

#if __has_builtin(__builtin_isnormal)
  } else if (!__builtin_isnormal(x)) {
#else
  } else if (!bits.exponent) {
#endif
    return FP_SUBNORMAL;

  } else {
    return FP_NORMAL;
  }
#endif
}

}  // namespace remill_std
namespace std {
using namespace remill_std;
}  // namespace std

#endif  // `__has_include(<cmath>)`
