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

#include <cstdint>
#include <limits>
#include <type_traits>

#if defined(__GNUG__) && !defined(__clang__)
#  define COMPILING_WITH_GCC 1
#else
#  define COMPILING_WITH_GCC 0
#endif

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/Definitions.h"

struct State;
struct Memory;

// Address in the source architecture type. We don't use a `uintptr_t` because
// that might be specific to the destination architecture type.
typedef uint32_t addr32_t;
typedef uint64_t addr64_t;
typedef IF_64BIT_ELSE(addr64_t, addr32_t) addr_t;
typedef IF_64BIT_ELSE(int64_t, int32_t) addr_diff_t;

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86) || \
    defined(__arm__)
typedef unsigned uint128_t __attribute__((mode(TI)));
typedef int int128_t __attribute__((mode(TI)));
#elif defined(__aarch64__)
typedef __uint128_t uint128_t;
typedef __int128_t int128_t;
#elif defined(__sparc__)
typedef __uint128_t uint128_t;
typedef __int128_t int128_t;
#else
#  error "Cannot determine (u)int128_t type of unuspported architecture."
#endif

static_assert(16 == sizeof(uint128_t), "Invalid `uint128_t` size.");
static_assert(16 == sizeof(int128_t), "Invalid `int128_t` size.");

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

typedef double float128_t;
static_assert(8 == sizeof(float128_t), "Invalid `float128_t` size.");

// TODO(pag): Assumes little endian.
struct float80_t final {
  uint8_t data[10];
} __attribute__((packed));

static_assert(10 == sizeof(float80_t), "Invalid `float80_t` size.");

union nan32_t {
  float32_t f;
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
  struct {
    uint64_t payload : 51;
    uint64_t is_quiet_nan : 1;
    uint64_t exponent : 11;
    uint64_t is_negative : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(float64_t) == sizeof(nan64_t),
              "Invalid packing of `nan64_t`.");

// Note: We are re-defining the `std::is_signed` type trait because we can't
//       always explicitly specialize it inside of the `std` namespace.

template <typename T>
struct is_signed {
#ifdef __PIN__
  static constexpr bool value = std::tr1::is_signed<T>::value;
#else
  static constexpr bool value = std::is_signed<T>::value;
#endif
};

template <typename T>
struct is_unsigned {
#ifdef __PIN__
  static constexpr bool value = std::tr1::is_unsigned<T>::value;
#else
  static constexpr bool value = std::is_unsigned<T>::value;
#endif
};

template <>
struct is_signed<int128_t> {
  static constexpr bool value = true;
};

template <>
struct is_unsigned<int128_t> {
  static constexpr bool value = false;
};

template <>
struct is_signed<uint128_t> {
  static constexpr bool value = false;
};

template <>
struct is_unsigned<uint128_t> {
  static constexpr bool value = true;
};

template <typename T>
struct VectorType;

template <typename T>
struct VectorType<T &> : public VectorType<T> {};

template <typename T>
struct VectorType<const T> : public VectorType<T> {};

// Forward-declaration of basic vector types.
union vec8_t;
union vec16_t;
union vec32_t;
union vec64_t;
union vec128_t;
union vec256_t;
union vec512_t;

#define MAKE_VECTOR(base_type, prefix, nelems, vec_size_bits, width_bytes) \
  struct prefix##v##nelems##_t final { \
    base_type elems[nelems]; \
  } __attribute__((packed)); \
\
  static_assert(width_bytes == sizeof(prefix##v##nelems##_t), \
                "Invalid definition of `" #prefix "v" #nelems "`."); \
\
  static_assert((width_bytes * 8) == vec_size_bits, \
                "Invalid definition of `" #prefix "v" #nelems "`."); \
\
  template <> \
  struct VectorType<prefix##v##nelems##_t> { \
    enum : std::size_t { kNumElems = nelems }; \
    typedef base_type BT; \
    typedef base_type BaseType; \
    typedef vec##vec_size_bits##_t T; \
    typedef vec##vec_size_bits##_t Type; \
  };

MAKE_VECTOR(uint8_t, uint8, 1, 8, 1)
MAKE_VECTOR(uint8_t, uint8, 2, 16, 2)
MAKE_VECTOR(uint8_t, uint8, 4, 32, 4)
MAKE_VECTOR(uint8_t, uint8, 8, 64, 8)
MAKE_VECTOR(uint8_t, uint8, 16, 128, 16)
MAKE_VECTOR(uint8_t, uint8, 32, 256, 32)
MAKE_VECTOR(uint8_t, uint8, 64, 512, 64)

MAKE_VECTOR(uint16_t, uint16, 1, 16, 2)
MAKE_VECTOR(uint16_t, uint16, 2, 32, 4)
MAKE_VECTOR(uint16_t, uint16, 4, 64, 8)
MAKE_VECTOR(uint16_t, uint16, 8, 128, 16)
MAKE_VECTOR(uint16_t, uint16, 16, 256, 32)
MAKE_VECTOR(uint16_t, uint16, 32, 512, 64)

MAKE_VECTOR(uint32_t, uint32, 1, 32, 4)
MAKE_VECTOR(uint32_t, uint32, 2, 64, 8)
MAKE_VECTOR(uint32_t, uint32, 4, 128, 16)
MAKE_VECTOR(uint32_t, uint32, 8, 256, 32)
MAKE_VECTOR(uint32_t, uint32, 16, 512, 64)

MAKE_VECTOR(uint64_t, uint64, 1, 64, 8)
MAKE_VECTOR(uint64_t, uint64, 2, 128, 16)
MAKE_VECTOR(uint64_t, uint64, 4, 256, 32)
MAKE_VECTOR(uint64_t, uint64, 8, 512, 64)

//MAKE_VECTOR(uint128_t, uint128, 0, 64, 8);
MAKE_VECTOR(uint128_t, uint128, 1, 128, 16)
MAKE_VECTOR(uint128_t, uint128, 2, 256, 32)
MAKE_VECTOR(uint128_t, uint128, 4, 512, 64)

MAKE_VECTOR(int8_t, int8, 1, 8, 1)
MAKE_VECTOR(int8_t, int8, 2, 16, 2)
MAKE_VECTOR(int8_t, int8, 4, 32, 4)
MAKE_VECTOR(int8_t, int8, 8, 64, 8)
MAKE_VECTOR(int8_t, int8, 16, 128, 16)
MAKE_VECTOR(int8_t, int8, 32, 256, 32)
MAKE_VECTOR(int8_t, int8, 64, 512, 64)

MAKE_VECTOR(int16_t, int16, 1, 16, 2)
MAKE_VECTOR(int16_t, int16, 2, 32, 4)
MAKE_VECTOR(int16_t, int16, 4, 64, 8)
MAKE_VECTOR(int16_t, int16, 8, 128, 16)
MAKE_VECTOR(int16_t, int16, 16, 256, 32)
MAKE_VECTOR(int16_t, int16, 32, 512, 64)

MAKE_VECTOR(int32_t, int32, 1, 32, 4)
MAKE_VECTOR(int32_t, int32, 2, 64, 8)
MAKE_VECTOR(int32_t, int32, 4, 128, 16)
MAKE_VECTOR(int32_t, int32, 8, 256, 32)
MAKE_VECTOR(int32_t, int32, 16, 512, 64)

MAKE_VECTOR(int64_t, int64, 1, 64, 8)
MAKE_VECTOR(int64_t, int64, 2, 128, 16)
MAKE_VECTOR(int64_t, int64, 4, 256, 32)
MAKE_VECTOR(int64_t, int64, 8, 512, 64)

//MAKE_VECTOR(int128_t, int128, 0, 64, 8);
MAKE_VECTOR(int128_t, int128, 1, 128, 16)
MAKE_VECTOR(int128_t, int128, 2, 256, 32)
MAKE_VECTOR(int128_t, int128, 4, 512, 64)

MAKE_VECTOR(float, float32, 1, 32, 4)
MAKE_VECTOR(float, float32, 2, 64, 8)
MAKE_VECTOR(float, float32, 4, 128, 16)
MAKE_VECTOR(float, float32, 8, 256, 32)
MAKE_VECTOR(float, float32, 16, 512, 64)

MAKE_VECTOR(double, float64, 1, 64, 8);
MAKE_VECTOR(double, float64, 2, 128, 16);
MAKE_VECTOR(double, float64, 4, 256, 32);
MAKE_VECTOR(double, float64, 8, 512, 64);

#define NumVectorElems(val) \
  static_cast<addr_t>(VectorType<decltype(val)>::kNumElems)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"

union vec8_t final {
  uint8v1_t bytes;
  int8v1_t sbytes;
} __attribute__((packed));

static_assert(1 == sizeof(vec8_t), "Invalid structure packing of `vec8_t`.");

union vec16_t final {
  uint8v2_t bytes;
  uint16v1_t words;

  int8v2_t sbytes;
  int16v1_t swords;
} __attribute__((packed));

static_assert(2 == sizeof(vec16_t), "Invalid structure packing of `vec16_t`.");

union vec32_t final {

  // Make this type look like an `[1 x i32]` to LLVM. This is important for
  // the cross-block alias analysis performed by remill-opt, as it enables
  // remill-opt to more easily handle false dependencies.
  uint32v1_t dwords;

  uint8v4_t bytes;
  uint16v2_t words;
  float32v1_t floats;

  int8v4_t sbytes;
  int16v2_t swords;
  int32v1_t sdwords;
} __attribute__((packed));

static_assert(4 == sizeof(vec32_t), "Invalid structure packing of `vec32_t`.");

union vec64_t final {

  // Make this type look like an `[1 x i64]` to LLVM. This is important for
  // the cross-block alias analysis performed by remill-opt, as it enables
  // remill-opt to more easily handle false dependencies.
  uint64v1_t qwords;

  uint8v8_t bytes;
  uint16v4_t words;
  uint32v2_t dwords;
  float32v2_t floats;
  float64v1_t doubles;

  int8v8_t sbytes;
  int16v4_t swords;
  int32v2_t sdwords;
  int64v1_t sqwords;
} __attribute__((packed));

#pragma clang diagnostic pop

static_assert(8 == sizeof(vec64_t), "Invalid structure packing of `vec64_t`.");

union vec128_t final {

  // Make this type look like an `[1 x i128]` to LLVM. This is important for
  // the cross-block alias analysis performed by remill-opt, as it enables
  // remill-opt to more easily handle false dependencies.
  uint128v1_t dqwords;

  uint8v16_t bytes;
  uint16v8_t words;
  uint32v4_t dwords;
  uint64v2_t qwords;
  float32v4_t floats;
  float64v2_t doubles;

  int8v16_t sbytes;
  int16v8_t swords;
  int32v4_t sdwords;
  int64v2_t sqwords;
  int128v1_t sdqwords;
} __attribute__((packed));

static_assert(16 == sizeof(vec128_t),
              "Invalid structure packing of `vec128_t`.");

union vec256_t final {
  uint8v32_t bytes;
  uint16v16_t words;
  uint32v8_t dwords;
  uint64v4_t qwords;
  uint128v2_t dqwords;
  float32v8_t floats;
  float64v4_t doubles;

  int8v32_t sbytes;
  int16v16_t swords;
  int32v8_t sdwords;
  int64v4_t sqwords;
  int128v2_t sdqwords;
} __attribute__((packed));

static_assert(32 == sizeof(vec256_t),
              "Invalid structure packing of `vec256_t`.");

union vec512_t final {
  uint8v64_t bytes;
  uint16v32_t words;
  uint32v16_t dwords;
  uint64v8_t qwords;
  uint128v4_t dqwords;
  float32v16_t floats;
  float64v8_t doubles;

  int8v64_t sbytes;
  int16v32_t swords;
  int32v16_t sdwords;
  int64v8_t sqwords;
  int128v4_t sdqwords;
} __attribute__((packed));

static_assert(64 == sizeof(vec512_t) && 64 == sizeof(vec512_t().bytes) &&
                  64 == sizeof(vec512_t().words) &&
                  64 == sizeof(vec512_t().dwords) &&
                  64 == sizeof(vec512_t().qwords) &&
                  64 == sizeof(vec512_t().dqwords) &&
                  64 == sizeof(vec512_t().floats) &&
                  64 == sizeof(vec512_t().doubles),
              "Invalid structure packing of `vec512_t`.");

// An n-bit memory reference. This is implemented as an `addr_t`. Part of the
// reason is because pointers have sizes that are architecture-specific, and
// because we want to be able to pass the address through an integer register
// and only access the addressed memory if/when needed.
template <typename T>
struct Mn final {
  addr_t addr;
};

template <typename T>
struct MVn final {
  addr_t addr;
};

template <typename T>
struct MnW final {
  addr_t addr;
};

template <typename T>
struct MVnW final {
  addr_t addr;
};

template <typename T, bool = sizeof(T) <= sizeof(addr_t)>
struct Rn;

// Note: We use `addr_t` as the internal type for `Rn` and `In` struct templates
//       because this will be the default register size used for parameter
//       passing in the underlying ABI that Clang chooses to use when converting
//       this code to bitcode. We want to avoid the issue where a size that's
//       too small, e.g. `uint8_t` or `uint16_t` in a struct, is passed as an
//       aligned pointer to a `byval` parameter.
template <typename T>
struct Rn<T, true> final {
  const addr_t val;
};

template <typename T>
struct Rn<T, false> final {
  const T val;
};

template <typename T>
struct RnW final {
  T *const val_ref;
};

template <>
struct Rn<float32_t> final {
  const float32_t val;
};

template <>
struct Rn<float64_t> final {
  const float64_t val;
};

template <>
struct RnW<float32_t> final {
  float32_t *const val_ref;
};

template <>
struct RnW<float64_t> final {
  float64_t *const val_ref;
};

template <typename T>
struct In final {
  const addr_t val;
};

// Okay so this is *kind of* a hack. The idea is that, in some cases, we want
// to pass things like 32- or 64-bit GPRs to instructions taking in vectors,
// and so it would be nice if those values could masquerade as vectors, even
// though the translator will pass in registers.
template <typename T>
struct RVn;

template <>
struct RVn<vec64_t> final {
  const uint64_t val;  // Must be 64 bits.
};

template <>
struct RVn<vec32_t> final {
  const addr_t val;  // Scales to "natural" machine word length.
};

template <>
struct RVn<vec16_t> final {
  const addr_t val;  // Scales to "natural" machine word length.
};

template <>
struct RVn<vec8_t> final {
  const addr_t val;  // Scales to "natural" machine word length.
};

template <typename T>
struct RVnW;

template <>
struct RVnW<vec32_t> final {
  uint32_t *const val_ref;
};

template <>
struct RVnW<vec64_t> final {
  uint64_t *const val_ref;
};

// A `void` pointer is used so that we can treat different vector types
// uniformly (from the LLVM bitcode side). That is, the type of value passed
// in may be a pointer to a wider vector than was is specified by `T`.
template <typename T>
struct Vn final {
  const void *const val;
};

template <typename T>
struct VnW final {
  void *const val_ref;
};

// Used to figure out the "base type" of an aggregate type (e.g. vector of BT)
// or of an integral/float type.
template <typename T>
struct BaseType {
  typedef T BT;
};

template <>
struct BaseType<float80_t> : public BaseType<float64_t> {};

template <typename T>
struct BaseType<volatile T> : public BaseType<T> {};

template <typename T>
struct BaseType<const T> : public BaseType<T> {};

template <typename T>
struct BaseType<T &> : public BaseType<T> {};

template <typename T>
struct BaseType<T *> : public BaseType<T> {};

template <typename T>
struct BaseType<Mn<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<MnW<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<MVn<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<MVnW<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<Rn<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<RnW<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<In<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<Vn<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<VnW<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<RVn<T>> : public BaseType<T> {};

template <typename T>
struct BaseType<RVnW<T>> : public BaseType<T> {};

template <typename T>
struct NextLargerIntegerType;

template <typename T>
struct NextSmallerIntegerType;

template <typename T>
struct SignedIntegerType;

template <typename T>
struct UnsignedIntegerType;

#define MAKE_SIGNED_INT_CHANGERS(signed_type, unsigned_type) \
  static_assert(sizeof(signed_type) == sizeof(unsigned_type), \
                "Invalid int changer type type."); \
  static_assert( \
      is_signed<signed_type>::value != is_signed<unsigned_type>::value, \
      "Sign match between int type and next int type."); \
  template <> \
  struct SignedIntegerType<unsigned_type> { \
    typedef signed_type BT; \
  }; \
  template <> \
  struct SignedIntegerType<signed_type> { \
    typedef signed_type BT; \
  }; \
  template <> \
  struct UnsignedIntegerType<signed_type> { \
    typedef unsigned_type BT; \
  }; \
  template <> \
  struct UnsignedIntegerType<unsigned_type> { \
    typedef unsigned_type BT; \
  };

#define MAKE_INT_TYPE(cur, next) \
  static_assert(sizeof(next) == (2 * sizeof(cur)), "Invalid next int type."); \
  static_assert(is_signed<cur>::value == is_signed<next>::value, \
                "Sign mismatch between int type and next int type."); \
  template <> \
  struct NextLargerIntegerType<cur> { \
    typedef next BT; \
  }; \
  template <> \
  struct NextSmallerIntegerType<next> { \
    typedef cur BT; \
  };

MAKE_SIGNED_INT_CHANGERS(int8_t, uint8_t)
MAKE_SIGNED_INT_CHANGERS(int16_t, uint16_t)
MAKE_SIGNED_INT_CHANGERS(int32_t, uint32_t)
MAKE_SIGNED_INT_CHANGERS(int64_t, uint64_t)
MAKE_SIGNED_INT_CHANGERS(int128_t, uint128_t)

MAKE_INT_TYPE(int8_t, int16_t)
MAKE_INT_TYPE(uint8_t, uint16_t)

MAKE_INT_TYPE(int16_t, int32_t)
MAKE_INT_TYPE(uint16_t, uint32_t)

MAKE_INT_TYPE(int32_t, int64_t)
MAKE_INT_TYPE(uint32_t, uint64_t)

MAKE_INT_TYPE(int64_t, int128_t)
MAKE_INT_TYPE(uint64_t, uint128_t)

static_assert(sizeof(NextLargerIntegerType<uint8_t>::BT) == 2, "Bad type.");
static_assert(sizeof(NextLargerIntegerType<uint16_t>::BT) == 4, "Bad type.");
static_assert(sizeof(NextLargerIntegerType<uint32_t>::BT) == 8, "Bad type.");
static_assert(sizeof(NextLargerIntegerType<uint64_t>::BT) == 16, "Bad type.");

static_assert(sizeof(NextSmallerIntegerType<uint16_t>::BT) == 1, "Bad type.");
static_assert(sizeof(NextSmallerIntegerType<uint32_t>::BT) == 2, "Bad type.");
static_assert(sizeof(NextSmallerIntegerType<uint64_t>::BT) == 4, "Bad type.");
static_assert(sizeof(NextSmallerIntegerType<uint128_t>::BT) == 8, "Bad type.");

#undef MAKE_SIGNED_INT_CHANGERS
#undef MAKE_INT_TYPE

template <>
struct NextLargerIntegerType<uint128_t> {
  typedef uint128_t BT;
};

template <>
struct NextLargerIntegerType<int128_t> {
  typedef int128_t BT;
};

// General integer type info. Useful for quickly changing between different
// integer types.
template <typename T>
struct IntegerType {
  typedef typename BaseType<T>::BT BT;
  typedef typename UnsignedIntegerType<BT>::BT UT;
  typedef typename SignedIntegerType<BT>::BT ST;

  typedef typename NextLargerIntegerType<BT>::BT WBT;
  typedef typename UnsignedIntegerType<WBT>::BT WUT;
  typedef typename SignedIntegerType<WBT>::BT WST;

  enum : std::size_t { kNumBits = sizeof(BT) * 8 };
};

template <>
struct IntegerType<bool> : public IntegerType<uint8_t> {};

#if __APPLE__

/*
 * In parts of the code, we create IntegerType<size_t>.
 * On OS X, size_t is the same as unsigned long, which is
 * 8 bytes. This code defines IntegerType for size_t.
 */

template <int>
struct SizeTEquivalent;

template <>
struct SizeTEquivalent<4> {
  typedef IntegerType<uint32_t> T;
};

template <>
struct SizeTEquivalent<8> {
  typedef IntegerType<uint64_t> T;
};

template <>
struct IntegerType<size_t> : public SizeTEquivalent<sizeof(size_t)>::T {};

#endif  // __APPLE__

#if !COMPILING_WITH_GCC

inline uint8_t operator"" _u8(unsigned long long value) {
  return static_cast<uint8_t>(value);
}

inline uint16_t operator"" _u16(unsigned long long value) {
  return static_cast<uint16_t>(value);
}

inline uint32_t operator"" _u32(unsigned long long value) {
  return static_cast<uint32_t>(value);
}

inline uint64_t operator"" _u64(unsigned long long value) {
  return static_cast<uint64_t>(value);
}

inline uint64_t operator"" _addr_t(unsigned long long value) {
  return static_cast<addr_t>(value);
}

inline uint128_t operator"" _u128(unsigned long long value) {
  return static_cast<uint128_t>(value);
}


inline int8_t operator"" _s8(unsigned long long value) {
  return static_cast<int8_t>(value);
}

inline int16_t operator"" _s16(unsigned long long value) {
  return static_cast<int16_t>(value);
}

inline int32_t operator"" _s32(unsigned long long value) {
  return static_cast<int32_t>(value);
}

inline int64_t operator"" _s64(unsigned long long value) {
  return static_cast<int64_t>(value);
}

inline int128_t operator"" _s128(unsigned long long value) {
  return static_cast<int128_t>(value);
}

#  define auto_t(T) typename BaseType<T>::BT

#endif  // COMPILING_WITH_GCC

#pragma clang diagnostic pop
