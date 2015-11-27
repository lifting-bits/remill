/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_SEMANTICS_TYPES_H_
#define MCSEMA_ARCH_SEMANTICS_TYPES_H_

#include <cstdint>
#include <type_traits>

#include "mcsema/Arch/Semantics/MACROS.h"

struct State;

// Address in the source architecture type. We don't use a `uintptr_t` because
// that might be specific to the destination architecture type.
typedef IF_64BIT_ELSE(uint64_t, uint32_t) addr_t;

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

struct alignas(16) float80_t {
  long double f;
};
static_assert(16 == sizeof(float80_t), "Invalid `float80_t` size.");

typedef unsigned uint128_t __attribute__((mode(TI)));
static_assert(16 == sizeof(uint128_t), "Invalid `uint128_t` size.");

typedef int int128_t __attribute__((mode(TI)));
static_assert(16 == sizeof(int128_t), "Invalid `int128_t` size.");

// Add in some missing type traits.
namespace std {

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


}  // namespace

template <typename T>
struct VectorInfo;

// Forward-declaration of basic vector types.
union vec64_t;
union vec128_t;
union vec256_t;
union vec512_t;

// TODO(pag): See if using the `ext_vector_type` attribute (OpenCL) produces
//            better code. These might also work better with NEON because they
//            support different kinds of selectors (`xyzw`).
#define MAKE_VECTOR(base_type, nelms, vec_size_bits, width_bytes) \
    typedef base_type ## _t base_type ## v ## nelms ## _t \
        __attribute__((vector_size(width_bytes))); \
    static_assert(width_bytes == sizeof(base_type ## v ## nelms ## _t), \
        "Invalid definition of `" #base_type "v" #nelms "`."); \
    static_assert((width_bytes * 8) == vec_size_bits, \
            "Invalid definition of `" #base_type "v" #nelms "`."); \
    template <> \
    struct VectorInfo<base_type ## v ## nelms ## _t> { \
      enum { \
        kNumElms = nelms \
      }; \
      typedef base_type ## _t BaseType; \
      typedef vec ## vec_size_bits ## _t VecType; \
    }

MAKE_VECTOR(uint8, 8, 64, 8);
MAKE_VECTOR(uint8, 16, 128, 16);
MAKE_VECTOR(uint8, 32, 256, 32);
MAKE_VECTOR(uint8, 64, 512, 64);

MAKE_VECTOR(uint16, 4, 64, 8);
MAKE_VECTOR(uint16, 8, 128, 16);
MAKE_VECTOR(uint16, 16, 256, 32);
MAKE_VECTOR(uint16, 32, 512, 64);

MAKE_VECTOR(uint32, 2, 64, 8);
MAKE_VECTOR(uint32, 4, 128, 16);
MAKE_VECTOR(uint32, 8, 256, 32);
MAKE_VECTOR(uint32, 16, 512, 64);

MAKE_VECTOR(uint64, 1, 64, 8);
MAKE_VECTOR(uint64, 2, 128, 16);
MAKE_VECTOR(uint64, 4, 256, 32);
MAKE_VECTOR(uint64, 8, 512, 64);

//MAKE_VECTOR(uint128, 0, 64, 8);
MAKE_VECTOR(uint128, 1, 128, 16);
MAKE_VECTOR(uint128, 2, 256, 32);
MAKE_VECTOR(uint128, 4, 512, 64);

MAKE_VECTOR(float32, 2, 64, 8);
MAKE_VECTOR(float32, 4, 128, 16);
MAKE_VECTOR(float32, 8, 256, 32);
MAKE_VECTOR(float32, 16, 512, 64);

MAKE_VECTOR(float64, 1, 64, 8);
MAKE_VECTOR(float64, 2, 128, 16);
MAKE_VECTOR(float64, 4, 256, 32);
MAKE_VECTOR(float64, 8, 512, 64);

union vec64_t {
  uint8v8_t bytes;
  uint16v4_t words;
  uint32v2_t dwords;
  uint64v1_t qwords;

  IF_64BIT_ELSE(uint64v1_t, uint32v2_t) iwords;  // Ideal.

  float32v2_t floats;
  float64v1_t doubles;

  // Note: This is a special case for consistency in `VecWriter`. In practice
  //       this should never be used.
  struct alignas(1) {} dqwords[8];

} __attribute__((packed));

static_assert(8 == sizeof(vec64_t) &&
              8 == sizeof(vec64_t().bytes) &&
              8 == sizeof(vec64_t().words) &&
              8 == sizeof(vec64_t().dwords) &&
              8 == sizeof(vec64_t().qwords) &&
              8 == sizeof(vec64_t().dqwords) &&
              8 == sizeof(vec64_t().floats) &&
              8 == sizeof(vec64_t().doubles) &&
              8 == sizeof(vec64_t().iwords),
              "Invalid structure packing of `vec64_t`.");

union vec128_t {
  ALWAYS_INLINE vec128_t(void);
  ALWAYS_INLINE vec128_t(const vec64_t &&sub_vec);

  uint8v16_t bytes;
  uint16v8_t words;
  uint32v4_t dwords;
  uint64v2_t qwords;

  IF_64BIT_ELSE(uint64v2_t, uint32v4_t) iwords;  // Ideal.

  uint128v1_t dqwords;
  float32v4_t floats;
  float64v2_t doubles;
} __attribute__((packed));

static_assert(16 == sizeof(vec128_t) &&
              16 == sizeof(vec128_t().bytes) &&
              16 == sizeof(vec128_t().words) &&
              16 == sizeof(vec128_t().dwords) &&
              16 == sizeof(vec128_t().qwords) &&
              16 == sizeof(vec128_t().dqwords) &&
              16 == sizeof(vec128_t().floats) &&
              16 == sizeof(vec128_t().doubles) &&
              16 == sizeof(vec128_t().iwords),
              "Invalid structure packing of `vec128_t`.");

union vec256_t {
  ALWAYS_INLINE vec256_t(void);
  ALWAYS_INLINE vec256_t(const vec64_t &&sub_vec);
  ALWAYS_INLINE vec256_t(const vec128_t &&sub_vec);

  uint8v32_t bytes;
  uint16v16_t words;
  uint32v8_t dwords;
  uint64v4_t qwords;
  uint128v2_t dqwords;

  IF_64BIT_ELSE(uint64v4_t, uint32v8_t) iwords;  // Ideal.

  float32v8_t floats;
  float64v4_t doubles;
} __attribute__((packed));


static_assert(32 == sizeof(vec256_t) &&
              32 == sizeof(vec256_t().bytes) &&
              32 == sizeof(vec256_t().words) &&
              32 == sizeof(vec256_t().dwords) &&
              32 == sizeof(vec256_t().qwords) &&
              32 == sizeof(vec256_t().dqwords) &&
              32 == sizeof(vec256_t().floats) &&
              32 == sizeof(vec256_t().doubles) &&
              32 == sizeof(vec256_t().iwords),
              "Invalid structure packing of `vec256_t`.");

union vec512_t {
  ALWAYS_INLINE vec512_t(void);
  ALWAYS_INLINE vec512_t(const vec64_t &&sub_vec);
  ALWAYS_INLINE vec512_t(const vec128_t &&sub_vec);
  ALWAYS_INLINE vec512_t(const vec256_t &&sub_vec);

  uint8v64_t bytes;
  uint16v32_t words;
  uint32v16_t dwords;
  uint64v8_t qwords;
  uint128v4_t dqwords;

  uint128v4_t iwords;  // Ideal.

  float32v16_t floats;
  float64v8_t doubles;
} __attribute__((packed));

static_assert(64 == sizeof(vec512_t) &&
              64 == sizeof(vec512_t().bytes) &&
              64 == sizeof(vec512_t().words) &&
              64 == sizeof(vec512_t().dwords) &&
              64 == sizeof(vec512_t().qwords) &&
              64 == sizeof(vec512_t().dqwords) &&
              64 == sizeof(vec512_t().floats) &&
              64 == sizeof(vec512_t().doubles) &&
              64 == sizeof(vec512_t().iwords),
              "Invalid structure packing of `vec512_t`.");

// Aligned vector types.
typedef vec128_t avec128_t __attribute__((aligned(64)));
typedef vec256_t avec256_t __attribute__((aligned(64)));
typedef vec512_t avec512_t __attribute__((aligned(64)));

template <typename T>
struct NextLargerIntegerType;

template <typename T>
struct NextSmallerIntegerType;

template <typename T>
struct SignedIntegerType {
  typedef T Type;
};

template <typename T>
struct UnsignedIntegerType {
  typedef T Type;
};

#define MAKE_SIGNED_INT_CHANGERS(signed_type, unsigned_type) \
    static_assert(sizeof(signed_type) == sizeof(unsigned_type), \
                  "Invalid int changer type type."); \
    static_assert(std::is_signed<signed_type>::value != \
                  std::is_signed<unsigned_type>::value, \
                  "Sign match between int type and next int type."); \
    template <> \
    struct SignedIntegerType<unsigned_type> { \
      typedef signed_type Type ; \
    }; \
    template <> \
    struct UnsignedIntegerType<signed_type> { \
      typedef unsigned_type Type ; \
    }

#define MAKE_INT_TYPE(cur, next) \
    static_assert(sizeof(next) == (2 * sizeof(cur)), \
                  "Invalid next int type."); \
    static_assert(std::is_signed<cur>::value == std::is_signed<next>::value, \
                  "Sign mismatch between int type and next int type."); \
    template <> \
    struct NextLargerIntegerType<cur> { \
      typedef next Type; \
    }; \
    template <> \
    struct NextSmallerIntegerType<next> { \
      typedef cur Type; \
    }

MAKE_SIGNED_INT_CHANGERS(int8_t, uint8_t);
MAKE_SIGNED_INT_CHANGERS(int16_t, uint16_t);
MAKE_SIGNED_INT_CHANGERS(int32_t, uint32_t);
MAKE_SIGNED_INT_CHANGERS(int64_t, uint64_t);
MAKE_SIGNED_INT_CHANGERS(int128_t, uint128_t);

MAKE_INT_TYPE(int8_t, int16_t);
MAKE_INT_TYPE(uint8_t, uint16_t);

MAKE_INT_TYPE(int16_t, int32_t);
MAKE_INT_TYPE(uint16_t, uint32_t);

MAKE_INT_TYPE(int32_t, int64_t);
MAKE_INT_TYPE(uint32_t, uint64_t);

MAKE_INT_TYPE(int64_t, int128_t);
MAKE_INT_TYPE(uint64_t, uint128_t);

#undef MAKE_SIGNED_INT_CHANGERS
#undef MAKE_INT_TYPE

template <typename T>
struct Mn {
  const addr_t addr;
};

template <typename T>
struct MnW {
  const addr_t addr;
};

template <typename T>
struct Rn {
  const T val;
};

template <typename T>
struct RnW {
  T &val_ref;
};

template <typename T>
struct In {
  const T val;
};

template <typename T>
struct Vn {
  const T &val;
};

template <typename T>
struct VnW {
  T &val_ref;
};

template <typename T>
struct BaseType {
  typedef T Type;
};

template <typename T>
struct BaseType<volatile T> : public BaseType<T> {};

template <typename T>
struct BaseType<const T> : public BaseType<T> {};

template <typename T>
struct BaseType<T &> : public BaseType<T> {};

template <typename T>
struct BaseType<T *> : public BaseType<T> {};

template <typename T>
struct BaseType<Mn<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<MnW<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<Rn<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<RnW<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<In<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<Vn<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<VnW<T>> {
  typedef typename BaseType<T>::Type Type;
};

#endif  // MCSEMA_ARCH_SEMANTICS_TYPES_H_
