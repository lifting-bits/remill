/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

struct alignas(16) float80_t {
  long double f;
};
static_assert(16 == sizeof(float80_t), "Invalid `float80_t` size.");

typedef uint8_t uint8v8_t __attribute__ ((vector_size (8)));
typedef uint16_t uint16v4_t __attribute__ ((vector_size (8)));
typedef uint32_t uint32v2_t __attribute__ ((vector_size (8)));
typedef uint64_t uint64v1_t __attribute__ ((vector_size (8)));
typedef float32_t float32v2_t __attribute__ ((vector_size (8)));
typedef float64_t float64v1_t __attribute__ ((vector_size (8)));

union vec64_t {
  uint8v8_t bytes;
  uint16v4_t words;
  uint32v2_t dwords;
  uint64v1_t qwords;
  float32v2_t floats;
  float64v1_t doubles;
} __attribute__((packed));

static_assert(8 == sizeof(vec64_t),
              "Invalid structure packing of `vec64_t`.");

typedef uint8_t uint8v16_t __attribute__ ((vector_size (16)));
typedef uint16_t uint16v8_t __attribute__ ((vector_size (16)));
typedef uint32_t uint32v4_t __attribute__ ((vector_size (16)));
typedef uint64_t uint64v2_t __attribute__ ((vector_size (16)));
typedef float32_t float32v4_t __attribute__ ((vector_size (16)));
typedef float64_t float64v2_t __attribute__ ((vector_size (16)));

union vec128_t {
  uint8v16_t bytes;
  uint16v8_t words;
  uint32v4_t dwords;
  uint64v2_t qwords;
  float32v4_t floats;
  float64v2_t doubles;
} __attribute__((packed));

static_assert(16 == sizeof(vec128_t),
              "Invalid structure packing of `vec128_t`.");

typedef uint8_t uint8v32_t __attribute__ ((vector_size (32)));
typedef uint16_t uint16v16_t __attribute__ ((vector_size (32)));
typedef uint32_t uint32v8_t __attribute__ ((vector_size (32)));
typedef uint64_t uint64v4_t __attribute__ ((vector_size (32)));
typedef float32_t float32v8_t __attribute__ ((vector_size (32)));
typedef float64_t float64v4_t __attribute__ ((vector_size (32)));

union vec256_t {
  uint8v32_t bytes;
  uint16v16_t words;
  uint32v8_t dwords;
  uint64v4_t qwords;
  float32v8_t floats;
  float64v4_t doubles;
} __attribute__((packed));

static_assert(32 == sizeof(vec256_t),
              "Invalid structure packing of `vec256_t`.");

typedef uint8_t uint8v64_t __attribute__ ((vector_size (64)));
typedef uint16_t uint16v32_t __attribute__ ((vector_size (64)));
typedef uint32_t uint32v16_t __attribute__ ((vector_size (64)));
typedef uint64_t uint64v8_t __attribute__ ((vector_size (64)));
typedef float32_t float32v16_t __attribute__ ((vector_size (64)));
typedef float64_t float64v8_t __attribute__ ((vector_size (64)));

union vec512_t {
  uint8v64_t bytes;
  uint16v32_t words;
  uint32v16_t dwords;
  uint64v8_t qwords;
  float32v16_t floats;
  float64v8_t doubles;
} __attribute__((packed));

static_assert(64 == sizeof(vec512_t),
              "Invalid structure packing of `vec512_t`.");

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
    template <> \
    struct SignedIntegerType<unsigned_type> { \
      typedef signed_type Type ; \
    }; \
    template <> \
    struct UnsignedIntegerType<signed_type> { \
      typedef unsigned_type Type ; \
    }

#define MAKE_INT_TYPE(cur, next) \
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

MAKE_INT_TYPE(int8_t, int16_t);
MAKE_INT_TYPE(uint8_t, uint16_t);

MAKE_INT_TYPE(int16_t, int32_t);
MAKE_INT_TYPE(uint16_t, uint32_t);

MAKE_INT_TYPE(int32_t, int64_t);
MAKE_INT_TYPE(uint32_t, uint64_t);

#if 64 == ADDRESS_SIZE_BITS
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
static_assert(16 == sizeof(int128_t), "Invalid size of `int128_t`.");
static_assert(16 == sizeof(uint128_t), "Invalid size of `uint128_t`.");
MAKE_INT_TYPE(int64_t, int128_t);
MAKE_INT_TYPE(uint64_t, uint128_t);
MAKE_SIGNED_INT_CHANGERS(int128_t, uint128_t);
#endif  // 64 == ADDRESS_SIZE_BITS

#undef MAKE_SIGNED_INT_CHANGERS
#undef MAKE_INT_TYPE


template <typename T>
struct Mn {
  const uintptr_t addr;
};

template <typename T>
struct MnW {
  const uintptr_t addr;
};

template <typename T>
struct Rn {
  const T val;
};

template <typename T>
struct RnW {
  T &val_ref;
};

extern "C" void __escape(void *);

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
struct BaseType<Vn<T>> {
  typedef typename BaseType<T>::Type Type;
};

template <typename T>
struct BaseType<VnW<T>> {
  typedef typename BaseType<T>::Type Type;
};

[[gnu::used]]
extern "C" bool __mcsema_undefined_bool(void);
