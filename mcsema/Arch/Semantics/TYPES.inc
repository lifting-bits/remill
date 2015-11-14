/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

struct alignas(16) float80_t {
  long double f;
};
static_assert(16 == sizeof(float80_t), "Invalid `float80_t` size.");

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

[[gnu::used]]
extern "C" bool __mcsema_undefined_bool(void);
