/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Runtime/Runtime.h"

#ifndef HAS_FEATURE_AVX
# define HAS_FEATURE_AVX 1
#endif

#ifndef HAS_FEATURE_AVX512
# define HAS_FEATURE_AVX512 1
#endif

#if HAS_FEATURE_AVX
#define IF_AVX(...) __VA_ARGS__
#define IF_AVX_ELSE(a, b) a
#else
#define IF_AVX(...)
#define IF_AVX_ELSE(a, b) b
#endif

#if HAS_FEATURE_AVX && HAS_FEATURE_AVX512
#define IF_AVX512(...) __VA_ARGS__
#define IF_AVX512_ELSE(a, b) a
#else
#define IF_AVX512(...)
#define IF_AVX512_ELSE(a, b) b
#endif

#if HAS_FEATURE_AVX && HAS_FEATURE_AVX512
#define AVX_SEL_XYZ(tail) Z ## tail
#define AVX_SEL_xyz(tail) z ## tail
#elif HAS_FEATURE_AVX
#define AVX_SEL_XYZ(tail) Y ## tail
#define AVX_SEL_xyz(tail) y ## tail
#else
#define AVX_SEL_XYZ(tail) X ## tail
#define AVX_SEL_xyz(tail) x ## tail
#endif

union FPUStatusWord {
  struct {
    uint16_t ie:1;  // bit 0
    uint16_t de:1;
    uint16_t ze:1;
    uint16_t oe:1;
    uint16_t ue:1;  // bit 4
    uint16_t pe:1;
    uint16_t sf:1;
    uint16_t es:1;
    uint16_t c0:1;  // bit 8
    uint16_t c1:1;
    uint16_t c2:1;
    uint16_t top:3;
    uint16_t c3:1;
    uint16_t b:1;
  } __attribute__((packed)) u;
  uint16_t flat;
} __attribute__((packed));

static_assert(2 == sizeof(FPUStatusWord),
              "Invalid structure packing of `FPUFlags`.");

union FPUControlWord {
  struct {
    uint16_t im:1;  // bit 0
    uint16_t dm:1;
    uint16_t zm:1;
    uint16_t om:1;
    uint16_t um:1;  // bit 4
    uint16_t pm:1;
    uint16_t _rsvd0:2;
    uint16_t pc:2;  // bit 8
    uint16_t rc:2;
    uint16_t x:1;
    uint16_t _rsvd1:3;
  } __attribute__((packed)) u;
  uint16_t flat;
} __attribute__((packed));

static_assert(2 == sizeof(FPUControlWord),
              "Invalid structure packing of `FPUControl`.");

union FPUStackElem {
  float80_t st;
  double mmx;
};

// FP register state that conforms with `FXSAVE`.
struct FPU {
  FPUControlWord cwd;
  FPUStatusWord swd;
  uint8_t ftw;
  uint8_t _rsvd0;
  uint16_t fop;
  uint32_t ip;
  uint16_t cs;
  uint16_t _rsvd1;
  uint32_t dp;
  uint16_t ds;
  uint16_t _rsvd2;
  uint32_t mxcsr;
  uint32_t mxcr_mask;
  float80_t st[8];   // 8*16 bytes for each FP reg = 128 bytes.

  // Note: This is consistent with `fxsave64`, but doesn't handle things like
  //       ZMM/YMM registers. Therefore, we use a different set of registers
  //       for those.
  vec128_t xmm[16];  // 16*16 bytes for each XMM reg = 256 bytes.
  uint32_t padding[24];
} __attribute__((packed));

static_assert(512 == sizeof(FPU), "Invalid structure packing of `FPU`.");

struct Flags {
  uint32_t cf:1;  // bit 0.
  uint32_t must_be_1:1;
  uint32_t pf:1;
  uint32_t must_be_0a:1;

  uint32_t af:1; // bit 4.
  uint32_t must_be_0b:1;
  uint32_t zf:1;
  uint32_t sf:1;

  uint32_t tf:1;  // bit 8.
  uint32_t _if:1;  // underscore to avoid token clash.
  uint32_t df:1;
  uint32_t of:1;

  uint32_t iopl:2; // A 2-bit field, bits 12-13.
  uint32_t nt:1;
  uint32_t must_be_0c:1;

  uint32_t rf:1; // bit 16.
  uint32_t vm:1;
  uint32_t ac:1;
  uint32_t vif:1;

  uint32_t vip:1; // bit 20.
  uint32_t id:1;   // bit 21.
  uint32_t reserved_eflags:10;  // bits 22-31.
  uint32_t reserved_rflags;  // bits 32-63.
} __attribute__((packed));

static_assert(8 == sizeof(Flags), "Invalid structure packing of `Flags`.");

struct alignas(8) ArithFlags {
  bool cf;
  bool pf;
  bool af;
  bool zf;
  bool sf;
  bool df;
  bool of;
  bool _unused1;
} __attribute__((packed));

static_assert(8 == sizeof(ArithFlags), "Invalid packing of `ArithFlags`.");

struct alignas(8) Segments {
  uint16_t ss;
  uint16_t es;
  uint16_t gs;
  uint16_t fs;
  uint16_t ds;
  uint16_t cs;
  uint16_t _unused1;
  uint16_t _unused2;
};

union Reg {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(8) uint64_t qword;
} __attribute__((packed));

static_assert(sizeof(uint64_t) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, byte.low),
              "Invalid packing of `Reg::low`.");
static_assert(1 == __builtin_offsetof(Reg, byte.high),
              "Invalid packing of `Reg::high`.");
static_assert(0 == __builtin_offsetof(Reg, word),
              "Invalid packing of `Reg::word`.");
static_assert(0 == __builtin_offsetof(Reg, dword),
              "Invalid packing of `Reg::dword`.");
static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");

union alignas(64) VectorReg {
  alignas(64) avec128_t xmm;
  alignas(64) avec256_t ymm;
  alignas(64) avec512_t zmm;
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(VectorReg, xmm),
              "Invalid packing of `VectorReg::xmm`.");

static_assert(0 == __builtin_offsetof(VectorReg, ymm),
              "Invalid packing of `VectorReg::ymm`.");

static_assert(0 == __builtin_offsetof(VectorReg, zmm),
              "Invalid packing of `VectorReg::zmm`.");

struct alignas(8) GPR {
  // Named the same way as the 64-bit version to keep names the same
  // across architectures. All registers are here, even the 64-bit ones. The
  // 64-bit ones are inaccessible in lifted 32-bit code because they will
  // not be referenced by named variables in the `__mcsema_basic_block`
  // function.
  Reg rax;
  Reg rbx;
  Reg rcx;
  Reg rdx;
  Reg rsi;
  Reg rdi;
  Reg rsp;
  Reg rbp;
  Reg r8;
  Reg r9;
  Reg r10;
  Reg r11;
  Reg r12;
  Reg r13;
  Reg r14;
  Reg r15;

  // Program counter. In general, this represents the "next" program counter.
  // For example, before a function call, the return address is loaded into
  // `rip`. Similarly, at conditional branches, the fall-through address is
  // loaded.
  Reg rip;
};

struct alignas(64) State {
  // Native `FXSAVE64` representation of the FPU, plus a semi-duplicate
  // representation of all vector regs (XMM, YMM, ZMM).
  FPU fpu;  // 512 bytes.

  // AVX512 has 32 vector registers, so we always include them all here for
  // consistency across the various state structures.
  VectorReg vec[32];  // 2048 bytes.

  // Two representations of flags. Makes it easy to convert from native-to-
  // lifted, as well as improved the optimizability of the aflags themselves.
  ArithFlags aflag;  // 8 bytes.
  Flags rflag;  // 8 bytes.

  Segments seg;  // 12 bytes, padded to 16 bytes.
  GPR gpr;  // 136 bytes.

  // Total: 2728 bytes, padded to 2752 bytes.
};

static_assert(2752 == sizeof(State), "Invalid packing of `State`.");
