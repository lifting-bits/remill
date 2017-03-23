/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_RUNTIME_STATE_H_
#define REMILL_ARCH_X86_RUNTIME_STATE_H_

// !!! RULES FOR STATE STRUCTURE TYPES !!!
//
//  (1) Never use a type that has a different allocation size on a different
//      architecture. This includes things like pointers or architecture-
//      specific floating point types (e.g. `long double`).
//
//  (2) Never depend on implicit padding or alignment, even if you explicitly
//      specify it. Always "fill" structures to the desired alignment with
//      explicit structure fields.
//
//  (3) Trust but verify the `static_assert`s that try to verify the sizes of
//      structures. Clang will LIE to you! This happens if you compile a file
//      to bitcode for one architecture, then change its `DataLayout` to
//      match another architecture.

#pragma clang diagnostic push
#pragma clang diagnostic fatal "-Wpadded"

#include "remill/Arch/Runtime/State.h"
#include "remill/Arch/Runtime/Types.h"

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

#define aword IF_64BIT_ELSE(qword, dword)

union FPUStatusWord final {
  uint16_t flat;
  struct {
    uint16_t ie:1;  // Invalid operation.
    uint16_t de:1;  // Denormal operand.
    uint16_t ze:1;  // Zero divide.
    uint16_t oe:1;  // Overflow.
    uint16_t ue:1;  // Underflow.
    uint16_t pe:1;  // Precision.
    uint16_t sf:1;  // Stack fault.
    uint16_t es:1;  // Error summary status.
    uint16_t c0:1;  // Part of condition code.
    uint16_t c1:1;  // Used for a whole lot of stuff.
    uint16_t c2:1;  // Part of condition code.
    uint16_t top:3;  // Stack pointer.
    uint16_t c3:1;  // Part of condition code.
    uint16_t b:1;  // Busy.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(2 == sizeof(FPUStatusWord),
              "Invalid structure packing of `FPUFlags`.");

#if COMPILING_WITH_GCC
using FPUPrecisionControl = uint16_t;
using FPURoundingControl = uint16_t;
using FPUInfinityControl = uint16_t;
#else
enum FPUPrecisionControl : uint16_t {
  kPrecisionSingle,
  kPrecisionReserved,
  kPrecisionDouble,
  kPrecisionExtended
};

enum FPURoundingControl : uint16_t {
  kFPURoundToNearestEven,
  kFPURoundDownNegInf,
  kFPURoundUpInf,
  kFPURoundToZero
};

enum FPUInfinityControl : uint16_t {
  kInfinityProjective,
  kInfinityAffine
};
#endif

union FPUControlWord final {
  uint16_t flat;
  struct {
    uint16_t im:1;  // Invalid Operation.
    uint16_t dm:1;  // Denormalized Operand.
    uint16_t zm:1;  // Zero Divide.
    uint16_t om:1;  // Overflow.
    uint16_t um:1;  // Underflow.
    uint16_t pm:1;  // Precision.
    uint16_t _rsvd0:2;
    FPUPrecisionControl pc:2;  // bit 8
    FPURoundingControl rc:2;
    FPUInfinityControl x:1;
    uint16_t _rsvd1:3;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(2 == sizeof(FPUControlWord),
              "Invalid structure packing of `FPUControl`.");

struct FPUStackElem final {
  union {
    float80_t st;
    struct {
      uint64_t mmx;
      uint16_t infinity;  // When an MMX register is used, this is all 1s.
    } __attribute__((packed));
  } __attribute__((packed));
  uint8_t _rsvd[6];
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(FPUStackElem, st),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(0 == __builtin_offsetof(FPUStackElem, mmx),
              "Invalid structure packing of `FPUStackElem::mmx`.");

static_assert(8 == __builtin_offsetof(FPUStackElem, infinity),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(10 == __builtin_offsetof(FPUStackElem, _rsvd[0]),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(16 == sizeof(FPUStackElem),
              "Invalid structure packing of `FPUStackElem`.");

union FPUControlStatus {
  uint32_t flat;
  struct {
    uint32_t ie:1;  // Invalid operation.
    uint32_t de:1;  // Denormal flag.
    uint32_t ze:1;  // Divide by zero.
    uint32_t oe:1;  // Overflow.
    uint32_t ue:1;  // Underflow.
    uint32_t pe:1;  // Precision.
    uint32_t daz:1;  // Denormals are zero.
    uint32_t im:1;  // Invalid operation.
    uint32_t dm:1;  // Denormal mask.
    uint32_t zm:1;  // Dvidide by zero mask.
    uint32_t om:1;  // Overflow mask.
    uint32_t um:1;  // Underflow mask.
    uint32_t pm:1;  // Precision mask.
    uint32_t rn:1;  // Round negative.
    uint32_t rp:1;  // Round positive.
    uint32_t fz:1;  // Flush to zero.
    uint32_t _rsvd:16;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(4 == sizeof(FPUControlStatus),
              "Invalid structure packing of `SSEControlStatus`.");

#if COMPILING_WITH_GCC
using FPUTag = uint16_t;
using FPUAbridgedTag = uint8_t;
#else
enum FPUTag : uint16_t {
  kFPUTagNonZero,
  kFPUTagZero,
  kFPUTagSpecial,
  kFPUTagEmpty
};

enum FPUAbridgedTag : uint8_t {
  kFPUAbridgedTagEmpty,
  kFPUAbridgedTagValid
};
#endif

// Note: Stored in top-of-stack order.
struct FPUTagWord final {
  FPUTag tag0:2;
  FPUTag tag1:2;
  FPUTag tag2:2;
  FPUTag tag3:2;
  FPUTag tag4:2;
  FPUTag tag5:2;
  FPUTag tag6:2;
  FPUTag tag7:2;
} __attribute__((packed));

static_assert(sizeof(FPUTagWord) == 2,
              "Invalid structure packing of `TagWord`.");

// Note: Stored in physical order.
struct FPUAbridgedTagWord final {
  FPUAbridgedTag r0:1;
  FPUAbridgedTag r1:1;
  FPUAbridgedTag r2:1;
  FPUAbridgedTag r3:1;
  FPUAbridgedTag r4:1;
  FPUAbridgedTag r5:1;
  FPUAbridgedTag r6:1;
  FPUAbridgedTag r7:1;
};

// FP register state that conforms with `FXSAVE`.
struct alignas(64) FPU final {
  FPUControlWord cwd;
  FPUStatusWord swd;
  union {
    struct {
      FPUAbridgedTagWord abridged;
      uint8_t _rsvd0;
    } __attribute__((packed)) fxsave;
    struct {
      FPUTagWord full;
    } __attribute__((packed)) fsave;
  } __attribute__((packed)) ftw;
  uint16_t fop;
  union {
    struct {
      uint32_t ip;  // Offset in segment of last non-control FPU instruction.
      uint16_t cs;  // Code segment associated with `ip`.
      uint16_t _rsvd1;
      uint32_t dp;
      uint16_t ds;
      uint16_t _rsvd2;
    } __attribute__((packed)) fxsave;
    struct {
      uint64_t ip;
      uint64_t dp;
    } __attribute__((packed)) fxsave64;
  } __attribute__((packed)) code_data;
  FPUControlStatus mxcsr;
  FPUControlStatus mxcsr_mask;
  FPUStackElem st[8];   // 8*16 bytes for each FP reg = 128 bytes.

  // Note: This is consistent with `fxsave64`, but doesn't handle things like
  //       ZMM/YMM registers. Therefore, we use a different set of registers
  //       for those.
  vec128_t xmm[16];  // 16*16 bytes for each XMM reg = 256 bytes.
  uint32_t padding[24];
} __attribute__((packed));

static_assert(512 == sizeof(FPU), "Invalid structure packing of `FPU`.");

struct FPUStatusFlags final {
  uint8_t _0;
  uint8_t c0;
  uint8_t _1;
  uint8_t c1;
  uint8_t _2;
  uint8_t c2;
  uint8_t _3;
  uint8_t c3;
} __attribute__((packed));

static_assert(8 == sizeof(FPUStatusFlags),
              "Invalid packing of `FPUStatusFlags`.");

union alignas(8) Flags final {
  uint64_t flat;
  struct {
    uint32_t cf:1;  // bit 0.
    uint32_t must_be_1:1;
    uint32_t pf:1;
    uint32_t must_be_0a:1;

    uint32_t af:1;  // bit 4.
    uint32_t must_be_0b:1;
    uint32_t zf:1;
    uint32_t sf:1;

    uint32_t tf:1;  // bit 8.
    uint32_t _if:1;  // underscore to avoid token clash.
    uint32_t df:1;
    uint32_t of:1;

    uint32_t iopl:2;  // A 2-bit field, bits 12-13.
    uint32_t nt:1;
    uint32_t must_be_0c:1;

    uint32_t rf:1;  // bit 16.
    uint32_t vm:1;
    uint32_t ac:1;  // Alignment check.
    uint32_t vif:1;

    uint32_t vip:1;  // bit 20.
    uint32_t id:1;   // bit 21.
    uint32_t reserved_eflags:10;  // bits 22-31.
    uint32_t reserved_rflags;  // bits 32-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(Flags), "Invalid structure packing of `Flags`.");

struct alignas(8) ArithFlags final {
  // Prevents LLVM from casting and `ArithFlags` into an `i8` to access `cf`.
  volatile bool _0;
  uint8_t cf;  // Prevents load/store coalescing.
  volatile bool _1;
  uint8_t pf;
  volatile bool _2;
  uint8_t af;
  volatile bool _3;
  uint8_t zf;
  volatile bool _4;
  uint8_t sf;
  volatile bool _5;
  uint8_t df;
  volatile bool _6;
  uint8_t of;
  volatile bool _7;
  volatile bool _8;
} __attribute__((packed));

static_assert(16 == sizeof(ArithFlags), "Invalid packing of `ArithFlags`.");

struct alignas(8) Segments final {
  volatile uint16_t _0;
  uint16_t ss;
  volatile uint16_t _1;
  uint16_t es;
  volatile uint16_t _2;
  uint16_t gs;
  volatile uint16_t _3;
  uint16_t fs;
  volatile uint16_t _4;
  uint16_t ds;
  volatile uint16_t _5;
  uint16_t cs;
} __attribute__((packed));

static_assert(24 == sizeof(Segments), "Invalid packing of `struct Segments`.");

// For remill-opt's register alias analysis, we don't want 32-bit lifted
// code to look like operations on 64-bit registers, because then every
// (bitcasted from 64 bit) store of a 32-bit value will look like a false-
// dependency on the (bitcasted from 64 bit) full 64-bit quantity.
struct Reg final {
  union {
    alignas(1) struct {
      uint8_t low;
      uint8_t high;
    } byte;
    alignas(2) uint16_t word;
    alignas(4) uint32_t dword;
    IF_64BIT(alignas(8) uint64_t qword;)
  } __attribute__((packed));
  IF_32BIT(uint32_t _padding0;)
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
IF_64BIT(static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");)

union alignas(16) VectorReg final {
  alignas(16) vec128_t xmm;
  alignas(16) vec256_t ymm;
  alignas(16) vec512_t zmm;
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(VectorReg, xmm),
              "Invalid packing of `VectorReg::xmm`.");

static_assert(0 == __builtin_offsetof(VectorReg, ymm),
              "Invalid packing of `VectorReg::ymm`.");

static_assert(0 == __builtin_offsetof(VectorReg, zmm),
              "Invalid packing of `VectorReg::zmm`.");

static_assert(64 == sizeof(VectorReg),
              "Invalid packing of `struct VectorReg`.");

struct alignas(8) AddressSpace final {
  volatile uint64_t _0;
  Reg fs_base;
  volatile uint64_t _1;
  Reg gs_base;
} __attribute__((packed));

static_assert(32 == sizeof(AddressSpace),
              "Invalid packing of `struct AddressSpace`.");

// Named the same way as the 64-bit version to keep names the same
// across architectures. All registers are here, even the 64-bit ones. The
// 64-bit ones are inaccessible in lifted 32-bit code because they will
// not be referenced by named variables in the `__remill_basic_block`
// function.
struct alignas(8) GPR final {
  // Prevents LLVM from casting a `GPR` into an `i64` to access `rax`.
  volatile uint64_t _0;
  Reg rax;
  volatile uint64_t _1;
  Reg rbx;
  volatile uint64_t _2;
  Reg rcx;
  volatile uint64_t _3;
  Reg rdx;
  volatile uint64_t _4;
  Reg rsi;
  volatile uint64_t _5;
  Reg rdi;
  volatile uint64_t _6;
  Reg rsp;
  volatile uint64_t _7;
  Reg rbp;
  volatile uint64_t _8;
  Reg r8;
  volatile uint64_t _9;
  Reg r9;
  volatile uint64_t _10;
  Reg r10;
  volatile uint64_t _11;
  Reg r11;
  volatile uint64_t _12;
  Reg r12;
  volatile uint64_t _13;
  Reg r13;
  volatile uint64_t _14;
  Reg r14;
  volatile uint64_t _15;
  Reg r15;
  volatile uint64_t _16;

  // Program counter of the CURRENT instruction!
  Reg rip;
} __attribute__((packed));

static_assert(272 == sizeof(GPR), "Invalid structure packing of `GPR`.");

struct alignas(8) X87Stack final {
  struct alignas(8) {
    uint64_t _0;
    float64_t val;
  } __attribute__((packed)) elems[8];
};

static_assert(128 == sizeof(X87Stack),
              "Invalid structure packing of `X87Stack`.");

struct alignas(8) MMX final {
  struct alignas(8) {
    uint64_t _0;
    vec64_t val;
  } __attribute__((packed)) elems[8];
};

static_assert(128 == sizeof(MMX), "Invalid structure packing of `MMX`.");

enum : size_t {
  kNumVecRegisters = 32
};

struct alignas(16) State final : public ArchState {
  // ArchState occupies 16 bytes.

  // AVX512 has 32 vector registers, so we always include them all here for
  // consistency across the various state structures.
  VectorReg vec[kNumVecRegisters];  // 2048 bytes.

  // Two representations of flags. Makes it easy to convert from native-to-
  // lifted, as well as improved the optimizability of the aflags themselves.
  ArithFlags aflag;  // 16 bytes.
  Flags rflag;  // 8 bytes.
  Segments seg;  // 24 bytes.
  AddressSpace addr;  // 32 bytes.
  GPR gpr;  // 272 bytes.
  X87Stack st;  // 128 bytes.
  MMX mmx;  // 128 bytes.
  FPUStatusFlags sw;  // 8 bytes
  uint8_t _0[8];
} __attribute__((packed));

static_assert((2672 + 16) == sizeof(State),
              "Invalid packing of `struct State`");

#pragma clang diagnostic pop

#endif  // REMILL_ARCH_X86_RUNTIME_STATE_H_
