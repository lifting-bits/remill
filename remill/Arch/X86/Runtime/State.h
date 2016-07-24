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

#include "remill/Arch/Runtime/Runtime.h"

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

union FPUStatusWord final {
  uint16_t flat;
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
} __attribute__((packed));

static_assert(2 == sizeof(FPUStatusWord),
              "Invalid structure packing of `FPUFlags`.");

union FPUControlWord final {
  uint16_t flat;
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
} __attribute__((packed));

static_assert(2 == sizeof(FPUControlWord),
              "Invalid structure packing of `FPUControl`.");

struct FPUStackElem final {
  uint8_t _rsvd[6];
  union {
    float80_t st;
    struct {
      uint16_t infinity;  // When an MMX register is used, this is all 1s.
      vec64_t mmx;
    } __attribute__((packed));
  } __attribute__((packed));
} __attribute__((packed));

static_assert(16 == sizeof(FPUStackElem),
              "Invalid structure packing of `FPUStackElem`.");

union SSEControlStatus {
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

static_assert(4 == sizeof(SSEControlStatus),
              "Invalid structure packing of `SSEControlStatus`.");

// FP register state that conforms with `FXSAVE`.
struct alignas(64) FPU final {
  FPUControlWord cwd;
  FPUStatusWord swd;
  uint8_t ftw;
  uint8_t _rsvd0;
  uint16_t fop;
  union {
    struct {
      uint32_t ip;  // Offset in segment of last non-control FPU instruction.
      uint16_t cs;  // Code segment associated with `ip`.
      uint16_t _rsvd1;
      uint32_t dp;
      uint16_t ds;
      uint16_t _rsvd2;
    } __attribute__((packed)) x86;
    struct {
      uint64_t ip;
      uint64_t dp;
    } __attribute__((packed)) amd64;
  } __attribute__((packed)) u;
  SSEControlStatus mxcsr;
  uint32_t mxcsr_mask;
  FPUStackElem st[8];   // 8*16 bytes for each FP reg = 128 bytes.

  // Note: This is consistent with `fxsave64`, but doesn't handle things like
  //       ZMM/YMM registers. Therefore, we use a different set of registers
  //       for those.
  vec128_t xmm[16];  // 16*16 bytes for each XMM reg = 256 bytes.
  uint32_t padding[24];
} __attribute__((packed));

static_assert(512 == sizeof(FPU), "Invalid structure packing of `FPU`.");

union alignas(8) Flags final {
  uint64_t flat;
  struct {
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
} __attribute__((packed));

static_assert(8 == sizeof(Flags), "Invalid structure packing of `Flags`.");

struct alignas(16) ArithFlags final {
  // Prevents LLVM from casting and `ArithFlags` into an `i8` to access `cf`.
  volatile bool _tear0;
  bool cf;  // Prevents load/store coalescing.
  volatile bool _tear1;
  bool pf;
  volatile bool _tear2;
  bool af;
  volatile bool _tear3;
  bool zf;
  volatile bool _tear4;
  bool sf;
  volatile bool _tear5;
  bool df;
  volatile bool _tear6;
  bool of;
  volatile bool _tear7;
  volatile bool _tear8;
} __attribute__((packed));

static_assert(16 == sizeof(ArithFlags), "Invalid packing of `ArithFlags`.");

struct alignas(8) Segments final {
  volatile uint16_t _tear0;
  uint16_t ss;
  volatile uint16_t _tear1;
  uint16_t es;
  volatile uint16_t _tear2;
  uint16_t gs;
  volatile uint16_t _tear3;
  uint16_t fs;
  volatile uint16_t _tear4;
  uint16_t ds;
  volatile uint16_t _tear5;
  uint16_t cs;
} __attribute__((packed));

union Reg final {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(sizeof(addr_t)) addr_t aword;
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
static_assert(0 == __builtin_offsetof(Reg, aword),
              "Invalid packing of `Reg::aword`.");
static_assert(0 == __builtin_offsetof(Reg, qword),
              "Invalid packing of `Reg::qword`.");

union alignas(64) VectorReg final {
  alignas(64) vec128_t xmm;
  alignas(64) vec256_t ymm;
  alignas(64) vec512_t zmm;
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(VectorReg, xmm),
              "Invalid packing of `VectorReg::xmm`.");

static_assert(0 == __builtin_offsetof(VectorReg, ymm),
              "Invalid packing of `VectorReg::ymm`.");

static_assert(0 == __builtin_offsetof(VectorReg, zmm),
              "Invalid packing of `VectorReg::zmm`.");

// Named the same way as the 64-bit version to keep names the same
// across architectures. All registers are here, even the 64-bit ones. The
// 64-bit ones are inaccessible in lifted 32-bit code because they will
// not be referenced by named variables in the `__remill_basic_block`
// function.
struct alignas(16) GPR final {
  // Prevents LLVM from casting a `GPR` into an `i64` to access `rax`.
  volatile uint64_t _tear0;
  Reg rax;
  volatile uint64_t _tear1;
  Reg rbx;
  volatile uint64_t _tear2;
  Reg rcx;
  volatile uint64_t _tear3;
  Reg rdx;
  volatile uint64_t _tear4;
  Reg rsi;
  volatile uint64_t _tear5;
  Reg rdi;
  volatile uint64_t _tear6;
  Reg rsp;
  volatile uint64_t _tear7;
  Reg rbp;
  volatile uint64_t _tear8;
  Reg r8;
  volatile uint64_t _tear9;
  Reg r9;
  volatile uint64_t _tear10;
  Reg r10;
  volatile uint64_t _tear11;
  Reg r11;
  volatile uint64_t _tear12;
  Reg r12;
  volatile uint64_t _tear13;
  Reg r13;
  volatile uint64_t _tear14;
  Reg r14;
  volatile uint64_t _tear15;
  Reg r15;
  volatile uint64_t _tear16;

  // Program counter. In general, this represents the "next" program counter.
  // For example, before a function call, the return address is loaded into
  // `rip`. Similarly, at conditional branches, the fall-through address is
  // loaded.
  Reg rip;
} __attribute__((packed));

static_assert(272 == sizeof(GPR), "Invalid structure packing of `GPR`.");

struct alignas(16) X87Stack {
  struct alignas(16) {
    uint64_t _tear;
    float64_t val;
  } __attribute__((packed)) element[8];
};

static_assert(128 == sizeof(X87Stack),
              "Invalid structure packing of `X87Stack`.");

struct alignas(16) MMX {
  struct alignas(8) {
    uint64_t _tear;
    vec64_t val;
  } __attribute__((packed)) mmx[8];
};

static_assert(128 == sizeof(MMX), "Invalid structure packing of `MMX`.");

enum : size_t {
  kNumVecRegisters = 32
};

struct alignas(64) State final {
  // Native `FXSAVE64` representation of the FPU, plus a semi-duplicate
  // representation of all vector regs (XMM, YMM, ZMM).
  FPU fpu;  // 512 bytes.

  // AVX512 has 32 vector registers, so we always include them all here for
  // consistency across the various state structures.
  VectorReg vec[kNumVecRegisters];  // 2048 bytes.

  // Two representations of flags. Makes it easy to convert from native-to-
  // lifted, as well as improved the optimizability of the aflags themselves.
  ArithFlags aflag;  // 16 bytes.
  Flags rflag;  // 8 bytes.
  Segments seg;  // 24 bytes.
  GPR gpr;  // 272 bytes.
  X87Stack st;  // 128 bytes.
  MMX mmx;  // 128 bytes.

  // Used to communicate the interrupt vector number to an intrinsic. The
  // issue is that the interrupt number is part of an instruction, and our
  // generic three-operand block/intrinsic form (state, mem, pc) doesn't
  // have room to hold a vector number.
  //
  // TODO(pag): I'm not particular fond of this approach, but oh well.
  volatile uint32_t interrupt_vector;

  // Use to communicate to `Translator.cpp` that the conditional branch should
  // be taken or not-taken.
  //
  // TODO(pag): This is kind of ugly, but enables PC-specific independence
  //            (to handle things like relocatable binaries).
  volatile bool conditional_branch_taken;

  uint8_t _padding[59];
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(State, fpu),
              "Invalid packing of `State::fpu`.");

static_assert(512 == __builtin_offsetof(State, vec[0]),
              "Invalid packing of `State::vec`.");

static_assert(2560 == __builtin_offsetof(State, aflag),
              "Invalid packing of `State::aflag`.");

static_assert(2576 == __builtin_offsetof(State, rflag),
              "Invalid packing of `State::rflag`.");

static_assert(2584 == __builtin_offsetof(State, seg),
              "Invalid packing of `State::seg`.");

static_assert(2608 == __builtin_offsetof(State, gpr),
              "Invalid packing of `State::seg`.");

static_assert(2880 == __builtin_offsetof(State, st),
              "Invalid packing of `State::st`.");

static_assert(3008 == __builtin_offsetof(State, mmx),
              "Invalid packing of `State::mmx`.");

static_assert(3136 == __builtin_offsetof(State, interrupt_vector),
              "Invalid packing of `State::interrupt`.");

static_assert(3200 == sizeof(State), "Invalid packing of `State`.");

#endif  // REMILL_ARCH_X86_RUNTIME_STATE_H_
