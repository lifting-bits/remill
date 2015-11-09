/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>
#include <type_traits>

#include "mcsema/Arch/X86/Semantics/Register.inc"

typedef float float32_t;
static_assert(4 == sizeof(float32_t), "Invalid `float32_t` size.");

typedef double float64_t;
static_assert(8 == sizeof(float64_t), "Invalid `float64_t` size.");

struct alignas(16) float80_t {
  long double f;
};
static_assert(16 == sizeof(float80_t), "Invalid `float80_t` size.");

typedef unsigned uint128_t __attribute__ ((vector_size (16)));
static_assert(16 == sizeof(uint128_t), "Invalid `uint128_t` size.");

typedef unsigned uint256_t __attribute__ ((vector_size (32)));
static_assert(32 == sizeof(uint256_t), "Invalid `uint256_t` size.");

typedef unsigned uint512_t __attribute__ ((vector_size (64)));
static_assert(64 == sizeof(uint512_t), "Invalid `uint512_t` size.");

union FPUStatusWord {
  struct {
    uint16_t ie:1;  ///< bit 0
    uint16_t de:1;
    uint16_t ze:1;
    uint16_t oe:1;
    uint16_t ue:1;  ///< bit 4
    uint16_t pe:1;
    uint16_t sf:1;
    uint16_t es:1;
    uint16_t c0:1;  ///< bit 8
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
    uint16_t im:1;  ///< bit 0
    uint16_t dm:1;
    uint16_t zm:1;
    uint16_t om:1;
    uint16_t um:1;  ///< bit 4
    uint16_t pm:1;
    uint16_t _rsvd0:2;
    uint16_t pc:2;  ///< bit 8
    uint16_t rc:2;
    uint16_t x:1;
    uint16_t _rsvd1:3;
  } __attribute__((packed)) u;
  uint16_t flat;
} __attribute__((packed));

static_assert(2 == sizeof(FPUControlWord),
              "Invalid structure packing of `FPUControl`.");

typedef uint8_t uint8v16_t __attribute__ ((vector_size (16)));
typedef uint16_t uint16v8_t __attribute__ ((vector_size (16)));
typedef uint32_t uint32v4_t __attribute__ ((vector_size (16)));
typedef uint64_t uint64v2_t __attribute__ ((vector_size (16)));
typedef float32_t float32v4_t __attribute__ ((vector_size (16)));
typedef float64_t float64v2_t __attribute__ ((vector_size (16)));

union XMMReg {
  uint8v16_t bytes;
  uint16v8_t words;
  uint32v4_t dwords;
  uint64v2_t qwords;
  float32v4_t floats;
  float64v2_t doubles;
} __attribute__((packed));

static_assert(16 == sizeof(XMMReg),
              "Invalid structure packing of `XMMReg`.");

#if 64 == ADDRESS_SIZE_BITS

typedef uint8_t uint8v32_t __attribute__ ((vector_size (32)));
typedef uint16_t uint16v16_t __attribute__ ((vector_size (32)));
typedef uint32_t uint32v8_t __attribute__ ((vector_size (32)));
typedef uint64_t uint64v4_t __attribute__ ((vector_size (32)));
typedef float32_t float32v8_t __attribute__ ((vector_size (32)));
typedef float64_t float64v4_t __attribute__ ((vector_size (32)));

union YMMReg {
  uint8v32_t bytes;
  uint16v16_t words;
  uint32v8_t dwords;
  uint64v4_t qwords;
  float32v8_t floats;
  float64v4_t doubles;
} __attribute__((packed));

static_assert(32 == sizeof(YMMReg),
              "Invalid structure packing of `YMMReg`.");

typedef uint8_t uint8v64_t __attribute__ ((vector_size (64)));
typedef uint16_t uint16v32_t __attribute__ ((vector_size (64)));
typedef uint32_t uint32v16_t __attribute__ ((vector_size (64)));
typedef uint64_t uint64v8_t __attribute__ ((vector_size (64)));
typedef float32_t float32v16_t __attribute__ ((vector_size (64)));
typedef float64_t float64v8_t __attribute__ ((vector_size (64)));

union ZMMReg {
  uint8v64_t bytes;
  uint16v32_t words;
  uint32v16_t dwords;
  uint64v8_t qwords;
  float32v16_t floats;
  float64v8_t doubles;
} __attribute__((packed));

static_assert(64 == sizeof(ZMMReg),
              "Invalid structure packing of `ZMMReg`.");

#endif  // 64 == ADDRESS_SIZE_BITS

union alignas(64) VectorReg {
  XMMReg xmm;
#if 64 == ADDRESS_SIZE_BITS
  YMMReg ymm;
  ZMMReg zmm;
#endif  // 64 == ADDRESS_SIZE_BITS
} __attribute__((packed));

static_assert(sizeof(uint512_t) == sizeof(VectorReg),
              "Invalid structure packing of `VectorReg`.");
static_assert(0 == __builtin_offsetof(VectorReg, xmm),
              "Invalid packing of `VectorReg::xmm`.");

#if 64 == ADDRESS_SIZE_BITS
static_assert(0 == __builtin_offsetof(VectorReg, ymm),
              "Invalid packing of `VectorReg::ymm`.");
static_assert(0 == __builtin_offsetof(VectorReg, zmm),
              "Invalid packing of `VectorReg::zmm`.");
#endif  // 64 == ADDRESS_SIZE_BITS

union FPUStackElem {
  float80_t st;
  double mmx;
};

// FP register state that conforms with `FXSAVE`.
class FPU {
 public:
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
  uint128_t xmm[16];  // 16*16 bytes for each XMM reg = 256 bytes.
  uint32_t padding[24];
} __attribute__((packed));

static_assert(512 == sizeof(FPU), "Invalid structure packing of `FPU`.");

class Flags {
 public:
  uint32_t cf:1;  ///< bit 0
  uint32_t must_be_1:1;
  uint32_t pf:1;
  uint32_t must_be_0a:1;

  uint32_t af:1; ///< bit 4
  uint32_t must_be_0b:1;
  uint32_t zf:1;
  uint32_t sf:1;

  uint32_t tf:1;  ///< bit 8
  uint32_t _if:1;  ///< underscore to avoid token clash
  uint32_t df:1;
  uint32_t of:1;

  uint32_t iopl:2; ///< A 2-bit field, bits 12-13
  uint32_t nt:1;
  uint32_t must_be_0c:1;

  uint32_t rf:1; ///< bit 16
  uint32_t vm:1;
  uint32_t ac:1;
  uint32_t vif:1;

  uint32_t vip:1; ///< bit 20
  uint32_t id:1;   ///< bit 21
  uint32_t reserved:10;  ///< bits 22-31
} __attribute__((packed));

static_assert(4 == sizeof(Flags), "Invalid structure packing of `Flags`.");

class alignas(8) ArithFlags {
 public:
  bool cf;
  bool pf;
  bool af;
  bool zf;
  bool sf;
  bool of;
  bool _unused1;
  bool _unused_2;
} __attribute__((packed));

static_assert(8 == sizeof(ArithFlags), "Invalid structure packing of `ArithFlags`.");

class alignas(8) Segments {
 public:
  uint16_t ss;
  uint16_t es;
  uint16_t gs;
  uint16_t fs;
  uint16_t ds;
  uint16_t cs;
};

#if 64 == ADDRESS_SIZE_BITS

union Reg {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(8) uint64_t full;
  alignas(8) uint64_t *ptr;
};

#else

union Reg {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(4) uint32_t full;
  alignas(4) uint32_t *ptr;
};

#endif  // 64 != ADDRESS_SIZE_BITS

static_assert(sizeof(void *) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, byte.low), "Invalid packing of `Reg::low`.");
static_assert(1 == __builtin_offsetof(Reg, byte.high), "Invalid packing of `Reg::high`.");
static_assert(0 == __builtin_offsetof(Reg, word), "Invalid packing of `Reg::word`.");
static_assert(0 == __builtin_offsetof(Reg, dword), "Invalid packing of `Reg::dword`.");
static_assert(0 == __builtin_offsetof(Reg, full), "Invalid packing of `Reg::full`.");

class alignas(8) GPR {
 public:
  // Named the same way as the 64-bit version to keep names the same
  // across architectures.
  Reg rax;
  Reg rbx;
  Reg rcx;
  Reg rdx;
  Reg rsi;
  Reg rdi;
  Reg rsp;
  Reg rbp;

#if 64 == ADDRESS_SIZE_BITS
  Reg r8;
  Reg r9;
  Reg r10;
  Reg r11;
  Reg r12;
  Reg r13;
  Reg r14;
  Reg r15;
#endif  // 64 == ADDRESS_SIZE_BITS

  // Next program counter.
  Reg rip;
};

class alignas(64) State {
 public:
  // Native `XSAVE64` representation of the FPU, plus a semi-duplicate
  // representation of all vector regs (XMM, YMM, ZMM).
  FPU fpu;
  VectorReg vec[64 == ADDRESS_SIZE_BITS ? 32 : 16];

  // Two representations of flags. Makes it easy to convert from native-to-
  // lifted, as well as improved the optimizability of the aflags themselves.
  ArithFlags aflag;
  Flags rflag;

  Segments seg;
  GPR gpr;
};

extern "C" {

// Method that will implement a basic block. We will clone this method for
// each basic block in the code being lifted.
[[gnu::used]]
void BlockMethod(State &state) noexcept {

  // Define read- and write-specific aliases of each register. We will
  // reference these variables from the bitcode side of things so that,
  // given a decoded register name and an operation type (read or write),
  // we can map the register to a specific field in the State structure.
#define REG_INFO(read_sel, write_sel, name) \
  auto & name ## _read = state.read_sel ; \
  auto & name ## _write = state.write_sel ;

  // Make it so that the register read/write access variables for 64-bit
  // registers are not defined in 32-bit mode.
#if 64 == ADDRESS_SIZE_BITS
# define REG_INFO64 REG_INFO
#else
# define REG_INFO64(...)
#endif  // 64 != ADDRESS_SIZE_BITS

  PLAT_X86_REG_INFOS()
#undef REG_INFO
#undef REG_INFO64
}

// TODO(pag): Perform exit the program due to an error.
[[gnu::used, gnu::noinline]]
void DispatchExitProgramError(State &state) noexcept {
  (void) state.gpr.rip;
}

// TODO(pag): Perform indirect branch based on program counter.
[[gnu::used, gnu::noinline]]
void DispatchIndirectFunctionCall(State &state) noexcept {
  (void) state.gpr.rip;
}

// TODO(pag): Perform indirect branch based on program counter.
[[gnu::used, gnu::noinline]]
void DispatchIndirectJump(State &state) noexcept {
  (void) state.gpr.rip;
}

// TODO(pag): Perform indirect branch based on program counter.
[[gnu::used, gnu::noinline]]
void DispatchFunctionReturn(State &state) noexcept {
  (void) state.gpr.rip;
}

}  // extern C

typedef uint64_t &R64W;
typedef uint64_t R64;

typedef decltype(Reg().full) &R32W;
typedef uint32_t R32;

typedef uint16_t &R16W;
typedef uint16_t R16;

typedef uint8_t &R8W;
typedef uint8_t R8;

// TODO(pag): These could be turned into references. It would be interesting
//            to see if this has any effect in terms of optimization, as the
//            pointers would be marked as `dereferencable`.
typedef uint64_t *M64;
typedef uint32_t *M32;
typedef uint16_t *M16;
typedef uint8_t *M8;

typedef uint64_t IMM64;
typedef uint32_t IMM32;
typedef uint16_t IMM16;
typedef uint8_t IMM8;

typedef int64_t SIMM64;
typedef int32_t SIMM32;
typedef int16_t SIMM16;
typedef int8_t SIMM8;

typedef uintptr_t PC;

#define INSTR_ATTRIBS [[gnu::always_inline, gnu::gnu_inline, gnu::flatten]]

// Define a specific instruction selection variable.
#define DEF_ISEL(name) extern "C" constexpr auto name __attribute__((used, visibility("default")))

// Define a semantics implementing function.
#define DEF_SEM(name, ...) \
    INSTR_ATTRIBS static inline void name (State &state, ##__VA_ARGS__)

#define DEF_ISEL_ALL(name, func) \
    DEF_ISEL(name ## _8) = func ; \
    DEF_ISEL(name ## _16) = func ; \
    DEF_ISEL(name ## _32) = func ; \
    DEF_ISEL(name ## _64) = func

#define DEF_ISEL_32UP(name, func) \
    DEF_ISEL(name ## _32) = func ; \
    DEF_ISEL(name ## _64) = func

#define DEF_ISEL_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32> ; \
    DEF_ISEL(name ## _64) = tpl_func<R64>

#define DEF_ISEL_WRn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, M32> ; \
    DEF_ISEL(name ## _64) = tpl_func<R64W, M64>

#define DEF_ISEL_WRn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32> ; \
    DEF_ISEL(name ## _64) = tpl_func<R64W, R64>

#define DEF_ISEL_WRn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, IMM8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, IMM16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, IMM32> ; \
    DEF_ISEL(name ## _64) = tpl_func<R64W, IMM64>

#define DEF_ISEL_Mn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, IMM8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, IMM16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, IMM32> ; \
    DEF_ISEL(name ## _64) = tpl_func<M64, IMM64>

#define DEF_ISEL_Mn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, R32> ; \
    DEF_ISEL(name ## _64) = tpl_func<M64, R64>

namespace {

template <typename T>
INSTR_ATTRIBS
static inline T &W(T *v) { return *v; }

template <typename T>
INSTR_ATTRIBS
static inline T &W(T &v) { return v; }

template <typename T>
INSTR_ATTRIBS
static inline T R(T *v) { return *v; }

template <typename T>
INSTR_ATTRIBS
static inline T R(T v) { return v; }

#include "mcsema/Arch/X86/Semantics/Flags.inc"

}  // namespace

#include "mcsema/Arch/X86/Semantics/CALL_RET.inc"
#include "mcsema/Arch/X86/Semantics/COND_BR.inc"
#include "mcsema/Arch/X86/Semantics/DATAXFER.inc"
#include "mcsema/Arch/X86/Semantics/LOGICAL.inc"
#include "mcsema/Arch/X86/Semantics/MISC.inc"
