/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <type_traits>
#include <cstdint>

struct State;

#include "mcsema/Arch/Semantics/CONTROL.inc"
#include "mcsema/Arch/Semantics/TYPES.inc"
#include "mcsema/Arch/Semantics/MACROS.inc"
#include "mcsema/Arch/Semantics/MEMORY.inc"

#if 64 == ADDRESS_SIZE_BITS
# define IF_64BIT(...) __VA_ARGS__
#else
# define IF_64BIT(...)
#endif

#include "mcsema/Arch/X86/Semantics/REGISTER.inc"

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
  vec128_t xmm[16];  // 16*16 bytes for each XMM reg = 256 bytes.
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
  alignas(8) int64_t sfull;
} __attribute__((packed));

#else

union Reg {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(4) uint32_t full;
  alignas(4) int32_t sfull;
} __attribute__((packed));

#endif  // 64 != ADDRESS_SIZE_BITS

static_assert(sizeof(void *) == sizeof(Reg), "Invalid packing of `Reg`.");
static_assert(0 == __builtin_offsetof(Reg, byte.low), "Invalid packing of `Reg::low`.");
static_assert(1 == __builtin_offsetof(Reg, byte.high), "Invalid packing of `Reg::high`.");
static_assert(0 == __builtin_offsetof(Reg, word), "Invalid packing of `Reg::word`.");
static_assert(0 == __builtin_offsetof(Reg, dword), "Invalid packing of `Reg::dword`.");
static_assert(0 == __builtin_offsetof(Reg, full), "Invalid packing of `Reg::full`.");
static_assert(0 == __builtin_offsetof(Reg, sfull), "Invalid packing of `Reg::sfull`.");

union alignas(64) VectorReg {
  vec128_t xmm;

  IF_64BIT( vec256_t ymm; )
  IF_64BIT( vec512_t zmm; )

} __attribute__((packed));

static_assert(0 == __builtin_offsetof(VectorReg, xmm),
              "Invalid packing of `VectorReg::xmm`.");

#if 64 == ADDRESS_SIZE_BITS
static_assert(0 == __builtin_offsetof(VectorReg, ymm),
              "Invalid packing of `VectorReg::ymm`.");
static_assert(0 == __builtin_offsetof(VectorReg, zmm),
              "Invalid packing of `VectorReg::zmm`.");
#endif  // 64 == ADDRESS_SIZE_BITS

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
void __mcsema_basic_block(State &state) noexcept {

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

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_intrinsics(void) {
  (void) __mcsema_basic_block;
  (void) __mcsema_error;
  (void) __mcsema_function_call;
  (void) __mcsema_function_return;
  (void) __mcsema_jump;
  (void) __mcsema_system_call;
  (void) __mcsema_system_return;
  (void) __mcsema_interrupt_call;
  (void) __mcsema_interrupt_return;
  (void) __mcsema_read_memory_8;
  (void) __mcsema_read_memory_16;
  (void) __mcsema_read_memory_32;
  (void) __mcsema_read_memory_64;
  (void) __mcsema_read_memory_128;
  (void) __mcsema_read_memory_256;
  (void) __mcsema_read_memory_512;
  (void) __mcsema_write_memory_8;
  (void) __mcsema_write_memory_16;
  (void) __mcsema_write_memory_32;
  (void) __mcsema_write_memory_64;
  (void) __mcsema_write_memory_128;
  (void) __mcsema_write_memory_256;
  (void) __mcsema_write_memory_512;
  (void) __mcsema_compute_address;
  (void) __mcsema_undefined_bool;
}

}  // extern C

// Unsigned -------------

typedef uint8_t &R8W;
typedef uint8_t R8;
typedef uint16_t &R16W;
typedef uint16_t R16;
typedef decltype(Reg().full) &R32W;
typedef uint32_t R32;
IF_64BIT( typedef uint64_t &R64W; )
IF_64BIT( typedef uint64_t R64; )
typedef vec128_t &R128W;
typedef vec128_t R128;
typedef vec256_t &R256W;
typedef vec256_t R256;
typedef vec512_t &R512W;
typedef vec512_t R512;

IF_64BIT( typedef uint64_t I64; )
typedef uint32_t I32;
typedef uint16_t I16;
typedef uint8_t I8;

IF_64BIT( typedef int64_t SI64; )
typedef int32_t SI32;
typedef int16_t SI16;
typedef int8_t SI8;

// Immediate selectors -------------

typedef uintptr_t PC;

#define INSTR_ATTRIBS ALWAYS_INLINE

// Define a specific instruction selection variable.
#define DEF_ISEL(name) \
  extern "C" constexpr auto name __attribute__((used, visibility("default")))

// Define a semantics implementing function.
#define DEF_SEM(name, ...) \
    INSTR_ATTRIBS static inline void name (State &state, ##__VA_ARGS__)

#define DEF_ISEL_ALL(name, func) \
    DEF_ISEL(name ## _8) = func ; \
    DEF_ISEL(name ## _16) = func ; \
    DEF_ISEL(name ## _32) = func ; \
    DEF_ISEL(name ## _64) = func

#define DEF_ISEL_32UP(name, func) \
    DEF_ISEL(name ## _32) = func \
    IF_64BIT( ; DEF_ISEL(name ## _64) = func )

#define DEF_ISEL_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64> )

#define DEF_ISEL_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64> )

#define DEF_ISEL_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<I64> )

// Two operand (dst <- src)
#define DEF_ISEL_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, M64> )

#define DEF_ISEL_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64> )

#define DEF_ISEL_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, I64> )

#define DEF_ISEL_Mn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, I64> )

#define DEF_ISEL_Mn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, R64> )

#define DEF_ISEL_RO_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, M64> )

#define DEF_ISEL_RO_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, R64> )

#define DEF_ISEL_RO_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64, I64> )

#define DEF_ISEL_RO_Mn_In DEF_ISEL_Mn_In
#define DEF_ISEL_RO_Mn_Rn DEF_ISEL_Mn_Rn

// 3-operand dst <- (src1 op src2)
#define DEF_ISEL_Rn_Rn_Mn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, M8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, M16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, M32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, M64> )

#define DEF_ISEL_Rn_Rn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, R64> )

#define DEF_ISEL_Rn_Rn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<R8W, R8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<R16W, R16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<R32W, R32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<R64W, R64, I64> )

#define DEF_ISEL_Mn_Mn_In(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, I8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, I16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, I32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, I64> )

#define DEF_ISEL_Mn_Mn_Rn(name, tpl_func) \
    DEF_ISEL(name ## _8) = tpl_func<M8, R8> ; \
    DEF_ISEL(name ## _16) = tpl_func<M16, R16> ; \
    DEF_ISEL(name ## _32) = tpl_func<M32, R32> \
    IF_64BIT( ; DEF_ISEL(name ## _64) = tpl_func<M64, R64> )

namespace {

// Write to memory.
template <typename T>
INSTR_ATTRIBS
static inline Mn<T> W(Mn<T> addr) {
  return addr;
}

// Write to a register.
template <typename T>
INSTR_ATTRIBS
static inline T &W(T &v) { return v; }

template <typename T>
INSTR_ATTRIBS
static inline T R(Mn<T> addr) {
  return addr.Read();
}

template <typename T>
INSTR_ATTRIBS
static inline T R(T v) {
  return v;
}

}  // namespace

#include "mcsema/Arch/X86/Semantics/FLAGS.inc"
#include "mcsema/Arch/X86/Semantics/BINARY.inc"
#include "mcsema/Arch/X86/Semantics/CALL_RET.inc"
#include "mcsema/Arch/X86/Semantics/COND_BR.inc"
#include "mcsema/Arch/X86/Semantics/DATAXFER.inc"
#include "mcsema/Arch/X86/Semantics/LOGICAL.inc"
#include "mcsema/Arch/X86/Semantics/MISC.inc"
#include "mcsema/Arch/X86/Semantics/STACK.inc"
#include "mcsema/Arch/X86/Semantics/UNCOND_BR.inc"
