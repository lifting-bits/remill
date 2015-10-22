/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdint>

#include "mcsema/Arch/X86/Register.inc"

struct alignas(16) float80_t {
  long double f;
};
static_assert(16 == sizeof(float80_t), "Invalid `float80_t` size.");

typedef unsigned uint128_t __attribute__ ((mode (TI)));
static_assert(16 == sizeof(uint128_t), "Invalid `uint128_t` size.");

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
  float80_t st[8];   /* 8*16 bytes for each FP-reg = 128 bytes */
  uint128_t xmm[16];  /* 16*16 bytes for each XMM-reg = 256 bytes */
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

class Segments {
 public:
  uint16_t ss;
  uint16_t es;
  uint16_t gs;
  uint16_t fs;
  uint16_t ds;
  uint16_t cs;
};

union Reg32 {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(4) uint32_t full;
};

static_assert(4 == sizeof(Reg32), "Invalid packing of `Reg32`.");
static_assert(0 == __builtin_offsetof(Reg32, byte.low), "Invalid packing of `Reg32::low`.");
static_assert(1 == __builtin_offsetof(Reg32, byte.high), "Invalid packing of `Reg32::high`.");
static_assert(0 == __builtin_offsetof(Reg32, word), "Invalid packing of `Reg32::word`.");
static_assert(0 == __builtin_offsetof(Reg32, dword), "Invalid packing of `Reg32::dword`.");
static_assert(0 == __builtin_offsetof(Reg32, full), "Invalid packing of `Reg32::full`.");

union Reg64 {
  alignas(1) struct {
    uint8_t low;
    uint8_t high;
  } byte;
  alignas(2) uint16_t word; 
  alignas(4) uint32_t dword;
  alignas(8) uint64_t full;
};

static_assert(8 == sizeof(Reg64), "Invalid packing of `Reg64`.");
static_assert(0 == __builtin_offsetof(Reg64, byte.low), "Invalid packing of `Reg64::low`.");
static_assert(1 == __builtin_offsetof(Reg64, byte.high), "Invalid packing of `Reg64::high`.");
static_assert(0 == __builtin_offsetof(Reg64, word), "Invalid packing of `Reg64::word`.");
static_assert(0 == __builtin_offsetof(Reg64, dword), "Invalid packing of `Reg64::dword`.");
static_assert(0 == __builtin_offsetof(Reg64, full), "Invalid packing of `Reg64::full`.");

class GPR {
 public:
  // Named the same way as the 64-bit version to keep names the same
  // across architectures.
  MCSEMA_STATE_REG rax;
  MCSEMA_STATE_REG rbx;
  MCSEMA_STATE_REG rcx;
  MCSEMA_STATE_REG rdx;
  MCSEMA_STATE_REG rsi;
  MCSEMA_STATE_REG rdi;
  MCSEMA_STATE_REG rsp;
  MCSEMA_STATE_REG rbp;

  // Not actually used in 32-bit; but useful for keeping everything consistent
  // across architectures.
  MCSEMA_STATE_REG r8;
  MCSEMA_STATE_REG r9;
  MCSEMA_STATE_REG r10;
  MCSEMA_STATE_REG r11;
  MCSEMA_STATE_REG r12;
  MCSEMA_STATE_REG r13;
  MCSEMA_STATE_REG r14;
  MCSEMA_STATE_REG r15;

  // Next program counter.
  MCSEMA_STATE_REG rip;
};

class alignas(64) State {
 private:
  // Method that will implement a basic block. We will clone this method for
  // each basic block in the code being lifted.
  __attribute__((used))
  void Block(void) noexcept {
    
    // Define read- and write-specific aliases of each register. We will
    // reference these variables from the bitcode side of things so that,
    // given a decoded register name and an operation type (read or write),
    // we can map the register to a specific field in the State structure.
#define REG_INFO(read_sel, write_sel, name) \
    auto & name ## _read = read_sel ; \
    auto & name ## _write = write_sel ;
    
    PLAT_X86_REG_INFOS()
#undef REG_INFO

  }
  
  // TODO(pag): Perform indirect branch based on program counter.
  __attribute__((used))
  void IndirectBranchResolver(void) noexcept {
    (void) gpr.rip;
  }

  FPU fpu;
  Flags flag;
  Segments seg;
  GPR gpr;
};

