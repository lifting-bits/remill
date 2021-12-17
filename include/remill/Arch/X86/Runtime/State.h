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
#  define HAS_FEATURE_AVX 1
#endif

#ifndef HAS_FEATURE_AVX512
#  define HAS_FEATURE_AVX512 1
#endif

#if HAS_FEATURE_AVX
#  define IF_AVX(...) __VA_ARGS__
#  define IF_AVX_ELSE(a, b) a
#else
#  define IF_AVX(...)
#  define IF_AVX_ELSE(a, b) b
#endif

#if HAS_FEATURE_AVX && HAS_FEATURE_AVX512
#  define IF_AVX512(...) __VA_ARGS__
#  define IF_AVX512_ELSE(a, b) a
#else
#  define IF_AVX512(...)
#  define IF_AVX512_ELSE(a, b) b
#endif

enum RequestPrivilegeLevel : uint16_t {
  kRPLRingZero = 0,
  kRPLRingOne = 1,
  kRPLRingTwo = 2,
  kRPLRingThree = 3
};

enum TableIndicator : uint16_t {
  kGlobalDescriptorTable = 0,
  kLocalDescriptorTable = 1
};

#ifndef __clang__
#  define RequestPrivilegeLevel uint16_t
#  define TableIndicator uint16_t
#endif

union SegmentSelector final {
  uint16_t flat;
  struct {
    RequestPrivilegeLevel rpi : 2;
    TableIndicator ti : 1;
    uint16_t index : 13;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(SegmentSelector) == 2,
              "Invalid packing of `union SegmentSelector`.");

struct SegmentShadow final {
  union {
    uint32_t dword;
    uint64_t qword;
  } base;
  uint32_t limit;
  uint32_t flags;
} __attribute__((packed));

static_assert(sizeof(SegmentShadow) == 16,
              "Invalid packing of `struct SegmentShadow`.");

union FPUStatusWord final {
  uint16_t flat;
  struct {
    uint16_t ie : 1;  // Invalid operation.
    uint16_t de : 1;  // Denormal operand.
    uint16_t ze : 1;  // Zero divide.
    uint16_t oe : 1;  // Overflow.
    uint16_t ue : 1;  // Underflow.
    uint16_t pe : 1;  // Precision.
    uint16_t sf : 1;  // Stack fault.
    uint16_t es : 1;  // Error summary status.
    uint16_t c0 : 1;  // Part of condition code.
    uint16_t c1 : 1;  // Used for a whole lot of stuff.
    uint16_t c2 : 1;  // Part of condition code.
    uint16_t top : 3;  // Stack pointer.
    uint16_t c3 : 1;  // Part of condition code.
    uint16_t b : 1;  // Busy.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(2 == sizeof(FPUStatusWord),
              "Invalid structure packing of `FPUFlags`.");

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

enum FPUInfinityControl : uint16_t { kInfinityProjective, kInfinityAffine };

#ifndef __clang__
#  define FPUPrecisionControl uint16_t
#  define FPURoundingControl uint16_t
#  define FPUInfinityControl uint16_t
#endif

union FPUControlWord final {
  uint16_t flat;
  struct {
    uint16_t im : 1;  // Invalid Operation.
    uint16_t dm : 1;  // Denormalized Operand.
    uint16_t zm : 1;  // Zero Divide.
    uint16_t om : 1;  // Overflow.
    uint16_t um : 1;  // Underflow.
    uint16_t pm : 1;  // Precision.
    uint16_t _rsvd0 : 2;
    FPUPrecisionControl pc : 2;  // bit 8
    FPURoundingControl rc : 2;
    FPUInfinityControl x : 1;
    uint16_t _rsvd1 : 3;
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
    uint32_t ie : 1;  // Invalid operation.
    uint32_t de : 1;  // Denormal flag.
    uint32_t ze : 1;  // Divide by zero.
    uint32_t oe : 1;  // Overflow.
    uint32_t ue : 1;  // Underflow.
    uint32_t pe : 1;  // Precision.
    uint32_t daz : 1;  // Denormals are zero.
    uint32_t im : 1;  // Invalid operation.
    uint32_t dm : 1;  // Denormal mask.
    uint32_t zm : 1;  // Divide by zero mask.
    uint32_t om : 1;  // Overflow mask.
    uint32_t um : 1;  // Underflow mask.
    uint32_t pm : 1;  // Precision mask.
    uint32_t rn : 1;  // Round negative.
    uint32_t rp : 1;  // Round positive.
    uint32_t fz : 1;  // Flush to zero.
    uint32_t _rsvd : 16;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(4 == sizeof(FPUControlStatus),
              "Invalid structure packing of `SSEControlStatus`.");

enum FPUTag : uint16_t {
  kFPUTagNonZero,
  kFPUTagZero,
  kFPUTagSpecial,  // Invalid (NaN, unsupported), infinity, denormal.
  kFPUTagEmpty
};

enum FPUAbridgedTag : uint8_t { kFPUAbridgedTagEmpty, kFPUAbridgedTagValid };

#ifndef __clang__
#  define FPUTag uint16_t
#  define FPUAbridgedTag uint8_t
#endif

// Note: Stored in top-of-stack order.
union FPUTagWord final {
  uint16_t flat;
  struct {
    FPUTag tag0 : 2;
    FPUTag tag1 : 2;
    FPUTag tag2 : 2;
    FPUTag tag3 : 2;
    FPUTag tag4 : 2;
    FPUTag tag5 : 2;
    FPUTag tag6 : 2;
    FPUTag tag7 : 2;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPUTagWord) == 2,
              "Invalid structure packing of `TagWord`.");

// Note: Stored in physical order.
union FPUAbridgedTagWord final {
  uint8_t flat;
  struct {
    FPUAbridgedTag r0 : 1;
    FPUAbridgedTag r1 : 1;
    FPUAbridgedTag r2 : 1;
    FPUAbridgedTag r3 : 1;
    FPUAbridgedTag r4 : 1;
    FPUAbridgedTag r5 : 1;
    FPUAbridgedTag r6 : 1;
    FPUAbridgedTag r7 : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPUAbridgedTagWord) == 1,
              "Invalid structure packing of `FPUAbridgedTagWord`.");

// FPU register state that conforms with `FSAVE` and `FRSTOR`.
struct FpuFSAVE {
  FPUControlWord cwd;
  uint16_t _rsvd0;
  FPUStatusWord swd;
  uint16_t _rsvd1;
  FPUTagWord ftw;
  uint16_t fop;  // Last instruction opcode.
  uint32_t ip;  // Offset in segment of last non-control FPU instruction.
  SegmentSelector cs;  // Code segment associated with `ip`.
  uint16_t _rsvd2;
  uint32_t dp;  // Operand address.
  SegmentSelector ds;  // Data segment associated with `dp`.
  uint16_t _rsvd3;
  FPUStackElem st[8];
} __attribute__((packed));

// FPU register state that conforms with `FXSAVE` and `FXRSTOR`.
struct FpuFXSAVE {
  FPUControlWord cwd;
  FPUStatusWord swd;
  FPUAbridgedTagWord ftw;
  uint8_t _rsvd0;
  uint16_t fop;  // Last instruction opcode.
  uint32_t ip;  // Offset in segment of last non-control FPU instruction.
  SegmentSelector cs;  // Code segment associated with `ip`.
  uint16_t _rsvd1;
  uint32_t dp;  // Operand address.
  SegmentSelector ds;  // Data segment associated with `dp`.
  uint16_t _rsvd2;
  FPUControlStatus mxcsr;
  FPUControlStatus mxcsr_mask;
  FPUStackElem st[8];
  vec128_t xmm[16];
} __attribute__((packed));

// FPU register state that conforms with `FXSAVE64` and `FXRSTOR64`.
struct FpuFXSAVE64 {
  FPUControlWord cwd;
  FPUStatusWord swd;
  FPUAbridgedTagWord ftw;
  uint8_t _rsvd0;
  uint16_t fop;  // Last instruction opcode.
  uint64_t ip;  // Offset in segment of last non-control FPU instruction.
  uint64_t dp;  // Operand address.
  FPUControlStatus mxcsr;
  FPUControlStatus mxcsr_mask;
  FPUStackElem st[8];
  vec128_t xmm[16];
} __attribute__((packed));

// FP register state that conforms with `FXSAVE` and `FXSAVE64`.
union alignas(16) FPU final {
  struct : public FpuFSAVE {
    uint8_t _padding0[512 - sizeof(FpuFSAVE)];
  } __attribute__((packed)) fsave;

  struct : public FpuFXSAVE {
    uint8_t _padding0[512 - sizeof(FpuFXSAVE)];
  } __attribute__((packed)) fxsave32;

  struct : public FpuFXSAVE64 {
    uint8_t _padding0[512 - sizeof(FpuFXSAVE64)];
  } __attribute__((packed)) fxsave64;
} __attribute__((packed));

#define fxsave IF_64BIT_ELSE(fxsave64, fxsave32)

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

  uint8_t _4;
  uint8_t pe;  // Precision.

  uint8_t _5;
  uint8_t ue;  // Underflow.

  uint8_t _6;
  uint8_t oe;  // Overflow.

  uint8_t _7;
  uint8_t ze;  // Divide by zero.

  uint8_t _8;
  uint8_t de;  // Denormal operand.

  uint8_t _9;
  uint8_t ie;  // Invalid operation.

  uint8_t _padding[4];
} __attribute__((packed));

static_assert(24 == sizeof(FPUStatusFlags),
              "Invalid packing of `FPUStatusFlags`.");

union alignas(8) Flags final {
  uint64_t flat;
  struct {
    uint32_t cf : 1;  // bit 0.
    uint32_t must_be_1 : 1;
    uint32_t pf : 1;
    uint32_t must_be_0a : 1;

    uint32_t af : 1;  // bit 4.
    uint32_t must_be_0b : 1;
    uint32_t zf : 1;
    uint32_t sf : 1;

    uint32_t tf : 1;  // bit 8.
    uint32_t _if : 1;  // underscore to avoid token clash.
    uint32_t df : 1;
    uint32_t of : 1;

    uint32_t iopl : 2;  // A 2-bit field, bits 12-13.
    uint32_t nt : 1;
    uint32_t must_be_0c : 1;

    uint32_t rf : 1;  // bit 16.
    uint32_t vm : 1;
    uint32_t ac : 1;  // Alignment check.
    uint32_t vif : 1;

    uint32_t vip : 1;  // bit 20.
    uint32_t id : 1;  // bit 21.
    uint32_t reserved_eflags : 10;  // bits 22-31.
    uint32_t reserved_rflags;  // bits 32-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(Flags), "Invalid structure packing of `Flags`.");

struct alignas(8) ArithFlags final {

  // Prevents LLVM from casting and `ArithFlags` into an `i8` to access `cf`.
  volatile uint8_t _0;
  uint8_t cf;  // Prevents load/store coalescing.
  volatile uint8_t _1;
  uint8_t pf;
  volatile uint8_t _2;
  uint8_t af;
  volatile uint8_t _3;
  uint8_t zf;
  volatile uint8_t _4;
  uint8_t sf;
  volatile uint8_t _5;
  uint8_t df;
  volatile uint8_t _6;
  uint8_t of;
  volatile uint8_t _7;
  volatile uint8_t _8;
} __attribute__((packed));

static_assert(16 == sizeof(ArithFlags), "Invalid packing of `ArithFlags`.");

union XCR0 {
  uint64_t flat;

  struct {
    uint32_t eax;
    uint32_t edx;
  } __attribute__((packed));

  // Bits specify what process states should be saved.
  struct {
    uint64_t x87_fpu_mmx : 1;  // Must be 1; bit 0.
    uint64_t xmm : 1;  // SSE.
    uint64_t ymm : 1;  // AVX and AVX2.
    uint64_t bndreg : 1;  // Part of MPX.
    uint64_t bndcsr : 1;  // Part of MPX.
    uint64_t opmask : 1;  // Registers k0 through k7, AVX512-only.
    uint64_t
        zmm_hi256 : 1;  // High 256 bits of ZMM0 through ZMM15, AVX512-only.
    uint64_t hi16_zmm : 1;  // ZMM16 through ZMM31, AVX512-only.
    uint64_t pkru : 1;  // Protected key stuff.
    uint64_t _reserved0 : 53;
    uint64_t lwp : 1;  // AMD lightweight profiling.
    uint64_t _reserved1 : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(XCR0), "Invalid packing of `XCR0`.");

struct alignas(8) Segments final {
  volatile uint16_t _0;
  SegmentSelector ss;
  volatile uint16_t _1;
  SegmentSelector es;
  volatile uint16_t _2;
  SegmentSelector gs;
  volatile uint16_t _3;
  SegmentSelector fs;
  volatile uint16_t _4;
  SegmentSelector ds;
  volatile uint16_t _5;
  SegmentSelector cs;
} __attribute__((packed));

static_assert(24 == sizeof(Segments), "Invalid packing of `struct Segments`.");

struct alignas(8) SegmentCaches final {
  SegmentShadow cs;
  SegmentShadow ss;
  SegmentShadow ds;
  SegmentShadow es;
  SegmentShadow fs;
  SegmentShadow gs;
} __attribute__((packed));

static_assert(96 == sizeof(SegmentCaches),
              "Invalid packing of `struct SegmentCaches`.");

enum DescriptorPrivilegeLevel : uint64_t {
  kDPLRingZero = 0,
  kDPLRingOne = 1,
  kDPLRingTwo = 2,
  kDPLRingThree = 3
};

enum DescriptorClass : uint64_t {
  kDataSegmentDescriptor,
  kCodeSegmentDescriptor,
  kSystemSegmentDescriptor,
  kGateDescriptor,
  kNotPresentDescriptor
};

enum SegmentGranularity : uint64_t {
  kSegmentGranularityNotScaled,
  kSegmentGranularityScaled
};

enum SegmentDefaultOperandSize : uint64_t {
  kSegmentDefaultOperandSize16,
  kSegmentDefaultOperandSize32
};

enum SegmentPresentStatus : uint64_t { kSegmentNotPresent, kSegmentPresent };

enum SystemDescriptorType : uint64_t {
  kSystemTypeIllegal0,
  kSystemTypeIllegal1,
  kSystemTypeLDT,
  kSystemTypeIllegal2,
  kSystemTypeIllegal3,
  kSystemTypeIllegal4,
  kSystemTypeIllegal5,
  kSystemTypeIllegal6,
  kSystemTypeIllegal7,
  kSystemTypeAvailableTSS,
  kSystemTypeIllegal8,
  kSystemTypeBusyTSS,
  kSystemTypeCallGate,
  kSystemTypeIllegal9,
  kSystemTypeInterruptGate,
  kSystemTypeTrapGate
};

enum CodeSegmentMode : uint64_t {
  kSegmentCompatibilityMode,
  kSegment64BitMode
};

enum SegmentSystemBit : uint64_t { kSegmentBitSystem, kSegmentBitUser };

#ifndef __clang__
#  define DescriptorPrivilegeLevel uint64_t
#  define DescriptorClass uint64_t
#  define SegmentGranularity uint64_t
#  define SegmentDefaultOperandSize uint64_t
#  define SegmentPresentStatus uint64_t
#  define SystemDescriptorType uint64_t
#  define CodeSegmentMode uint64_t
#  define SegmentSystemBit uint64_t
#endif

struct GenericDescriptor {
  uint64_t unused : 44;
  uint64_t sbit : 1;
  uint64_t dpl : 2;
  uint64_t present : 1;
  uint64_t unused3 : 16;
} __attribute__((packed));

static_assert(8U == sizeof(GenericDescriptor),
              "Invalid packing of `struct GenericDescriptor`.");

union SegmentDescriptor {
  uint64_t flat;
  struct {
    uint16_t limit_low : 16;
    uint16_t base_low : 16;
    uint16_t base_middle : 8;
    uint16_t system_type : 4;
    uint16_t system_access : 4;
    uint16_t limit_high : 4;
    uint16_t available : 1;

    /* Only valid for kCodeSegmentDescriptor */
    uint16_t code_mode : 1;  // Only valid for code segments.

    /* Only valid for kCodeSegmentDescriptor, kDataSegmentDescriptor */
    uint16_t default_operand_size : 1;
    uint16_t granularity : 1;

    uint16_t base_high : 8;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8U == sizeof(SegmentDescriptor),
              "Invalid packing of `struct SegmentDescriptor`.");

struct GateDescriptor {
  uint64_t target_offset_low : 16;
  uint64_t target_selector : 16;
  /* Only valid for interrupt gates. */
  uint64_t interrupt_stack_table_index : 3;
  uint64_t reserved : 5;
  uint64_t system_type : 4;
  uint64_t access : 4;
  uint64_t target_offset_middle : 16;
} __attribute__((packed));

static_assert(8U == sizeof(GateDescriptor),
              "Invalid packing of `struct GateDescriptor`.");

struct ExtensionDescriptor {
  uint64_t higher_addr : 32;
  uint64_t reserved : 32;
} __attribute__((packed));

static_assert(8U == sizeof(ExtensionDescriptor),
              "Invalid packing of `struct DescritorExtension`.");

union Descriptor {
  GenericDescriptor generic;
  SegmentDescriptor segment;
  GateDescriptor gate;
  ExtensionDescriptor extension;
} __attribute__((packed));

static_assert(8U == sizeof(Descriptor),
              "Invalid packing of `struct SystemDescriptorExtra`.");

// We don't want 32-bit lifted code to look like operations on 64-bit
// registers, because then every (bitcasted from 64 bit) store of a 32-bit
// value will look like a false- dependency on the (bitcasted from 64 bit)
// full 64-bit quantity.
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
  IF_32BIT(volatile uint32_t _padding0;)
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
  Reg ss_base;
  volatile uint64_t _1;
  Reg es_base;
  volatile uint64_t _2;
  Reg gs_base;
  volatile uint64_t _3;
  Reg fs_base;
  volatile uint64_t _4;
  Reg ds_base;
  volatile uint64_t _5;
  Reg cs_base;
} __attribute__((packed));

static_assert(96 == sizeof(AddressSpace),
              "Invalid packing of `struct AddressSpace`.");

// Named the same way as the 64-bit version to keep names the same
// across architectures. All registers are here, even the 64-bit ones. The
// 64-bit ones are not used in lifted 32-bit code.
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

// Declare val as float80_t
struct alignas(16) X87Stack final {
  struct alignas(16) {
    uint8_t _[6];
    float80_t val;
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

struct alignas(8) K_REG final {
  struct alignas(8) {
    uint64_t _0;
    uint64_t val;
  } __attribute__((packed)) elems[8];
};

static_assert(128 == sizeof(MMX), "Invalid structure packing of `MMX`.");

enum : size_t { kNumVecRegisters = 32 };

struct alignas(16) X86State : public ArchState {

  // ArchState occupies 16 bytes.

  // AVX512 has 32 vector registers, so we always include them all here for
  // consistency across the various state structures.
  VectorReg vec[kNumVecRegisters];  // 2048 bytes.

  // Two representations of flags. Makes it easy to convert from native-to-
  // lifted, as well as improved the optimizability of the aflags themselves.
  ArithFlags aflag;  // 16 bytes.
  Flags rflag;  // 8 bytes.
  Segments seg;  // 24 bytes.
  AddressSpace addr;  // 96 bytes.
  GPR gpr;  // 272 bytes.
  X87Stack st;  // 128 bytes.
  MMX mmx;  // 128 bytes.
  FPUStatusFlags sw;  // 24 bytes
  XCR0 xcr0;  // 8 bytes.
  FPU x87;  // 512 bytes
  SegmentCaches seg_caches;  // 96 bytes
  K_REG k_reg; // 128 bytes.
} __attribute__((packed));

static_assert((96 + 3264 + 16 + 128) == sizeof(X86State),
              "Invalid packing of `struct State`");

struct State : public X86State {};

union CR0Reg {
  uint64_t flat;
  struct {
    uint64_t pe : 1;
    uint64_t mp : 1;
    uint64_t em : 1;
    uint64_t ts : 1;
    uint64_t et : 1;
    uint64_t ne : 1;
    uint64_t _rsvd0 : 10;
    uint64_t wp : 1;
    uint64_t _rsvd1 : 1;
    uint64_t am : 1;
    uint64_t _rsvd2 : 10;
    uint64_t nw : 1;
    uint64_t cd : 1;
    uint64_t pg : 1;
    uint64_t _rsvd3 : 32;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(CR0Reg), "Invalid packing of CR0Reg");

union CR1Reg {
  uint64_t flat;
} __attribute__((packed));

static_assert(8 == sizeof(CR1Reg), "Invalid packing of CR1Reg");

union CR2Reg {
  uint64_t flat;
  addr_t linear_address;
} __attribute__((packed));

static_assert(8 == sizeof(CR2Reg), "Invalid packing of CR2Reg");

union CR3Reg {
  uint64_t flat;
  struct {
    uint64_t _rsvd0 : 3;
    uint64_t pwt : 1;
    uint64_t pcd : 1;
    uint64_t _rsvd1 : 7;
    uint64_t page_dir_base : 52;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(CR3Reg), "Invalid packing of CR3Reg");

union CR4Reg {
  uint64_t flat;
  struct {
    uint64_t vme : 1;
    uint64_t pvi : 1;
    uint64_t tsd : 1;
    uint64_t de : 1;
    uint64_t pse : 1;
    uint64_t pae : 1;
    uint64_t mce : 1;
    uint64_t pge : 1;
    uint64_t pce : 1;
    uint64_t osfxsr : 1;
    uint64_t osxmmexcpt : 1;
    uint64_t umip : 1;
    uint64_t _rsvd0 : 1;
    uint64_t vmxe : 1;
    uint64_t smxe : 1;
    uint64_t _rsvd1 : 1;
    uint64_t fsgsbase : 1;
    uint64_t pcide : 1;
    uint64_t osxsave : 1;
    uint64_t _rsvd2 : 1;
    uint64_t smep : 1;
    uint64_t smap : 1;
    uint64_t pke : 1;
    uint64_t _rsvd3 : 9;
    uint64_t _rsvd4 : 32;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(CR4Reg), "Invalid packing of CR4Reg");

union CR8Reg {
  uint64_t flat;
  struct {
    uint64_t tpr : 4;
    uint64_t _rsvd0 : 60;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(CR8Reg), "Invalid packing of CR8Reg");

#pragma clang diagnostic pop
