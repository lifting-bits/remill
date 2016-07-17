/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_RUNTIME_TYPES_H_
#define REMILL_ARCH_X86_RUNTIME_TYPES_H_

// What's going on with `R32W`? In 64-bit code, writes to the 32-bit general
// purpose registers actually clear the high 32-bits of the associated 64-bit
// registers, so we want to model that behavior.
typedef RnW<uint8_t> R8W;
typedef RnW<uint16_t> R16W;
typedef RnW<IF_64BIT_ELSE(uint64_t, uint32_t)> R32W;  // AMD64-ism.
typedef RnW<uint64_t> R64W;

typedef Rn<uint8_t> R8;
typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;

// What's this `RVn` (and `RVnW` later)? The idea here is that some instructions
// that operate on vectors also operate on MMX technology registers, or just
// plain old GPRs. We don't want to have to create a special version of those
// instruction implementations, so we "fake" the 32- and 64-bit vector types
// to be more register-like (passed as an `addr_t`), and hide the vectorization
// of those values in the operators for reading/writing to vectors.
typedef RVn<vec32_t> V32;  // GPR holding a vector.
typedef RVn<vec64_t> V64;  // MMX technology register, or GPR holding a vector.

typedef Vn<vec128_t> V128;  // Legacy (SSE) XMM register.
typedef Vn<vec128_t> VV128;  // AVX VEX.128-encoded XMM register.
typedef Vn<vec256_t> VV256;  // AVX YMM register.
typedef Vn<vec512_t> VV512;  // AVX512 ZMM register.

// What's going on here? If we're using AVX or AVX512, then writes to XMM
// registers are really writing to the YMM or ZMM registers, so we want to
// represent that. We distinguish SSE and AVX semantics by using things like
// `V128W` for writing to an XMM register, but `VV128W` for writing to an
// extended AVX(512) register like YMM or ZMM.
typedef IF_AVX512_ELSE(vec512_t, IF_AVX_ELSE(vec256_t, vec128_t))
        WriteVecType;
typedef RVnW<IF_64BIT_ELSE(vec64_t, vec32_t)> V32W;  // GPR with vector.
typedef RVnW<vec64_t> V64W;  // MMX technology register, or GPR with vector.
typedef VnW<vec128_t> V128W;  // Legacy (SSE) XMM register.

typedef VnW<WriteVecType> VV128W;  // AVX VEX.128-encoded XMM register.
typedef VnW<WriteVecType> VV256W;  // AVX YMM register.
typedef VnW<WriteVecType> VV512W;  // AVX512 ZMM register.

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;
typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;

typedef MnW<float32_t> MF32W;
typedef MnW<float64_t> MF64W;
typedef MnW<float80_t> MF80W;

typedef Mn<float32_t> MF32;
typedef Mn<float64_t> MF64;
typedef Mn<float80_t> MF80;

typedef MnW<vec32_t> MV32W;
typedef MnW<vec64_t> MV64W;
typedef MnW<vec128_t> MV128W;
typedef MnW<vec256_t> MV256W;
typedef MnW<vec512_t> MV512W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;
typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;

typedef Mn<vec8_t> MV8;
typedef Mn<vec16_t> MV16;
typedef Mn<vec32_t> MV32;
typedef Mn<vec64_t> MV64;
typedef Mn<vec128_t> MV128;
typedef Mn<vec256_t> MV256;
typedef Mn<vec512_t> MV512;

typedef In<uint8_t> I8;
typedef In<uint16_t> I16;
typedef In<uint32_t> I32;
typedef In<uint64_t> I64;

typedef addr_t PC;
typedef addr_t ADDR;

typedef Rn<float32_t> RF32;
typedef RnW<float32_t> RF32W;

typedef Rn<float64_t> RF64;
typedef RnW<float64_t> RF64W;

// Internally, we boil F80s down into F64s.
typedef Rn<float64_t> RF80;
typedef RnW<float64_t> RF80W;

#endif  // REMILL_ARCH_X86_RUNTIME_TYPES_H_
