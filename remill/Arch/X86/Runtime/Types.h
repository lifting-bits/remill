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

union bcd_digit_pair_t {
  uint8_t u8;
  struct {
    uint8_t lsd:4;  // Least-significant digit
    uint8_t msd:4;  // Most-significant digit
  } __attribute((packed)) pair;
} __attribute((packed));

// TODO(joe): Assumes little endian.
// 80-bit packed binary-coded decimal.
struct bcd80_t final {
  union bcd_digit_pair_t digit_pairs[9];
  struct {
    uint8_t _unused:7;  // No meaning in encoding
    uint8_t is_negative:1;
  } __attribute((packed));
} __attribute__((packed));

static_assert(10 == sizeof(bcd80_t), "Invalid `bcd80_t` size.");

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
typedef Vn<vec256_t> V256;  // AVX YMM register.
typedef Vn<vec256_t> VV256;  // AVX YMM register.
typedef Vn<vec512_t> V512;  // AVX512 ZMM register.
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
typedef MnW<uint128_t> M128W;

typedef MnW<bcd80_t> MBCD80W;

typedef MnW<float32_t> MF32W;
typedef MnW<float64_t> MF64W;
typedef MnW<float80_t> MF80W;

typedef Mn<float32_t> MF32;
typedef Mn<float64_t> MF64;
typedef Mn<float80_t> MF80;

typedef MVnW<vec32_t> MV32W;
typedef MVnW<vec64_t> MV64W;
typedef MVnW<vec128_t> MV128W;
typedef MVnW<vec256_t> MV256W;
typedef MVnW<vec512_t> MV512W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;
typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;
typedef Mn<uint128_t> M128;

typedef Mn<bcd80_t> MBCD80;

typedef MVn<vec8_t> MV8;
typedef MVn<vec16_t> MV16;
typedef MVn<vec32_t> MV32;
typedef MVn<vec64_t> MV64;
typedef MVn<vec128_t> MV128;
typedef MVn<vec256_t> MV256;
typedef MVn<vec512_t> MV512;

typedef In<uint8_t> I8;
typedef In<uint16_t> I16;
typedef In<uint32_t> I32;
typedef In<uint64_t> I64;

typedef In<addr_t> PC;

typedef Rn<float32_t> RF32;
typedef RnW<float32_t> RF32W;

typedef Rn<float64_t> RF64;
typedef RnW<float64_t> RF64W;

// Internally, we boil F80s down into F64s.
typedef Rn<float64_t> RF80;
typedef RnW<float64_t> RF80W;
