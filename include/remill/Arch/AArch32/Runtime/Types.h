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

// We need this for boolean conditions, used in branch instructions.
typedef RnW<uint8_t> R8W;

typedef RnW<uint8_t> R8W;
typedef RnW<uint16_t> R16W;

// Note: AArch64 zero-extends like x86, but the smallest register size that
// can be accessed is 32 bits.
typedef RnW<uint32_t> R32W;

typedef Rn<uint8_t> R8;

// typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;

typedef Vn<vec8_t> V8;
typedef Vn<vec16_t> V16;
typedef Vn<vec32_t> V32;
typedef Vn<vec64_t> V64;
typedef Vn<vec128_t> V128;
typedef VnW<vec128_t> V128W;

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;
typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;

typedef MVnW<vec8_t> MV8W;
typedef MVnW<vec16_t> MV16W;
typedef MVnW<vec32_t> MV32W;
typedef MVnW<vec64_t> MV64W;
typedef MVnW<vec128_t> MV128W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;

typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;

typedef MVn<vec8_t> MV8;
typedef MVn<vec16_t> MV16;
typedef MVn<vec32_t> MV32;
typedef MVn<vec64_t> MV64;
typedef MVn<vec128_t> MV128;
typedef MVn<vec256_t> MV256;

typedef In<uint8_t> I8;
typedef In<uint16_t> I16;
typedef In<uint32_t> I32;

typedef In<float32_t> F32;
typedef In<float64_t> F64;

typedef In<addr_t> PC;
typedef In<addr_t> ADDR;
