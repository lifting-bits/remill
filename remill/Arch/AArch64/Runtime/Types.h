/*
 * Types.h
 *
 *  Created on: May 9, 2017
 *      Author: akshayk
 */

#ifndef REMILL_ARCH_AARCH64_RUNTIME_TYPES_H_
#define REMILL_ARCH_AARCH64_RUNTIME_TYPES_H_

// We need this for boolean conditions, used in branch instructions.
typedef RnW<uint8_t> R8W;

typedef RnW<uint8_t> R8W;
typedef RnW<uint16_t> R16W;

// Note: ARM zero-extends like x86, but the smallest register size that
// can be accessed is 32 bits.
typedef RnW<uint64_t> R32W;
typedef RnW<uint64_t> R64W;

typedef Rn<uint8_t> R8;
typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;

typedef RVn<vec32_t> V32;
typedef RVn<vec64_t> V64;

typedef RVnW<IF_64BIT_ELSE(vec64_t, vec32_t)> V32W;
typedef RVnW<vec64_t> V64W;

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;
typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;

typedef MVnW<vec32_t> MV32W;
typedef MVnW<vec64_t> MV64W;
typedef MVnW<vec128_t> MV128W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;

typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;

typedef MVn<vec32_t> MV32;
typedef MVn<vec64_t> MV64;
typedef MVn<vec128_t> MV128;

typedef In<uint32_t> I32;
typedef In<uint64_t> I64;

typedef In<addr_t> PC;
typedef In<addr_t> ADDR;

#endif /* REMILL_ARCH_AARCH64_RUNTIME_TYPES_H_ */
