/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_X86_RUNTIME_TYPES_H_
#define MCSEMA_ARCH_X86_RUNTIME_TYPES_H_

typedef RnW<uint8_t> R8W;
typedef RnW<uint16_t> R16W;
typedef RnW<IF_64BIT_ELSE(uint64_t, uint32_t)> R32W;  // AMD64-ism.
typedef RnW<uint64_t> R64W;

typedef Rn<uint8_t> R8;
typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;

typedef Vn<vec64_t> V64;
typedef Vn<avec128_t> V128;
typedef Vn<avec256_t> V256;
typedef Vn<avec512_t> V512;

typedef IF_AVX512_ELSE(avec512_t, IF_AVX_ELSE(avec256_t, avec128_t))
        WriteVecType;

typedef VnW<vec64_t> V64W;  // Legacy MMX technology register.
typedef VnW<WriteVecType> V128W;
typedef VnW<WriteVecType> V256W;
typedef VnW<WriteVecType> V512W;

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;
typedef MnW<uint32_t> M32W;
typedef MnW<uint64_t> M64W;

typedef MnW<vec64_t> MV64W;
typedef MnW<vec128_t> MV128W;
typedef MnW<vec256_t> MV256W;
typedef MnW<vec512_t> MV512W;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;
typedef Mn<uint32_t> M32;
typedef Mn<uint64_t> M64;

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

ALWAYS_INLINE static IF_64BIT_ELSE(uint64_t, uint32_t) R(const Reg &reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

ALWAYS_INLINE static IF_64BIT_ELSE(uint64_t, uint32_t) &W(Reg &reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

#endif  // MCSEMA_ARCH_X86_RUNTIME_TYPES_H_
