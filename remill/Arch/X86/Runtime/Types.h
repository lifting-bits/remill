/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_RUNTIME_TYPES_H_
#define REMILL_ARCH_X86_RUNTIME_TYPES_H_

typedef RnW<uint8_t> R8W;
typedef RnW<uint16_t> R16W;
typedef RnW<IF_64BIT_ELSE(uint64_t, uint32_t)> R32W;  // AMD64-ism.
typedef RnW<uint64_t> R64W;

typedef Rn<uint8_t> R8;
typedef Rn<uint16_t> R16;
typedef Rn<uint32_t> R32;
typedef Rn<uint64_t> R64;

typedef Vn<vec64_t> V64;  // Legacy MMX technology register.
typedef Vn<avec128_t> V128;  // Legacy (SSE) XMM register.

typedef Vn<avec128_t> VV128;  // AVX VEX.128-encoded XMM register.
typedef Vn<avec256_t> VV256;  // AVX YMM register.
typedef Vn<avec512_t> VV512;  // AVX512 ZMM register.

typedef IF_AVX512_ELSE(avec512_t, IF_AVX_ELSE(avec256_t, avec128_t))
        WriteVecType;

typedef VnW<vec32_t> V32W;  // Legacy MMX technology register.
typedef VnW<vec64_t> V64W;  // Legacy MMX technology register.
typedef VnW<avec128_t> V128W;  // Legacy (SSE) XMM register.

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

ALWAYS_INLINE static IF_64BIT_ELSE(uint64_t, uint32_t) R(const Reg &reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

ALWAYS_INLINE static IF_64BIT_ELSE(uint64_t, uint32_t) &W(Reg &reg) {
  return reg.IF_64BIT_ELSE(qword, dword);
}

ALWAYS_INLINE static addr_t A(const Reg &reg) {
  return reg.aword;
}


typedef Rn<float32_t> RF32;
typedef RnW<float32_t> RF32W;

typedef Rn<float64_t> RF64;
typedef RnW<float64_t> RF64W;

// Internally, we boil F80s down into F64s.
typedef Rn<float64_t> RF80;
typedef RnW<float64_t> RF80W;

struct MemoryWriterfloat80_t {
  ALWAYS_INLINE void operator=(const float32_t &val_) const {
    float80_t val = val_;
    __remill_memory_order = __remill_write_memory_f80(__remill_memory_order,
                                                      addr, val);
  }
  ALWAYS_INLINE void operator=(const float64_t &val_) const {
    float80_t val = val_;
    __remill_memory_order = __remill_write_memory_f80(__remill_memory_order,
                                                      addr, val);
  }
  ALWAYS_INLINE
  void operator=(const float80_t &val) const {
    __remill_memory_order = __remill_write_memory_f80(__remill_memory_order,
                                                      addr, val);
  }
  addr_t addr;
};

ALWAYS_INLINE static float64_t R(MF80 mem) {
  float80_t val;
  __remill_memory_order = __remill_read_memory_f80(__remill_memory_order,
                                                   mem.addr, val);
  float64_t out_val;
  __remill_read_f80(val, out_val);
  return out_val;
}

ALWAYS_INLINE static MemoryWriterfloat80_t W(MF80W mem) {
  return MemoryWriterfloat80_t { mem.addr };
}


#endif  // REMILL_ARCH_X86_RUNTIME_TYPES_H_
