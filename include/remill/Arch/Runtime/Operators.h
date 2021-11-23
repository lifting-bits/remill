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

struct Memory;
struct State;

#include "Float.h"

namespace {

ALWAYS_INLINE static uint128_t __remill_read_memory_128(Memory *mem,
                                                        addr_t addr);

ALWAYS_INLINE static Memory *__remill_write_memory_128(Memory *mem, addr_t addr,
                                                       uint128_t val);

#define MAKE_UNDEF(n) \
  ALWAYS_INLINE static uint##n##_t Undefined(uint##n##_t) { \
    return __remill_undefined_##n(); \
  } \
  ALWAYS_INLINE static uint##n##_t Undefined(Rn<uint##n##_t>) { \
    return __remill_undefined_##n(); \
  } \
  ALWAYS_INLINE static uint##n##_t Undefined(RnW<uint##n##_t>) { \
    return __remill_undefined_##n(); \
  } \
  ALWAYS_INLINE static uint##n##_t Undefined(Mn<uint##n##_t>) { \
    return __remill_undefined_##n(); \
  } \
  ALWAYS_INLINE static uint##n##_t Undefined(MnW<uint##n##_t>) { \
    return __remill_undefined_##n(); \
  }

MAKE_UNDEF(8)
MAKE_UNDEF(16)
MAKE_UNDEF(32)
MAKE_UNDEF(64)

#undef MAKE_UNDEF

#define READBIT(A, B) ((A >> B) & 1)

#define MAKE_SIGNED_MEM_ACCESS(size) \
  ALWAYS_INLINE static int##size##_t __remill_read_memory_s##size( \
      Memory *mem, addr_t addr) { \
    return static_cast<int##size##_t>(__remill_read_memory_##size(mem, addr)); \
  } \
\
  ALWAYS_INLINE static Memory *__remill_write_memory_s##size( \
      Memory *mem, addr_t addr, int##size##_t val) { \
    return __remill_write_memory_##size(mem, addr, \
                                        static_cast<uint##size##_t>(val)); \
  }

MAKE_SIGNED_MEM_ACCESS(8)
MAKE_SIGNED_MEM_ACCESS(16)
MAKE_SIGNED_MEM_ACCESS(32)
MAKE_SIGNED_MEM_ACCESS(64)
MAKE_SIGNED_MEM_ACCESS(128)

// Read a value directly.
ALWAYS_INLINE static bool _Read(Memory *, bool val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static uint8_t _Read(Memory *, uint8_t val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static uint16_t _Read(Memory *, uint16_t val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static uint32_t _Read(Memory *, uint32_t val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static uint64_t _Read(Memory *, uint64_t val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static float32_t _Read(Memory *, float32_t val) {
  return val;
}

// Read a value directly.
ALWAYS_INLINE static float64_t _Read(Memory *, float64_t val) {
  return val;
}

ALWAYS_INLINE static float80_t _Read(Memory *, float80_t val) {
  return val;
}

ALWAYS_INLINE static float32_t _Read(Memory *, In<float32_t> imm) {
  return reinterpret_cast<const float32_t &>(imm.val);
}

ALWAYS_INLINE static float64_t _Read(Memory *, In<float64_t> imm) {
  return reinterpret_cast<const float64_t &>(imm.val);
}

ALWAYS_INLINE static float80_t _Read(Memory *, In<float80_t> imm) {
  return reinterpret_cast<const float80_t &>(imm.val);
}

template <typename T>
ALWAYS_INLINE static T _Read(Memory *, In<T> imm) {
  return static_cast<T>(imm.val);
}

template <typename T>
ALWAYS_INLINE static T _Read(Memory *, Rn<T> reg) {
  return static_cast<T>(reg.val);
}

template <typename T>
ALWAYS_INLINE static T _Read(Memory *, RnW<T> reg) {
  return static_cast<T>(*(reg.val_ref));
}

// Make read operators for reading integral values from memory.
#define MAKE_MREAD(size, ret_size, type_prefix, access_suffix) \
  ALWAYS_INLINE static type_prefix##ret_size##_t _Read( \
      Memory *&memory, Mn<type_prefix##size##_t> op) { \
    return __remill_read_memory_##access_suffix(memory, op.addr); \
  } \
\
  ALWAYS_INLINE static type_prefix##ret_size##_t _Read( \
      Memory *&memory, MnW<type_prefix##size##_t> op) { \
    return __remill_read_memory_##access_suffix(memory, op.addr); \
  }

MAKE_MREAD(8, 8, uint, 8)
MAKE_MREAD(16, 16, uint, 16)
MAKE_MREAD(32, 32, uint, 32)
MAKE_MREAD(64, 64, uint, 64)
MAKE_MREAD(128, 128, uint, 128)

MAKE_MREAD(32, 32, float, f32)
MAKE_MREAD(64, 64, float, f64)

#undef MAKE_MREAD

ALWAYS_INLINE static float80_t _Read(Memory *&memory, Mn<float80_t> op) {
  native_float80_t val;
  memory = __remill_read_memory_f80(memory, op.addr, val);
  return val;
}

ALWAYS_INLINE static float80_t _Read(Memory *&memory, MnW<float80_t> op) {
  native_float80_t val;
  memory = __remill_read_memory_f80(memory, op.addr, val);
  return val;
}

// Basic write form for references.
template <typename T>
ALWAYS_INLINE static Memory *_Write(Memory *memory, T &dst, T src) {
  dst = src;
  return memory;
}

// Make write operators for writing values to registers.
#define MAKE_RWRITE(type) \
  ALWAYS_INLINE static Memory *_Write(Memory *memory, RnW<type> reg, \
                                      type val) { \
    *(reg.val_ref) = val; \
    return memory; \
  }

MAKE_RWRITE(uint8_t)
MAKE_RWRITE(uint16_t)
MAKE_RWRITE(uint32_t)
MAKE_RWRITE(uint64_t)
MAKE_RWRITE(float32_t)
MAKE_RWRITE(float64_t)
MAKE_RWRITE(float80_t)

#undef MAKE_RWRITE

// Make write operators for writing values to memory.
#define MAKE_MWRITE(size, write_size, mem_prefix, type_prefix, access_suffix) \
  ALWAYS_INLINE static Memory *_Write(Memory *memory, \
                                      MnW<mem_prefix##size##_t> op, \
                                      type_prefix##write_size##_t val) { \
    return __remill_write_memory_##access_suffix(memory, op.addr, val); \
  }

MAKE_MWRITE(8, 8, uint, uint, 8)
MAKE_MWRITE(16, 16, uint, uint, 16)
MAKE_MWRITE(32, 32, uint, uint, 32)
MAKE_MWRITE(64, 64, uint, uint, 64)
MAKE_MWRITE(128, 128, uint, uint, 128)

MAKE_MWRITE(32, 32, float, float, f32)
MAKE_MWRITE(64, 64, float, float, f64)
MAKE_MWRITE(80, 80, float, float, f80)

#undef MAKE_MWRITE

#define MAKE_READRV(prefix, size, accessor, base_type) \
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *, RVnW<T> vec) \
      ->decltype(T().accessor) { \
    return reinterpret_cast<T *>(vec.val_ref)->accessor; \
  } \
\
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *, RVn<T> vec) \
      ->decltype(T().accessor) { \
    return reinterpret_cast<const T *>(&vec.val)->accessor; \
  }

MAKE_READRV(U, 8, bytes, uint8_t)
MAKE_READRV(U, 16, words, uint16_t)
MAKE_READRV(U, 32, dwords, uint32_t)
MAKE_READRV(U, 64, qwords, uint64_t)

MAKE_READRV(S, 8, sbytes, int8_t)
MAKE_READRV(S, 16, swords, int16_t)
MAKE_READRV(S, 32, sdwords, int32_t)
MAKE_READRV(S, 64, sqwords, int64_t)

MAKE_READRV(F, 32, floats, float32_t)
MAKE_READRV(F, 64, doubles, float64_t)
MAKE_READRV(F, 80, tdoubles, float80_t)

#undef MAKE_READRV

#define MAKE_READV(prefix, size, accessor) \
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *, VnW<T> vec) \
      ->decltype(T().accessor) { \
    return reinterpret_cast<T *>(vec.val_ref)->accessor; \
  } \
\
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *, Vn<T> vec) \
      ->decltype(T().accessor) { \
    return reinterpret_cast<const T *>(vec.val)->accessor; \
  }

MAKE_READV(U, 8, bytes)
MAKE_READV(U, 16, words)
MAKE_READV(U, 32, dwords)
MAKE_READV(U, 64, qwords)
MAKE_READV(U, 128, dqwords)

MAKE_READV(S, 8, sbytes)
MAKE_READV(S, 16, swords)
MAKE_READV(S, 32, sdwords)
MAKE_READV(S, 64, sqwords)
MAKE_READV(S, 128, sdqwords)

MAKE_READV(F, 32, floats)
MAKE_READV(F, 64, doubles)
MAKE_READV(F, 80, tdouble)

#undef MAKE_READV

#define MAKE_MREADV(prefix, size, vec_accessor, mem_accessor) \
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *memory, MVn<T> mem) \
      ->decltype(T().vec_accessor) { \
    decltype(T().vec_accessor) vec = {}; \
    const addr_t el_size = sizeof(vec.elems[0]); \
    _Pragma("unroll") for (addr_t i = 0; i < NumVectorElems(vec); ++i) { \
      vec.elems[i] = __remill_read_memory_##mem_accessor( \
          memory, mem.addr + (i * el_size)); \
    } \
    return vec; \
  } \
\
  template <typename T> \
  ALWAYS_INLINE static auto _##prefix##ReadV##size(Memory *memory, \
                                                   MVnW<T> mem) \
      ->decltype(T().vec_accessor) { \
    decltype(T().vec_accessor) vec = {}; \
    const addr_t el_size = sizeof(vec.elems[0]); \
    _Pragma("unroll") for (addr_t i = 0; i < NumVectorElems(vec); ++i) { \
      vec.elems[i] = __remill_read_memory_##mem_accessor( \
          memory, mem.addr + (i * el_size)); \
    } \
    return vec; \
  }

MAKE_MREADV(U, 8, bytes, 8)
MAKE_MREADV(U, 16, words, 16)
MAKE_MREADV(U, 32, dwords, 32)
MAKE_MREADV(U, 64, qwords, 64)
MAKE_MREADV(U, 128, dqwords, 128)

MAKE_MREADV(S, 8, sbytes, s8)
MAKE_MREADV(S, 16, swords, s16)
MAKE_MREADV(S, 32, sdwords, s32)
MAKE_MREADV(S, 64, sqwords, s64)
MAKE_MREADV(S, 128, sdqwords, s128)

MAKE_MREADV(F, 32, floats, f32)
MAKE_MREADV(F, 64, doubles, f64)
MAKE_MREADV(F, 80, tdoubles, f80)

#undef MAKE_MREADV

#define MAKE_WRITEV(prefix, size, accessor, kind, base_type) \
  template <typename T> \
  ALWAYS_INLINE static Memory *_##prefix##WriteV##size( \
      Memory *memory, kind<T> vec, base_type val) { \
    auto &sub_vec = reinterpret_cast<T *>(vec.val_ref)->accessor; \
    sub_vec.elems[0] = val; \
    _Pragma("unroll") for (addr_t i = 1; i < NumVectorElems(sub_vec); ++i) { \
      sub_vec.elems[i] = 0; \
    } \
    return memory; \
  } \
\
  template <typename T, typename V> \
  ALWAYS_INLINE static Memory *_##prefix##WriteV##size( \
      Memory *memory, kind<T> vec, const V &val) { \
    static_assert(sizeof(T) >= sizeof(V), "Object to WriteV is too big."); \
    typedef decltype(T().accessor.elems[0]) BT; \
    typedef decltype(V().elems[0]) VT; \
    static_assert(std::is_same<BT, VT>::value, \
                  "Incompatible types to a write to a vector register"); \
    auto &sub_vec = reinterpret_cast<T *>(vec.val_ref)->accessor; \
    _Pragma("unroll") for (addr_t i = 0; i < NumVectorElems(val); ++i) { \
      sub_vec.elems[i] = val.elems[i]; \
    } \
    _Pragma("unroll") for (addr_t i = NumVectorElems(val); \
                           i < NumVectorElems(sub_vec); ++i) { \
      sub_vec.elems[i] = 0; \
    } \
    return memory; \
  }

MAKE_WRITEV(U, 8, bytes, VnW, uint8_t)
MAKE_WRITEV(U, 16, words, VnW, uint16_t)
MAKE_WRITEV(U, 32, dwords, VnW, uint32_t)
MAKE_WRITEV(U, 64, qwords, VnW, uint64_t)
MAKE_WRITEV(U, 128, dqwords, VnW, uint128_t)

MAKE_WRITEV(S, 8, sbytes, VnW, int8_t)
MAKE_WRITEV(S, 16, swords, VnW, int16_t)
MAKE_WRITEV(S, 32, sdwords, VnW, int32_t)
MAKE_WRITEV(S, 64, sqwords, VnW, int64_t)
MAKE_WRITEV(S, 128, sdqwords, VnW, int128_t)

MAKE_WRITEV(F, 32, floats, VnW, float32_t)
MAKE_WRITEV(F, 64, doubles, VnW, float64_t)
MAKE_WRITEV(F, 80, tdoubles, VnW, float80_t)

MAKE_WRITEV(U, 8, bytes, RVnW, uint8_t)
MAKE_WRITEV(U, 16, words, RVnW, uint16_t)
MAKE_WRITEV(U, 32, dwords, RVnW, uint32_t)
MAKE_WRITEV(U, 64, qwords, RVnW, uint64_t)

MAKE_WRITEV(S, 8, sbytes, RVnW, int8_t)
MAKE_WRITEV(S, 16, swords, RVnW, int16_t)
MAKE_WRITEV(S, 32, sdwords, RVnW, int32_t)
MAKE_WRITEV(S, 64, sqwords, RVnW, int64_t)

MAKE_WRITEV(F, 32, floats, RVnW, float32_t)
MAKE_WRITEV(F, 64, doubles, RVnW, float64_t)
MAKE_WRITEV(F, 80, tdoubles, RVnW, float80_t)

#undef MAKE_WRITEV

#define MAKE_MWRITEV(prefix, size, vec_accessor, mem_accessor, base_type) \
  template <typename T> \
  ALWAYS_INLINE static Memory *_##prefix##WriteV##size( \
      Memory *memory, MVnW<T> mem, base_type val) { \
    T vec{}; \
    const addr_t el_size = sizeof(base_type); \
    vec.vec_accessor.elems[0] = val; \
    _Pragma("unroll") for (addr_t i = 0; i < NumVectorElems(vec.vec_accessor); \
                           ++i) { \
      memory = __remill_write_memory_##mem_accessor( \
          memory, mem.addr + (i * el_size), vec.vec_accessor.elems[i]); \
    } \
    return memory; \
  } \
\
  template <typename T, typename V> \
  ALWAYS_INLINE static Memory *_##prefix##WriteV##size( \
      Memory *memory, MVnW<T> mem, const V &val) { \
    static_assert(sizeof(T) == sizeof(V), "Invalid value size for MVnW."); \
    typedef decltype(T().vec_accessor) BT; \
    typedef decltype(V()) VT; \
    static_assert(std::is_same<BT, VT>::value, \
                  "Incompatible types to a write to a vector register"); \
    const addr_t el_size = sizeof(base_type); \
    _Pragma("unroll") for (addr_t i = 0; i < NumVectorElems(val); ++i) { \
      memory = __remill_write_memory_##mem_accessor( \
          memory, mem.addr + (i * el_size), val.elems[i]); \
    } \
    return memory; \
  }

MAKE_MWRITEV(U, 8, bytes, 8, uint8_t)
MAKE_MWRITEV(U, 16, words, 16, uint16_t)
MAKE_MWRITEV(U, 32, dwords, 32, uint32_t)
MAKE_MWRITEV(U, 64, qwords, 64, uint64_t)
MAKE_MWRITEV(U, 128, dqwords, 128, uint128_t)

MAKE_MWRITEV(S, 8, sbytes, s8, int8_t)
MAKE_MWRITEV(S, 16, swords, s16, int16_t)
MAKE_MWRITEV(S, 32, sdwords, s32, int32_t)
MAKE_MWRITEV(S, 64, sqwords, s64, int64_t)
MAKE_MWRITEV(S, 128, sdqwords, s128, int128_t)

MAKE_MWRITEV(F, 32, floats, f32, float32_t)
MAKE_MWRITEV(F, 64, doubles, f64, float64_t)
MAKE_MWRITEV(F, 80, tdoubles, f80, float80_t)

#undef MAKE_MWRITEV

#define MAKE_WRITE_REF(type) \
  ALWAYS_INLINE static Memory *_Write(Memory *memory, type &ref, type val) { \
    ref = val; \
    return memory; \
  }

MAKE_WRITE_REF(bool)
MAKE_WRITE_REF(uint8_t)
MAKE_WRITE_REF(uint16_t)
MAKE_WRITE_REF(uint32_t)
MAKE_WRITE_REF(uint64_t)
MAKE_WRITE_REF(uint128_t)
MAKE_WRITE_REF(float32_t)
MAKE_WRITE_REF(float64_t)
MAKE_WRITE_REF(float80_t)

#undef MAKE_WRITE_REF

#define MAKE_CMPXCHG(size, type_prefix, access_suffix) \
  template <typename T> \
  ALWAYS_INLINE static bool _CmpXchg(Memory *&memory, RnW<T> op, \
                                     type_prefix##size##_t &expected, \
                                     type_prefix##size##_t desired) { \
    if (decltype(expected)(*op.val_ref) == expected) { \
      *op.val_ref = desired; \
      return true; \
    } else { \
      expected = *reinterpret_cast<type_prefix##size##_t *>(op.val_ref); \
      return false; \
    } \
  } \
\
  template <typename T> \
  ALWAYS_INLINE static bool _CmpXchg(Memory *&memory, MnW<T> op, \
                                     type_prefix##size##_t &expected, \
                                     type_prefix##size##_t desired) { \
    auto prev_val = expected; \
    memory = __remill_compare_exchange_memory_##access_suffix( \
        memory, op.addr, expected, desired); \
    return prev_val == expected; \
  }

MAKE_CMPXCHG(8, uint, 8)
MAKE_CMPXCHG(16, uint, 16)
MAKE_CMPXCHG(32, uint, 32)
MAKE_CMPXCHG(64, uint, 64)
MAKE_CMPXCHG(128, uint, 128)

#undef MAKE_CMPXCHG
#define UCmpXchg(op, oldval, newval) _CmpXchg(memory, op, oldval, newval)

#define MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, size, type_prefix, op) \
  template <typename T> \
  ALWAYS_INLINE type_prefix##size##_t _U##name(Memory *&memory, MnW<T> addr, \
                                               type_prefix##size##_t value) { \
    memory = __remill_##intrinsic_name##_##size(memory, addr.addr, value); \
    return value; \
  } \
\
  template <typename T> \
  ALWAYS_INLINE type_prefix##size##_t _U##name(Memory *&memory, RnW<T> addr, \
                                               type_prefix##size##_t value) { \
    auto prev_value = \
        *reinterpret_cast<type_prefix##size##_t *>(addr.val_ref); \
    *addr.val_ref = prev_value op value; \
    return prev_value; \
  }

#define MAKE_ATOMIC(name, intrinsic_name, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 8, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 16, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 32, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 64, uint, op)

MAKE_ATOMIC(FetchAdd, fetch_and_add, +)
MAKE_ATOMIC(FetchSub, fetch_and_sub, -)
MAKE_ATOMIC(FetchOr, fetch_and_or, |)
MAKE_ATOMIC(FetchAnd, fetch_and_and, &)
MAKE_ATOMIC(FetchXor, fetch_and_xor, ^)

#undef MAKE_ATOMIC
#undef MAKE_ATOMIC_INTRINSIC

#define UFetchAdd(op1, op2) _UFetchAdd(memory, op1, op2)
#define UFetchSub(op1, op2) _UFetchSub(memory, op1, op2)
#define UFetchOr(op1, op2) _UFetchOr(memory, op1, op2)
#define UFetchAnd(op1, op2) _UFetchAnd(memory, op1, op2)
#define UFetchXor(op1, op2) _UFetchXor(memory, op1, op2)

#define MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, size, type_prefix, op) \
  template <typename T> \
  ALWAYS_INLINE type_prefix##size##_t _U##name(Memory *&memory, MnW<T> addr, \
                                               type_prefix##size##_t value) { \
    memory = __remill_##intrinsic_name##_##size(memory, addr.addr, value); \
    return value; \
  } \
\
  template <typename T> \
  ALWAYS_INLINE type_prefix##size##_t _U##name(Memory *&memory, RnW<T> addr, \
                                               type_prefix##size##_t value) { \
    auto prev_value = \
        *reinterpret_cast<type_prefix##size##_t *>(addr.val_ref); \
    *addr.val_ref = value; \
    return prev_value op value; \
  }

#define MAKE_ATOMIC(name, intrinsic_name, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 8, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 16, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 32, uint, op) \
  MAKE_ATOMIC_INTRINSIC(name, intrinsic_name, 64, uint, op)

MAKE_ATOMIC(AddFetch, add_and_fetch, +)
MAKE_ATOMIC(SubFetch, sub_and_fetch, -)
MAKE_ATOMIC(OrFetch, or_and_fetch, |)
MAKE_ATOMIC(AndFetch, and_and_fetch, &)
MAKE_ATOMIC(XorFetch, xor_and_fetch, ^)

#undef MAKE_ATOMIC
#undef MAKE_ATOMIC_INTRINSIC

#define UAddFetch(op1, op2) _UAddFetch(memory, op1, op2)
#define USubFetch(op1, op2) _USubFetch(memory, op1, op2)
#define UOrFetch(op1, op2) _UOrFetch(memory, op1, op2)
#define UAndFetch(op1, op2) _UAndFetch(memory, op1, op2)
#define UXorFetch(op1, op2) _UXorFetch(memory, op1, op2)

// For the sake of esthetics and hiding the small-step semantics of memory
// operands, we use this macros to implicitly pass in the `memory` operand,
// which we know will be defined in semantics functions.
#define Read(op) _Read(memory, op)

// Write a source value to a destination operand, where the sizes of the
// values must match.
#define Write(op, val) \
  do { \
    static_assert(sizeof(typename BaseType<decltype(op)>::BT) == sizeof(val), \
                  "Bad write!"); \
    memory = _Write(memory, op, (val)); \
  } while (false)


#if !defined(issignaling)

ALWAYS_INLINE bool issignaling(float32_t x) {
  const nan32_t x_nan = {x};
  return x_nan.exponent == 0xFFU && !x_nan.is_quiet_nan && x_nan.payload;
}

ALWAYS_INLINE bool issignaling(float64_t x) {
  const nan64_t x_nan = {x};
  return x_nan.exponent == 0x7FFU && !x_nan.is_quiet_nan && x_nan.payload;
}

ALWAYS_INLINE bool issignaling(float80_t x) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
// On non-x86 architectures, native_float80_t is defined as a double,
// which is identical to the float64_t definition above
  const nan80_t x_nan = {x};
  return x_nan.exponent == 0x7FFFU && !x_nan.is_quiet_nan && x_nan.payload && x_nan.interger_bit;
#else
  return issignaling(static_cast<native_float80_t>(x));
#endif
}

#endif  // !defined(issignaling)

template <typename T, typename R = typename IntegerType<T>::UT>
ALWAYS_INLINE static constexpr R ByteSizeOf(T) {
  return static_cast<R>(sizeof(typename BaseType<T>::BT));
}

template <typename T, typename R = typename IntegerType<T>::UT>
ALWAYS_INLINE static constexpr R BitSizeOf(T) {
  return static_cast<R>(sizeof(typename BaseType<T>::BT) * 8);
}

// Convert the input value into an unsigned integer.
template <typename T>
ALWAYS_INLINE static auto Unsigned(T val) -> typename IntegerType<T>::UT {
  return static_cast<typename IntegerType<T>::UT>(val);
}

// Convert the input value into a signed integer.
template <typename T>
ALWAYS_INLINE static auto Signed(T val) -> typename IntegerType<T>::ST {
  return static_cast<typename IntegerType<T>::ST>(val);
}

template <typename T>
ALWAYS_INLINE static uint8_t IsNegative(T x) {
  return static_cast<uint8_t>(std::signbit(x));
}

ALWAYS_INLINE static uint8_t IsNegative(float80_t x) {
  return static_cast<uint8_t>(std::signbit(static_cast<native_float80_t>(x)));
}

ALWAYS_INLINE static uint8_t IsZero(float32_t x) {
  return static_cast<uint8_t>(FP_ZERO == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsZero(float64_t x) {
  return static_cast<uint8_t>(FP_ZERO == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsZero(float80_t x) {
  return static_cast<uint8_t>(FP_ZERO == std::fpclassify(static_cast<native_float80_t>(x)));
}

ALWAYS_INLINE static uint8_t IsInfinite(float32_t x) {
  return static_cast<uint8_t>(FP_INFINITE == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsInfinite(float64_t x) {
  return static_cast<uint8_t>(FP_INFINITE == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsInfinite(float80_t x) {
  return static_cast<uint8_t>(FP_INFINITE == std::fpclassify(static_cast<native_float80_t>(x)));
}

ALWAYS_INLINE static uint8_t IsNaN(float32_t x) {
  return static_cast<uint8_t>(FP_NAN == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsNaN(float64_t x) {
  return static_cast<uint8_t>(FP_NAN == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsNaN(float80_t x) {
  return static_cast<uint8_t>(FP_NAN == std::fpclassify(static_cast<native_float80_t>(x)));
}

ALWAYS_INLINE static bool IsSignalingNaN(float32_t x) {
  const nan32_t x_nan = {x};
  return x_nan.exponent == 0xFFU && !x_nan.is_quiet_nan && x_nan.payload;
}

ALWAYS_INLINE static bool IsSignalingNaN(float64_t x) {
  const nan64_t x_nan = {x};
  return x_nan.exponent == 0x7FFU && !x_nan.is_quiet_nan && x_nan.payload;
}

ALWAYS_INLINE static bool IsSignalingNaN(float80_t x) {
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
// On non-x86 architectures, native_float80_t is defined as a double,
// which is identical to the float64_t definition above
  const nan80_t x_nan = {x};
  return x_nan.exponent == 0x7FFFU && !x_nan.is_quiet_nan && x_nan.payload && x_nan.interger_bit;
#else
  return IsSignalingNaN(static_cast<native_float80_t>(x));
#endif
}

template <typename T>
ALWAYS_INLINE static uint8_t IsSignalingNaN(T) {
  return 0;
}

template <typename T>
ALWAYS_INLINE static uint8_t IsDenormal(T x) {
  return static_cast<uint8_t>(FP_SUBNORMAL == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsDenormal(float32_t x) {
  return static_cast<uint8_t>(FP_SUBNORMAL == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsDenormal(float64_t x) {
  return static_cast<uint8_t>(FP_SUBNORMAL == std::fpclassify(x));
}

ALWAYS_INLINE static uint8_t IsDenormal(float80_t x) {
  return static_cast<uint8_t>(FP_SUBNORMAL == std::fpclassify(static_cast<native_float80_t>(x)));
}

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
// On non-x86 architectures, native_float80_t is defined as a double,
// which is identical to the float64_t definition above
ALWAYS_INLINE static uint8_t IsDenormal(native_float80_t x) {
  return static_cast<uint8_t>(FP_SUBNORMAL == std::fpclassify(static_cast<native_float80_t>(x)));
}
#endif

template <typename T>
ALWAYS_INLINE static uint8_t IsZero(T val) {
  return static_cast<uint8_t>(!val);
}

template <typename T>
ALWAYS_INLINE static uint8_t IsInfinite(T) {
  return 0;
}

template <typename T>
ALWAYS_INLINE static uint8_t IsNaN(T) {
  return 0;
}

// Return the largest possible value assignable to `val`.
template <typename T>
ALWAYS_INLINE static T Maximize(T) {
  return std::numeric_limits<T>::max();
}

// Return the smallest possible value assignable to `val`.
template <typename T>
ALWAYS_INLINE static T Minimize(T) {
  return std::numeric_limits<T>::min();
}

#define MAKE_CONVERT(dest_type, name) \
  template <typename T> \
  ALWAYS_INLINE static dest_type name(T val) { \
    return static_cast<dest_type>(val); \
  }

MAKE_CONVERT(int8_t, Int8)
MAKE_CONVERT(int16_t, Int16)
MAKE_CONVERT(int32_t, Int32)
MAKE_CONVERT(int64_t, Int64)
MAKE_CONVERT(int128_t, Int128)
MAKE_CONVERT(uint8_t, UInt8)
MAKE_CONVERT(uint16_t, UInt16)
MAKE_CONVERT(uint32_t, UInt32)
MAKE_CONVERT(uint64_t, UInt64)
MAKE_CONVERT(uint128_t, UInt128)
MAKE_CONVERT(float32_t, Float32)
MAKE_CONVERT(float64_t, Float64)
MAKE_CONVERT(float80_t, Float80)

#undef MAKE_CONVERT

// Return the value as-is. This is useful when making many accessors using
// macros, because it lets us decide to pull out values as-is, as unsigned
// integers, or as signed integers.
#define Identity(...) __VA_ARGS__

// Convert an integer to some other type. This is important for
// integer literals, whose type are `int`.
template <typename T, typename U>
ALWAYS_INLINE static auto Literal(U val) -> typename IntegerType<T>::BT {
  return static_cast<typename IntegerType<T>::BT>(val);
}

template <typename T, typename U>
ALWAYS_INLINE static auto ULiteral(U val) -> typename IntegerType<T>::UT {
  return static_cast<typename IntegerType<T>::UT>(val);
}

template <typename T, typename U>
ALWAYS_INLINE static auto SLiteral(U val) -> typename IntegerType<T>::ST {
  return static_cast<typename IntegerType<T>::ST>(val);
}

// Zero-extend an integer to twice its current width.
template <typename T>
ALWAYS_INLINE static auto ZExt(T val) -> typename IntegerType<T>::WUT {
  return static_cast<typename IntegerType<T>::WUT>(Unsigned(val));
}

// Zero-extend an integer type explicitly specified by `DT`. This is useful
// for things like writing to a possibly wider version of a register, but
// not knowing exactly how wide the wider version is.
template <typename DT, typename T>
ALWAYS_INLINE static auto ZExtTo(T val) -> typename IntegerType<DT>::UT {
  typedef typename IntegerType<DT>::UT UT;
  static_assert(sizeof(T) <= sizeof(typename IntegerType<DT>::BT),
                "Bad extension.");
  return static_cast<UT>(Unsigned(val));
}

// Sign-extend an integer to twice its current width.
template <typename T>
ALWAYS_INLINE static auto SExt(T val) -> typename IntegerType<T>::WST {
  return static_cast<typename IntegerType<T>::WST>(Signed(val));
}

// Zero-extend an integer type explicitly specified by `DT`.
template <typename DT, typename T>
ALWAYS_INLINE static auto SExtTo(T val) -> typename IntegerType<DT>::ST {
  static_assert(sizeof(T) <= sizeof(typename IntegerType<DT>::BT),
                "Bad extension.");
  return static_cast<typename IntegerType<DT>::ST>(Signed(val));
}

// Truncate an integer to half of its current width.
template <typename T>
ALWAYS_INLINE static auto Trunc(T val) ->
    typename NextSmallerIntegerType<T>::BT {
  return static_cast<typename NextSmallerIntegerType<T>::BT>(val);
}

// Truncate an integer to have the same width/sign as the type specified
// by `DT`.
template <typename DT, typename T>
ALWAYS_INLINE static auto TruncTo(T val) -> typename IntegerType<DT>::BT {
  static_assert(sizeof(T) >= sizeof(typename IntegerType<DT>::BT),
                "Bad truncation.");
  return static_cast<typename IntegerType<DT>::BT>(val);
}

#define WriteTrunc(op, val) \
  do { \
    Write(op, TruncTo<decltype(op)>(val)); \
  } while (false)

// Handle writes of N-bit values to M-bit values with N <= M. If N < M then the
// source value will be zero-extended to the dest value type. This is useful
// on x86-64 where writes to 32-bit registers zero-extend to 64-bits. In a
// 64-bit build of Remill, the `R32W` type used in the X86 architecture
// runtime actually aliases `R64W`.
#define WriteZExt(op, val) \
  do { \
    Write(op, ZExtTo<decltype(op)>(val)); \
  } while (false)

#define WriteSExt(op, val) \
  do { \
    Write(op, Unsigned(SExtTo<decltype(op)>(val))); \
  } while (false)

#define SWriteV8(op, val) \
  do { \
    memory = _SWriteV8(memory, op, (val)); \
  } while (false)

#define UWriteV8(op, val) \
  do { \
    memory = _UWriteV8(memory, op, (val)); \
  } while (false)

#define SWriteV16(op, val) \
  do { \
    memory = _SWriteV16(memory, op, (val)); \
  } while (false)

#define UWriteV16(op, val) \
  do { \
    memory = _UWriteV16(memory, op, (val)); \
  } while (false)

#define SWriteV32(op, val) \
  do { \
    memory = _SWriteV32(memory, op, (val)); \
  } while (false)

#define UWriteV32(op, val) \
  do { \
    memory = _UWriteV32(memory, op, (val)); \
  } while (false)

#define SWriteV64(op, val) \
  do { \
    memory = _SWriteV64(memory, op, (val)); \
  } while (false)

#define UWriteV64(op, val) \
  do { \
    memory = _UWriteV64(memory, op, (val)); \
  } while (false)

#define SWriteV128(op, val) \
  do { \
    memory = _SWriteV128(memory, op, (val)); \
  } while (false)

#define UWriteV128(op, val) \
  do { \
    memory = _UWriteV128(memory, op, (val)); \
  } while (false)

#define FWriteV32(op, val) \
  do { \
    memory = _FWriteV32(memory, op, (val)); \
  } while (false)

#define FWriteV64(op, val) \
  do { \
    memory = _FWriteV64(memory, op, (val)); \
  } while (false)


#define SReadV8(op) _SReadV8(memory, op)
#define UReadV8(op) _UReadV8(memory, op)

#define SReadV16(op) _SReadV16(memory, op)
#define UReadV16(op) _UReadV16(memory, op)

#define SReadV32(op) _SReadV32(memory, op)
#define UReadV32(op) _UReadV32(memory, op)

#define SReadV64(op) _SReadV64(memory, op)
#define UReadV64(op) _UReadV64(memory, op)

#define SReadV128(op) _SReadV128(memory, op)
#define UReadV128(op) _UReadV128(memory, op)

#define FReadV32(op) _FReadV32(memory, op)
#define FReadV64(op) _FReadV64(memory, op)

// Useful for stubbing out an operator.
#define MAKE_NOP(...)

// Unary operator.
#define MAKE_UOP(name, type, widen_type, op) \
  ALWAYS_INLINE static type name(type R) { \
    return static_cast<type>(op static_cast<widen_type>(R)); \
  }

// Binary operator.
#define MAKE_BINOP(name, type, widen_type, op) \
  ALWAYS_INLINE static type name(type L, type R) { \
    return static_cast<type>(static_cast<widen_type>(L) \
                                 op static_cast<widen_type>(R)); \
  }

#define MAKE_BOOLBINOP(name, type, widen_type, op) \
  ALWAYS_INLINE static bool name(type L, type R) { \
    return L op R; \
  }

// The purpose of the widening type is that Clang/LLVM will already extend
// the types of the inputs to their "natural" machine size, so we'll just
// make that explicit, where `addr_t` encodes the natural machine word.
#define MAKE_OPS(name, op, make_int_op, make_float_op) \
  make_int_op(U##name, uint8_t, addr_t, op) \
  make_int_op(U##name##8, uint8_t, addr_t,op) \
  make_int_op(U##name, uint16_t, addr_t, op) \
  make_int_op(U##name##16, uint16_t, addr_t, op) \
  make_int_op(U##name, uint32_t, addr_t, op) \
  make_int_op(U##name##32, uint32_t, addr_t, op) \
  make_int_op(U##name, uint64_t, uint64_t, op) \
  make_int_op(U##name##64, uint64_t, uint64_t, op) \
  make_int_op(U##name, uint128_t, uint128_t, op) \
  make_int_op(U##name##128, uint128_t, uint128_t, op) \
  make_int_op(S##name, int8_t, addr_diff_t, op) \
  make_int_op(S##name##8, int8_t, addr_diff_t, op) \
  make_int_op(S##name, int16_t, addr_diff_t, op) \
  make_int_op(S##name##16, int16_t, addr_diff_t, op) \
  make_int_op(S##name, int32_t, addr_diff_t, op) \
  make_int_op(S##name##32, int32_t, addr_diff_t, op) \
  make_int_op(S##name, int64_t, int64_t, op) \
  make_int_op(S##name##64, int64_t, int64_t, op) \
  make_int_op(S##name, int128_t, int128_t, op) \
  make_int_op(S##name##128, int128_t, int128_t, op) \
  make_float_op(F##name, float32_t, float32_t, op) \
  make_float_op(F##name##32, float32_t, float32_t, op) \
  make_float_op(F##name, float64_t, float64_t, op) \
  make_float_op(F##name##64, float64_t, float64_t, op) \
  make_float_op(F##name, float80_t, float80_t, op) \
  make_float_op(F##name##80, float80_t, float80_t, op)

MAKE_OPS(Add, +, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Sub, -, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Mul, *, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Div, /, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Rem, %, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(And, &, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(AndN, &~, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Or, |, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Xor, ^, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Shr, >>, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Shl, <<, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Neg, -, MAKE_UOP, MAKE_UOP)
MAKE_OPS(Not, ~, MAKE_UOP, MAKE_NOP)


template <typename T>
ALWAYS_INLINE static T Ror(T val_, T amount_) {
  using UT = typename IntegerType<T>::UT;
  constexpr UT width = static_cast<UT>(sizeof(UT) * 8);
  const UT val = static_cast<UT>(val_);
  const UT amount = static_cast<UT>(amount_) % width;
  if (!amount) {
    return val_;
  }
  const UT shifted_bits = val >> amount;
  const UT rotated_bits = val << (width - amount);
  return static_cast<T>(shifted_bits | rotated_bits);
}

template <typename T>
ALWAYS_INLINE static T Rol(T val_, T amount_) {
  using UT = typename IntegerType<T>::UT;
  constexpr UT width = static_cast<UT>(sizeof(val_) * 8);
  const UT val = static_cast<UT>(val_);
  const UT amount = static_cast<UT>(amount_) % width;
  if (!amount) {
    return val_;
  }
  UT low_bits = val >> (width - amount);
  UT high_bits = val << width;
  return static_cast<T>(low_bits | high_bits);
}

// TODO(pag): Handle unordered and ordered floating point comparisons.
MAKE_OPS(CmpEq, ==, MAKE_BOOLBINOP, MAKE_BOOLBINOP)
MAKE_OPS(CmpNeq, !=, MAKE_BOOLBINOP, MAKE_BOOLBINOP)
MAKE_OPS(CmpLt, <, MAKE_BOOLBINOP, MAKE_BOOLBINOP)
MAKE_OPS(CmpLte, <=, MAKE_BOOLBINOP, MAKE_BOOLBINOP)
MAKE_OPS(CmpGt, >, MAKE_BOOLBINOP, MAKE_BOOLBINOP)
MAKE_OPS(CmpGte, >=, MAKE_BOOLBINOP, MAKE_BOOLBINOP)

#undef MAKE_UNOP
#undef MAKE_BINOP
#undef MAKE_OPS

ALWAYS_INLINE static bool BAnd(bool a, bool b) {
  return a && b;
}

ALWAYS_INLINE static bool BOr(bool a, bool b) {
  return a || b;
}

ALWAYS_INLINE static bool BXor(bool a, bool b) {
  return a != b;
}

ALWAYS_INLINE static bool BXnor(bool a, bool b) {
  return a == b;
}

ALWAYS_INLINE static bool BNot(bool a) {
  return !a;
}

// Binary broadcast operator.
#define MAKE_BIN_BROADCAST(op, size, accessor) \
  template <typename T> \
  ALWAYS_INLINE static T op##V##size(const T &L, const T &R) { \
    T ret{}; \
    _Pragma("unroll") for (auto i = 0UL; i < NumVectorElems(L); ++i) { \
      ret.elems[i] = op(L.elems[i], R.elems[i]); \
    } \
    return ret; \
  }

// Unary broadcast operator.
#define MAKE_UN_BROADCAST(op, size, accessor) \
  template <typename T> \
  ALWAYS_INLINE static T op##V##size(const T &R) { \
    T ret{}; \
    _Pragma("unroll") for (auto i = 0UL; i < NumVectorElems(R); ++i) { \
      ret.elems[i] = op(R.elems[i]); \
    } \
    return ret; \
  }

#define MAKE_BROADCASTS(op, make_int_broadcast, make_float_broadcast) \
  make_int_broadcast(U##op, 8, bytes) make_int_broadcast(U##op, 16, words) \
      make_int_broadcast(U##op, 32, dwords) \
          make_int_broadcast(U##op, 64, qwords) \
              make_int_broadcast(S##op, 8, sbytes) \
                  make_int_broadcast(S##op, 16, swords) \
                      make_int_broadcast(S##op, 32, sdwords) \
                          make_int_broadcast(S##op, 64, sqwords) \
                              make_float_broadcast(F##op, 32, floats) \
                                  make_float_broadcast(F##op, 64, doubles)

MAKE_BROADCASTS(Add, MAKE_BIN_BROADCAST, MAKE_BIN_BROADCAST)
MAKE_BROADCASTS(Sub, MAKE_BIN_BROADCAST, MAKE_BIN_BROADCAST)
MAKE_BROADCASTS(Mul, MAKE_BIN_BROADCAST, MAKE_BIN_BROADCAST)
MAKE_BROADCASTS(Div, MAKE_BIN_BROADCAST, MAKE_BIN_BROADCAST)
MAKE_BROADCASTS(Rem, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(And, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(AndN, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Or, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Xor, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Shl, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Shr, MAKE_BIN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Neg, MAKE_UN_BROADCAST, MAKE_NOP)
MAKE_BROADCASTS(Not, MAKE_UN_BROADCAST, MAKE_NOP)

#undef MAKE_BIN_BROADCAST
#undef MAKE_UN_BROADCAST

// Binary broadcast operator.
#define MAKE_ACCUMULATE(op, size, accessor) \
  template <typename T> \
  ALWAYS_INLINE static auto Accumulate##op##V##size(T R)->decltype( \
      R.elems[0] | R.elems[1]) { \
    auto L = R.elems[0]; \
    _Pragma("unroll") for (auto i = 1UL; i < NumVectorElems(R); ++i) { \
      L = op(L, R.elems[i]); \
    } \
    return L; \
  }

MAKE_BROADCASTS(Add, MAKE_ACCUMULATE, MAKE_ACCUMULATE)
MAKE_BROADCASTS(And, MAKE_ACCUMULATE, MAKE_NOP)
MAKE_BROADCASTS(AndN, MAKE_ACCUMULATE, MAKE_NOP)
MAKE_BROADCASTS(Or, MAKE_ACCUMULATE, MAKE_NOP)
MAKE_BROADCASTS(Xor, MAKE_ACCUMULATE, MAKE_NOP)

#undef MAKE_ACCUMULATE
#undef MAKE_UN_BROADCAST
#undef MAKE_BROADCASTS
#undef MAKE_NOP

template <typename T>
ALWAYS_INLINE static auto NthVectorElem(const T &vec, size_t n) ->
    typename VectorType<T>::BaseType {
  return vec[n];
}

// Access the Nth element of an aggregate vector.
#define MAKE_EXTRACTV(size, base_type, accessor, out, prefix) \
  template <typename T> \
  ALWAYS_INLINE static base_type prefix##ExtractV##size(const T &vec, \
                                                        size_t n) { \
    static_assert(sizeof(base_type) == sizeof(typename VectorType<T>::BT), \
                  "Invalid extract"); \
    return out(vec.elems[n]); \
  }

MAKE_EXTRACTV(8, uint8_t, bytes, Unsigned, U)
MAKE_EXTRACTV(16, uint16_t, words, Unsigned, U)
MAKE_EXTRACTV(32, uint32_t, dwords, Unsigned, U)
MAKE_EXTRACTV(64, uint64_t, qwords, Unsigned, U)
MAKE_EXTRACTV(128, uint128_t, dqwords, Unsigned, U)
MAKE_EXTRACTV(8, int8_t, bytes, Signed, S)
MAKE_EXTRACTV(16, int16_t, words, Signed, S)
MAKE_EXTRACTV(32, int32_t, dwords, Signed, S)
MAKE_EXTRACTV(64, int64_t, qwords, Signed, S)
MAKE_EXTRACTV(128, int128_t, dqwords, Signed, S)
MAKE_EXTRACTV(32, float32_t, floats, Identity, F)
MAKE_EXTRACTV(64, float64_t, doubles, Identity, F)
MAKE_EXTRACTV(80, float80_t, tdoubles, Identity, F)

#undef MAKE_EXTRACTV

ALWAYS_INLINE static int8_t SAbs(int8_t val) {
  return val < 0 ? -val : val;
}

ALWAYS_INLINE static int16_t SAbs(int16_t val) {
  return val < 0 ? -val : val;
}

ALWAYS_INLINE static int32_t SAbs(int32_t val) {
  return val < 0 ? -val : val;
}

ALWAYS_INLINE static int64_t SAbs(int64_t val) {
  return val < 0 ? -val : val;
}

template <typename T>
ALWAYS_INLINE static auto SAbs(typename IntegerType<T>::ST val) ->
    typename IntegerType<T>::ST {
  return Select(SLt(val, 0), SNeg(val), val);
}

template <typename T>
ALWAYS_INLINE static auto UAbs(typename IntegerType<T>::UT val) ->
    typename IntegerType<T>::UT {
  return val;
}

// Access the Nth element of an aggregate vector.
#define MAKE_INSERTV(prefix, size, base_type, accessor) \
  template <typename T> \
  ALWAYS_INLINE static T prefix##InsertV##size(T vec, size_t n, \
                                               base_type val) { \
    static_assert(sizeof(base_type) == sizeof(typename VectorType<T>::BT), \
                  "Invalid extract"); \
    vec.elems[n] = val; \
    return vec; \
  }

MAKE_INSERTV(U, 8, uint8_t, bytes)
MAKE_INSERTV(U, 16, uint16_t, words)
MAKE_INSERTV(U, 32, uint32_t, dwords)
MAKE_INSERTV(U, 64, uint64_t, qwords)
MAKE_INSERTV(U, 128, uint128_t, dqwords)

MAKE_INSERTV(S, 8, int8_t, sbytes)
MAKE_INSERTV(S, 16, int16_t, swords)
MAKE_INSERTV(S, 32, int32_t, sdwords)
MAKE_INSERTV(S, 64, int64_t, sqwords)
MAKE_INSERTV(S, 128, int128_t, sdqwords)

MAKE_INSERTV(F, 32, float32_t, floats)
MAKE_INSERTV(F, 64, float64_t, doubles)
MAKE_INSERTV(F, 80, float80_t, tdoubles)

#undef MAKE_INSERTV

// Update the Nth element of an aggregate vector.
#define MAKE_UPDATEV(prefix, size, base_type, accessor) \
  template <typename T> \
  ALWAYS_INLINE static void prefix##UpdateV##size(T &vec, size_t n, \
                                                  base_type val) { \
    static_assert(sizeof(base_type) == sizeof(typename VectorType<T>::BT), \
                  "Invalid update"); \
    vec.elems[n] = val; \
  }

MAKE_UPDATEV(U, 8, uint8_t, bytes)
MAKE_UPDATEV(U, 16, uint16_t, words)
MAKE_UPDATEV(U, 32, uint32_t, dwords)
MAKE_UPDATEV(U, 64, uint64_t, qwords)
MAKE_UPDATEV(U, 128, uint128_t, dqwords)

MAKE_UPDATEV(S, 8, int8_t, sbytes)
MAKE_UPDATEV(S, 16, int16_t, swords)
MAKE_UPDATEV(S, 32, int32_t, sdwords)
MAKE_UPDATEV(S, 64, int64_t, sqwords)
MAKE_UPDATEV(S, 128, int128_t, sdqwords)

MAKE_UPDATEV(F, 32, float32_t, floats)
MAKE_UPDATEV(F, 64, float64_t, doubles)
MAKE_UPDATEV(F, 80, float80_t, tdoubles)

#undef MAKE_UPDATEV

template <typename U, typename T>
ALWAYS_INLINE static constexpr T _ZeroVec(void) {
  static_assert(std::is_same<U, typename VectorType<T>::BT>::value,
                "Vector type and base don't match.");
  return {};
}

#define _ClearV(base_type, ...)

#define UClearV8(...) _ZeroVec<uint8_t, decltype(__VA_ARGS__)>()
#define UClearV16(...) _ZeroVec<uint16_t, decltype(__VA_ARGS__)>()
#define UClearV32(...) _ZeroVec<uint32_t, decltype(__VA_ARGS__)>()
#define UClearV64(...) _ZeroVec<uint64_t, decltype(__VA_ARGS__)>()
#define UClearV128(...) _ZeroVec<uint128_t, decltype(__VA_ARGS__)>()

#define SClearV8(...) _ZeroVec<int8_t, decltype(__VA_ARGS__)>()
#define SClearV16(...) _ZeroVec<int16_t, decltype(__VA_ARGS__)>()
#define SClearV32(...) _ZeroVec<int32_t, decltype(__VA_ARGS__)>()
#define SClearV64(...) _ZeroVec<int64_t, decltype(__VA_ARGS__)>()
#define SClearV128(...) _ZeroVec<int128_t, decltype(__VA_ARGS__)>()

#define FClearV32(...) _ZeroVec<float32_t, decltype(__VA_ARGS__)>()
#define FClearV64(...) _ZeroVec<float64_t, decltype(__VA_ARGS__)>()

// Something has gone terribly wrong and we need to stop because there is
// an error.
//
// TODO(pag): What happens if there's a signal handler? How should we
//            communicate the error class?
#define StopFailure() return __remill_error(state, Read(REG_PC), memory)

// Aesthetically pleasing names that hide the implicit small-step semantics
// of the memory pointer.
#define BarrierLoadLoad() \
  do { \
    memory = __remill_barrier_load_load(memory); \
  } while (false)

#define BarrierLoadStore() \
  do { \
    memory = __remill_barrier_load_store(memory); \
  } while (false)

#define BarrierStoreLoad() \
  do { \
    memory = __remill_barrier_store_load(memory); \
  } while (false)

#define BarrierStoreStore() \
  do { \
    memory = __remill_barrier_store_store(memory); \
  } while (false)

#ifdef REMILL_BARRIER_AS_NOP

// The 'compiler' barrier is generating inline assembly which is inconvenient for KLEE
// disable it if flag `REMILL_BARRIER_AS_NOP` is defined.
#  define BarrierReorder(...)
#  define BarrierUsedHere(...)

#else

// A 'compiler' barrier that prevents reordering of instructions across the
// barrier. A thorough explanation can be found here:
// http://preshing.com/20120625/memory-ordering-at-compile-time/
#  define BarrierReorder() \
    do { \
      __asm__ __volatile__("" ::: "memory"); \
    } while (false)

// A 'compiler' barrier that also forces a variable's value to be resident in
// memory at the current spot. This is a useful debugging aid, e.g. when you
// see `<optimized out>` in GDB, and really pessimizes optimizations.
//
// An entertaining explanation is here: https://youtu.be/nXaxk27zwlk?t=40m50s
#  define BarrierUsedHere(x) \
    do { \
      __asm__ __volatile__("" ::"m"(x) : "memory"); \
    } while (false)
#endif

// Make a predicate for querying the type of an operand.
#define MAKE_PRED(name, X, val) \
  template <typename T> \
  ALWAYS_INLINE static constexpr bool Is##name(X<T>) { \
    return val; \
  }

MAKE_PRED(Register, Rn, true)
MAKE_PRED(Register, RnW, true)
MAKE_PRED(Register, Vn, true)
MAKE_PRED(Register, VnW, true)
MAKE_PRED(Register, Mn, false)
MAKE_PRED(Register, MnW, false)
MAKE_PRED(Register, MVn, false)
MAKE_PRED(Register, MVnW, false)
MAKE_PRED(Register, In, false)

MAKE_PRED(Memory, Rn, false)
MAKE_PRED(Memory, RnW, false)
MAKE_PRED(Memory, Vn, false)
MAKE_PRED(Memory, VnW, false)
MAKE_PRED(Memory, Mn, true)
MAKE_PRED(Memory, MnW, true)
MAKE_PRED(Memory, MVn, true)
MAKE_PRED(Memory, MVnW, true)
MAKE_PRED(Memory, In, false)

MAKE_PRED(Immediate, Rn, false)
MAKE_PRED(Immediate, RnW, false)
MAKE_PRED(Immediate, Vn, false)
MAKE_PRED(Immediate, VnW, false)
MAKE_PRED(Immediate, Mn, false)
MAKE_PRED(Immediate, MnW, false)
MAKE_PRED(Immediate, MVn, false)
MAKE_PRED(Immediate, MVnW, false)
MAKE_PRED(Immediate, In, true)

#undef MAKE_PRED
#define MAKE_PRED(name, T, val) \
  ALWAYS_INLINE static constexpr bool Is##name(T) { \
    return val; \
  }

MAKE_PRED(Register, uint8_t, true)
MAKE_PRED(Register, uint16_t, true)
MAKE_PRED(Register, uint32_t, true)
MAKE_PRED(Register, uint64_t, true)

MAKE_PRED(Immediate, uint8_t, true)
MAKE_PRED(Immediate, uint16_t, true)
MAKE_PRED(Immediate, uint32_t, true)
MAKE_PRED(Immediate, uint64_t, true)

#undef MAKE_PRED

template <typename T>
ALWAYS_INLINE static Mn<T> GetElementPtr(Mn<T> addr, addr_t index) {
  return {addr.addr + (index * static_cast<addr_t>(sizeof(T)))};
}

template <typename T>
ALWAYS_INLINE static MVn<T> GetElementPtr(MVn<T> addr, addr_t index) {
  return {addr.addr + (index * static_cast<addr_t>(sizeof(T)))};
}

template <typename T>
ALWAYS_INLINE static MnW<T> GetElementPtr(MnW<T> addr, addr_t index) {
  return {addr.addr + (index * static_cast<addr_t>(sizeof(T)))};
}

template <typename T>
ALWAYS_INLINE static MVnW<T> GetElementPtr(MVnW<T> addr, addr_t index) {
  return {addr.addr + (index * static_cast<addr_t>(sizeof(T)))};
}

template <typename T>
ALWAYS_INLINE static auto ReadPtr(addr_t addr) -> Mn<typename BaseType<T>::BT> {
  return {addr};
}

template <typename T>
ALWAYS_INLINE static auto ReadPtr(addr_t addr, addr_t seg_base)
    -> Mn<typename BaseType<T>::BT> {
  return {addr + seg_base};
}

template <typename T>
ALWAYS_INLINE static auto WritePtr(addr_t addr)
    -> MnW<typename BaseType<T>::BT> {
  return {addr};
}

template <typename T>
ALWAYS_INLINE static auto WritePtr(addr_t addr, addr_t seg_base)
    -> MnW<typename BaseType<T>::BT> {
  return {addr + seg_base};
}

template <typename T>
ALWAYS_INLINE static auto VReadPtr(addr_t addr) -> MVn<T> {
  return {addr};
}

template <typename T>
ALWAYS_INLINE static auto VReadPtr(addr_t addr, addr_t seg_base) -> MVn<T> {
  return {addr + seg_base};
}

template <typename T>
ALWAYS_INLINE static auto VWritePtr(addr_t addr) -> MVnW<T> {
  return {addr};
}

template <typename T>
ALWAYS_INLINE static auto VWritePtr(addr_t addr, addr_t seg_base) -> MVnW<T> {
  return {addr + seg_base};
}

template <typename T>
ALWAYS_INLINE static addr_t AddressOf(Mn<T> addr) {
  return addr.addr;
}

template <typename T>
ALWAYS_INLINE static addr_t AddressOf(MnW<T> addr) {
  return addr.addr;
}

template <typename T>
ALWAYS_INLINE static addr_t AddressOf(MVn<T> addr) {
  return addr.addr;
}

template <typename T>
ALWAYS_INLINE static addr_t AddressOf(MVnW<T> addr) {
  return addr.addr;
}

template <typename T>
ALWAYS_INLINE static Mn<T> DisplaceAddress(Mn<T> addr, addr_t disp) {
  return Mn<T>{addr.addr + disp};
}

template <typename T>
ALWAYS_INLINE static MnW<T> DisplaceAddress(MnW<T> addr, addr_t disp) {
  return MnW<T>{addr.addr + disp};
}

template <typename T>
ALWAYS_INLINE static MVn<T> DisplaceAddress(MVn<T> addr, addr_t disp) {
  return MVn<T>{addr.addr + disp};
}

template <typename T>
ALWAYS_INLINE static MVnW<T> DisplaceAddress(MVnW<T> addr, addr_t disp) {
  return MVnW<T>{addr.addr + disp};
}

template <typename T>
ALWAYS_INLINE static T Select(bool cond, T if_true, T if_false) {
  return cond ? if_true : if_false;
}

#define BUndefined __remill_undefined_8
#define UUndefined8 __remill_undefined_8
#define UUndefined16 __remill_undefined_16
#define UUndefined32 __remill_undefined_32
#define UUndefined64 __remill_undefined_64


// TODO(pag): Assumes little-endian.
ALWAYS_INLINE static uint128_t __remill_read_memory_128(Memory *mem,
                                                        addr_t addr) {
  uint128_t low_qword = ZExt(__remill_read_memory_64(mem, addr));
  uint128_t high_qword = ZExt(__remill_read_memory_64(mem, addr + 8));
  return UOr(UShl(high_qword, 64), low_qword);
}

// TODO(pag): Assumes little-endian.
ALWAYS_INLINE static Memory *__remill_write_memory_128(Memory *mem, addr_t addr,
                                                       uint128_t val) {
  uint64_t low_qword = Trunc(val);
  uint64_t high_qword = Trunc(UShr(val, 64));
  mem = __remill_write_memory_64(mem, addr, low_qword);
  mem = __remill_write_memory_64(mem, addr + 8, high_qword);
  return mem;
}

// Issue #374: https://github.com/lifting-bits/remill/issues/374
//
// The builtins may have defined or undefined behavior given a zero, depending
// on the target arch.
#define MAKE_BUILTIN(name, size, input_size, builtin, disp) \
  ALWAYS_INLINE static uint##size##_t name(uint##size##_t val) { \
    const auto in_val = static_cast<uint##input_size##_t>(val); \
    return in_val ? (static_cast<uint##size##_t>(builtin(in_val)) - \
                     static_cast<uint##input_size##_t>(disp)) \
                  : size; \
  }

MAKE_BUILTIN(CountLeadingZeros, 8, 32, __builtin_clz, 24)
MAKE_BUILTIN(CountLeadingZeros, 16, 32, __builtin_clz, 16)
MAKE_BUILTIN(CountLeadingZeros, 32, 32, __builtin_clz, 0)
MAKE_BUILTIN(CountLeadingZeros, 64, 64, __builtin_clzll, 0)

MAKE_BUILTIN(CountTrailingZeros, 8, 32, __builtin_ctz, 0)
MAKE_BUILTIN(CountTrailingZeros, 16, 32, __builtin_ctz, 0)
MAKE_BUILTIN(CountTrailingZeros, 32, 32, __builtin_ctz, 0)
MAKE_BUILTIN(CountTrailingZeros, 64, 64, __builtin_ctzll, 0)

#undef MAKE_BUILTIN


#define MAKE_BUILTIN_INTRINSIC(name, intrinsic_name, size, type) \
  ALWAYS_INLINE static type name(type val) { \
    return intrinsic_name(val); \
  } \
  ALWAYS_INLINE static type name##size(type val) { \
    return intrinsic_name(val); \
  }

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86)
#define MAKE_BUILTIN(name, intrinsic_name) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name##f, 32, float32_t) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name, 64, float64_t) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name##l, 80, float80_t)
#else
#define MAKE_BUILTIN(name, intrinsic_name) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name##f, 32, float32_t) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name, 64, float64_t) \
  MAKE_BUILTIN_INTRINSIC(name, intrinsic_name, 80, float80_t)
#endif

MAKE_BUILTIN(FAbs, __builtin_fabs);
MAKE_BUILTIN(FCos, __builtin_cos)
MAKE_BUILTIN(FSin, __builtin_sin)
MAKE_BUILTIN(FTan, __builtin_tan)
MAKE_BUILTIN(FAtan,__builtin_atan)
MAKE_BUILTIN(FSqrt,__builtin_sqrt)
MAKE_BUILTIN(Exp2,__builtin_exp2)
MAKE_BUILTIN(Log2,__builtin_log2)

MAKE_BUILTIN(FRoundUsingMode, __builtin_nearbyint);
MAKE_BUILTIN(FTruncTowardZero, __builtin_trunc);
MAKE_BUILTIN(FRoundAwayFromZero, __builtin_round);
MAKE_BUILTIN(FRoundToPositiveInfinity, __builtin_ceil);
MAKE_BUILTIN(FRoundToNegativeInfinity, __builtin_floor);

#undef MAKE_BUILTIN_INTRINSIC
#undef MAKE_BUILTIN

ALWAYS_INLINE static int16_t Float64ToInt16(float64_t val) {
  auto max_int = Float64(Maximize(Int16(0)));
  return Select<int16_t>(FCmpLt(max_int, FAbs(val)), Int16(0x8000), Int16(val));
}

ALWAYS_INLINE static int32_t Float64ToInt32(float64_t val) {
  auto max_int = Float64(Maximize(Int32(0)));
  return Select<int32_t>(FCmpLt(max_int, FAbs(val)), Int32(0x80000000),
                         Int32(val));
}

ALWAYS_INLINE static int16_t Float80ToInt16(float80_t val) {
	auto max_int = Float80(Float64(Maximize(Int16(0))));
  return Select<int16_t>(FCmpLt80(max_int, FAbs80(val)), Int16(0x8000), Int16(val));
}

ALWAYS_INLINE static int32_t Float80ToInt32(float80_t val) {
  auto max_int = Float80(Float64(Maximize(Int32(0))));
  return Select<int32_t>(FCmpLt80(max_int, FAbs80(val)), Int32(0x80000000),
                         Int32(val));
}

ALWAYS_INLINE static int16_t Float32ToInt16(float32_t val) {
  auto max_int = Float32(Maximize(Int32(0)));
  return Select<int16_t>(FCmpLt(max_int, FAbs(val)), Int16(0x8000), Int16(val));
}

ALWAYS_INLINE static int32_t Float32ToInt32(float32_t val) {
  auto max_int = Float32(Maximize(Int32(0)));
  return Select<int32_t>(FCmpLt(max_int, FAbs(val)), Int32(0x80000000),
                         Int32(val));
}

ALWAYS_INLINE static int64_t Float32ToInt64(float32_t val) {
  return Int64(val);
}

ALWAYS_INLINE static int64_t Float64ToInt64(float64_t val) {
  auto max_int = Float64(Maximize(Int64(0)));
  return Select<int64_t>(FCmpLt(max_int, FAbs(val)),
                         Int64(0x8000000000000000LL), Int64(val));
}

ALWAYS_INLINE static int64_t Float80ToInt64(float80_t val) {
  auto max_int = Float80(Float64(Maximize(Int64(0))));
  return Select<int64_t>(FCmpLt80(max_int, FAbs80(val)),
                         Int64(0x8000000000000000LL), Int64(val));
}

ALWAYS_INLINE static float32_t FRoundToNearestEven32(float32_t val) {
  return FRoundUsingMode32(val);

  //  auto abs_val = __builtin_fabsf(val);
  //  auto sign = (val / abs_val);
  //  auto floor_val = __builtin_floorf(abs_val);
  //  auto ceil_val = __builtin_ceilf(abs_val);
  //  auto halfway_val = floor_val + 0.5;
  //  if (halfway_val == abs_val) {  // Half-way case.
  //    auto floor_val_int = Float32ToInt64(floor_val);
  //    if (floor_val_int % 2) {
  //      return ceil_val * sign;
  //    } else {
  //      return floor_val * sign;
  //    }
  //  } else {
  //    return __builtin_roundf(val);
  //  }
}

ALWAYS_INLINE static float64_t FRoundToNearestEven64(float64_t val) {
  return FRoundUsingMode64(val);

  //  auto abs_val = __builtin_fabs(val);
  //  auto sign = (val / abs_val);
  //  auto floor_val = __builtin_floor(abs_val);
  //  auto ceil_val = __builtin_ceil(abs_val);
  //  auto halfway_val = floor_val + 0.5;
  //  if (halfway_val == abs_val) {  // Half-way case.
  //    auto floor_val_int = Float64ToInt64(floor_val);
  //    if (floor_val_int % 2) {
  //      return ceil_val * sign;
  //    } else {
  //      return floor_val * sign;
  //    }
  //  } else {
  //    return __builtin_round(val);
  //  }
}

}  // namespace
