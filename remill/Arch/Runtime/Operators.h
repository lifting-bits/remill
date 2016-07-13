/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_OPERATORS_H_
#define REMILL_ARCH_RUNTIME_OPERATORS_H_

struct Memory;
struct State;

// Something has gone terribly wrong and we need to stop because there is
// an error.
//
// TODO(pag): What happens if there's a signal handler? How should we
//            communicate the error class?
#define StopFailure() \
    do { \
      __remill_error(state, memory, Read(REG_XIP)); \
      __builtin_unreachable(); \
    } while (false)

namespace {

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

template <typename T>
ALWAYS_INLINE static
T _Read(Memory *, const In<T> imm) {
  return static_cast<T>(imm.val);
}

template <typename T>
ALWAYS_INLINE static
T _Read(Memory *, const Rn<T> reg) {
  return static_cast<T>(reg.val);
}

#define MAKE_VREAD(prefix, size) \
    template <typename T> \
    ALWAYS_INLINE static \
    T _ ## prefix ## ReadV ## size (Memory *, const Vn<T> reg) { \
      return *reg.val; \
    }

MAKE_VREAD(U, 8)
MAKE_VREAD(U, 16)
MAKE_VREAD(U, 32)
MAKE_VREAD(U, 64)
MAKE_VREAD(U, 128)
MAKE_VREAD(F, 32)
MAKE_VREAD(F, 64)

#undef MAKE_VREAD

// Make read operators for reading integral values from memory.
#define MAKE_MREAD(size, type_prefix, ...) \
    ALWAYS_INLINE static \
    type_prefix ## size ## _t _Read( \
        Memory *&memory, Mn<type_prefix ## size ## _t> op) { \
      return __remill_read_memory_ ## __VA_ARGS__ ## size (memory, op.addr); \
    }

MAKE_MREAD(8, uint)
MAKE_MREAD(16, uint)
MAKE_MREAD(32, uint)
MAKE_MREAD(64, uint)
MAKE_MREAD(32, float, f)
MAKE_MREAD(64, float, f)

#undef MAKE_MREAD

// Basic write form for references.
template <typename T>
ALWAYS_INLINE static
Memory *_Write(Memory *memory, T &dst, T src) {
  dst = src;
  return memory;
}

// Make write operators for writing values to registers.
#define MAKE_RWRITE(type) \
    ALWAYS_INLINE static \
    Memory *_Write( \
        Memory *memory, const RnW<type> reg, const type val) { \
      *reg.val_ref = val; \
      return memory; \
    }

MAKE_RWRITE(uint8_t)
MAKE_RWRITE(uint16_t)
MAKE_RWRITE(uint32_t)
MAKE_RWRITE(uint64_t)

#undef MAKE_RWRITE

// Make write operators for writing vectors to vector registers.
#define MAKE_VWRITE(prefix, size, accessor) \
    template <typename T, typename U> \
    ALWAYS_INLINE static \
    Memory *_ ## prefix ## WriteV ## size ( \
        Memory *memory, const VnW<T> reg, const U val) { \
      enum : size_t { \
        kNumSrcElems = NumVectorElems(val.accessor), \
        kNumDstElems = NumVectorElems(reg.val_ref->accessor) \
      }; \
      _Pragma("unroll") \
      for (size_t i = 0UL; i < kNumSrcElems; ++i) { \
        reg.val_ref->accessor.elems[i] = val.accessor.elems[i]; \
      } \
      _Pragma("unroll") \
      for (size_t i = kNumSrcElems; i < kNumDstElems; ++i) { \
        reg.val_ref->accessor.elems[i] = 0; \
      } \
      return memory; \
    }

MAKE_VWRITE(U, 8, bytes)
MAKE_VWRITE(U, 16, words)
MAKE_VWRITE(U, 32, dwords)
MAKE_VWRITE(U, 64, qwords)
MAKE_VWRITE(U, 128, dqwords)
MAKE_VWRITE(F, 32, floats)
MAKE_VWRITE(F, 64, doubles)

#undef MAKE_VWRITE

// Make write operators for writing values to memory.
#define MAKE_MWRITE(size, type_prefix, ...) \
    ALWAYS_INLINE static \
    Memory *_Write( \
        Memory *memory, MnW<type_prefix ## size ## _t> op, \
        type_prefix ## size ## _t val) { \
      return __remill_write_memory_ ## __VA_ARGS__ ## size (\
          memory, op.addr, val); \
    }

MAKE_MWRITE(8, uint)
MAKE_MWRITE(16, uint)
MAKE_MWRITE(32, uint)
MAKE_MWRITE(64, uint)
MAKE_MWRITE(32, float, f)
MAKE_MWRITE(64, float, f)

#undef MAKE_MWRITE

// Make write operators for writing vectors to vector registers.
#define MAKE_MVWRITE(prefix, size, small_prefix, accessor) \
    template <typename T> \
    ALWAYS_INLINE static \
    Memory *_ ## prefix ## WriteV ## size ( \
        Memory *memory, const MnW<T> mem, const T val) { \
      _Pragma("unroll") \
      for (size_t i = 0UL; i < NumVectorElems(val.accessor); ++i) { \
        memory = __remill_write_memory_ ## small_prefix ( \
            memory, \
            mem.addr + (i * sizeof(val.accessor.elems[0])), \
            val.accessor.elems[i]);\
      } \
      return memory; \
    }

MAKE_MVWRITE(U, 8, 8, bytes)
MAKE_MVWRITE(U, 16, 16, words)
MAKE_MVWRITE(U, 32, 32, dwords)
MAKE_MVWRITE(U, 64, 64, qwords)
MAKE_MVWRITE(U, 128, 128, dqwords)
MAKE_MVWRITE(F, 32, f32, floats)
MAKE_MVWRITE(F, 64, f64, doubles)

#undef MAKE_MVWRITE

// Make read operators for reading vectors to vector registers.
#define MAKE_MVREAD(prefix, size, small_prefix, accessor) \
    template <typename T> \
    ALWAYS_INLINE static \
    T _ ## prefix ## ReadV ## size ( \
        Memory *memory, const Mn<T> mem) { \
      T val; \
      _Pragma("unroll") \
      for (size_t i = 0UL; i < NumVectorElems(val.accessor); ++i) { \
        val.accessor.elems[i] = __remill_read_memory_ ## small_prefix ( \
            memory, \
            mem.addr + (i * sizeof(val.accessor.elems[0])));\
      } \
      return val; \
    }

MAKE_MVREAD(U, 8, 8, bytes)
MAKE_MVREAD(U, 16, 16, words)
MAKE_MVREAD(U, 32, 32, dwords)
MAKE_MVREAD(U, 64, 64, qwords)
MAKE_MVREAD(U, 128, 128, dqwords)
MAKE_MVREAD(F, 32, f32, floats)
MAKE_MVREAD(F, 64, f64, doubles)

#undef MAKE_MVREAD

// For the sake of esthetics and hiding the small-step semantics of memory
// operands, we use this macros to implicitly pass in the `memory` operand,
// which we know will be defined in semantics functions.
#define Read(op) _Read(memory, op)

// Write a source value to a destination operand, where the sizes of the
// valyes must match.
#define Write(op, val) \
    do { \
      static_assert( \
          sizeof(typename BaseType<decltype(op)>::BT) == sizeof(val), \
          "Bad write!"); \
      memory = _Write(memory, op, (val)); \
    } while (false)

// Handle writes of N-bit values to M-bit values with N <= M. If N < M then the
// source value will be zero-extended to the dest value type.
#define WriteZExt(op, val) \
    do { \
      Write(op, ZExtTo<decltype(op)>(val)); \
    } while (false)

#define UWriteV8 WriteV8
#define SWriteV8 WriteV8
#define WriteV8(op, val) \
    do { \
      memory = _UWriteV8(memory, op, (val)); \
    } while (false)

#define UWriteV16 WriteV16
#define SWriteV16 WriteV16
#define WriteV16(op, val) \
    do { \
      memory = _UWriteV16(memory, op, (val)); \
    } while (false)

#define UWriteV32 WriteV32
#define SWriteV32 WriteV32
#define WriteV32(op, val) \
    do { \
      memory = _UWriteV32(memory, op, (val)); \
    } while (false)

#define UWriteV64 WriteV64
#define SWriteV64 WriteV64
#define WriteV64(op, val) \
    do { \
      memory = _UWriteV64(memory, op, (val)); \
    } while (false)

#define UWriteV128 WriteV128
#define SWriteV128 WriteV128
#define WriteV128(op, val) \
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

#define UReadV8 ReadV8
#define SReadV8 ReadV8
#define ReadV8(op) _UReadV8(memory, op)

#define UReadV16 ReadV16
#define SReadV16 ReadV16
#define ReadV16(op) _UReadV16(memory, op)

#define UReadV32 ReadV32
#define SReadV32 ReadV32
#define ReadV32(op) _UReadV32(memory, op)

#define UReadV64 ReadV64
#define SReadV64 ReadV64
#define ReadV64(op) _UReadV64(memory, op)

#define UReadV128 ReadV128
#define SReadV128 ReadV128
#define ReadV128(op) _UReadV128(memory, op)

#define FReadV32(op) _FReadV32(memory, op)
#define FReadV64(op) _FReadV64(memory, op)

// Combine two vectors together into a third. If the second vector is smaller
// than the first then the "top" elements in the first are preserved.
#define MAKE_VUPDATE(base_type, size, accessor, prefix) \
    template <typename T, typename S> \
    ALWAYS_INLINE static \
    Memory *_UpdateV ## prefix ## size( \
        Memory *memory, const VnW<T> vec1, const S vec2) { \
      static_assert(sizeof(vec2) <= sizeof(vec1), \
                    "Second vector must be no larger than the first."); \
      _Pragma("unroll") \
      for (auto i = 0UL; i < NumVectorElems(vec2.accessor); ++i) { \
        vec1.val_ref->accessor.elems[i] = vec2.accessor.elems[i]; \
      } \
      return memory; \
    } \
    \
    template <typename T> \
    ALWAYS_INLINE static \
    Memory *_UpdateV ## prefix ## size( \
        Memory *memory, const VnW<T> vec1, base_type val) { \
      vec1.val_ref->accessor.elems[0] = val; \
      return memory; \
    } \
    \
    template <typename T> \
    ALWAYS_INLINE static \
    Memory *_UpdateV ## prefix ## size( \
        Memory *memory, const MnW<T> dst, const T src) { \
      return _WriteV ## prefix ## size(memory, dst, src); \
    }

MAKE_VUPDATE(uint8_t, 8, bytes, U)
MAKE_VUPDATE(uint16_t, 16, words, U)
MAKE_VUPDATE(uint32_t, 32, dwords, U)
MAKE_VUPDATE(uint64_t, 64, qwords, U)
MAKE_VUPDATE(uint128_t, 128, dqwords, U)
MAKE_VUPDATE(float32_t, 32, floats, F)
MAKE_VUPDATE(float64_t, 64, doubles, F)

#undef MAKE_VUPDATE

#define UpdateVU8(vec, val) \
    do { \
      memory = _UpdateVU8(memory, vec, (val)); \
    } while (false)

#define UpdateVU16(vec, val) \
    do { \
      memory = _UpdateVU16(memory, vec, (val)); \
    } while (false)

#define UpdateVU32(vec, val) \
    do { \
      memory = _UpdateVU32(memory, vec, (val)); \
    } while (false)

#define UpdateVU64(vec, val) \
    do { \
      memory = _UpdateVU64(memory, vec, (val)); \
    } while (false)

#define UpdateVU128(vec, val) \
    do { \
      memory = _UpdateVU128(memory, vec, (val)); \
    } while (false)

#define UpdateVF32(vec, val) \
    do { \
      memory = _UpdateVF32(memory, vec, (val)); \
    } while (false)

#define UpdateVF64(vec, val) \
    do { \
      memory = _UpdateVF64(memory, vec, (val)); \
    } while (false)


template <typename T>
ALWAYS_INLINE static constexpr
auto SizeOf(T) -> typename IntegerType<T>::UT {
  return static_cast<typename IntegerType<T>::UT>(
      sizeof(typename BaseType<T>::BT));
}

template <typename T>
ALWAYS_INLINE static constexpr
auto BitSizeOf(T) -> typename IntegerType<T>::UT {
  return static_cast<typename IntegerType<T>::UT>(
      sizeof(typename BaseType<T>::BT) * 8);
}

// Convert the input value into an unsigned integer.
template <typename T>
ALWAYS_INLINE static
auto Unsigned(T val) -> typename IntegerType<T>::UT {
  return static_cast<typename IntegerType<T>::UT>(val);
}
// Convert the input value into a signed integer.
template <typename T>
ALWAYS_INLINE static
auto Signed(T val) -> typename IntegerType<T>::ST {
  return static_cast<typename IntegerType<T>::ST>(val);
}

// Return the value as-is. This is useful when making many accessors using
// macros, because it lets us decide to pull out values as-is, as unsigned
// integers, or as signed integers.
template <typename T>
ALWAYS_INLINE static
T Identity(T val) {
  return val;
}

// Zero-extend an integer to twice its current width.
template <typename T>
ALWAYS_INLINE static
auto ZExt(T val) -> typename IntegerType<T>::WUT {
  return static_cast<typename IntegerType<T>::WUT>(Unsigned(val));
}

// Zero-extend an integer type explicitly specified by `DT`. This is useful
// for things like writing to a possibly wider version of a register, but
// not knowing exactly how wide the wider version is.
template <typename DT, typename T>
ALWAYS_INLINE static
auto ZExtTo(T val) -> typename IntegerType<DT>::UT {
  typedef typename IntegerType<DT>::UT UT;
  static_assert(sizeof(T) <= sizeof(typename IntegerType<DT>::BT),
                "Bad extension.");
  return static_cast<UT>(Unsigned(val));
}

// Sign-extend an integer to twice its current width.
template <typename T>
ALWAYS_INLINE static
auto SExt(T val) -> typename IntegerType<T>::WST {
  return static_cast<typename IntegerType<T>::WST>(Signed(val));
}

// Zero-extend an integer type explicitly specified by `DT`.
template <typename DT, typename T>
ALWAYS_INLINE static
auto SExtTo(T val) -> typename IntegerType<DT>::ST {
  static_assert(sizeof(T) <= sizeof(typename IntegerType<DT>::BT),
                "Bad extension.");
  return static_cast<typename IntegerType<DT>::ST>(Signed(val));
}

// Truncate an integer to half of its current width.
template <typename T>
ALWAYS_INLINE static
auto Trunc(T val) -> typename NextSmallerIntegerType<T>::BT {
  return static_cast<typename NextSmallerIntegerType<T>::BT>(val);
}

// Truncate an integer to have the same width/sign as the type specified
// by `DT`.
template <typename DT, typename T>
ALWAYS_INLINE static
auto TruncTo(T val) -> typename IntegerType<DT>::BT {
  static_assert(sizeof(T) >= sizeof(typename IntegerType<DT>::BT),
                "Bad truncation.");
  return static_cast<typename IntegerType<DT>::BT>(val);
}

// Useful for stubbing out an operator.
#define MAKE_NOP(...)

// Unary operator.
#define MAKE_UOP(name, type, op) \
    ALWAYS_INLINE type name(const type R) { \
      return static_cast<type>(op R); \
    }

// Binary operator.
#define MAKE_BINOP(name, type, op) \
    ALWAYS_INLINE type name(const type L, const type R) { \
      return static_cast<type>(L op R); \
    }

#define MAKE_OPS(name, op, make_int_op, make_float_op) \
    make_int_op(U ## name, uint8_t, op) \
    make_int_op(U ## name, uint16_t, op) \
    make_int_op(U ## name, uint32_t, op) \
    make_int_op(U ## name, uint64_t, op) \
    make_int_op(U ## name, uint128_t, op) \
    make_int_op(S ## name, int8_t, op) \
    make_int_op(S ## name, int16_t, op) \
    make_int_op(S ## name, int32_t, op) \
    make_int_op(S ## name, int64_t, op) \
    make_int_op(S ## name, int128_t, op) \
    make_float_op(F ## name, float32_t, op) \
    make_float_op(F ## name, float64_t, op)

MAKE_OPS(Add, +, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Sub, -, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Mul, *, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Div, /, MAKE_BINOP, MAKE_BINOP)
MAKE_OPS(Rem, %, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(And, &, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(AndN, & ~, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Or, |, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Xor, ^, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Shr, >>, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Shl, <<, MAKE_BINOP, MAKE_NOP)
MAKE_OPS(Neg, -, MAKE_UOP, MAKE_UOP)
MAKE_OPS(Not, ~, MAKE_UOP, MAKE_NOP)

#undef MAKE_UNOP
#undef MAKE_BINOP
#undef MAKE_OPS


// Binary broadcast operator.
#define MAKE_BIN_BROADCAST(op, size, accessor, in, out) \
    template <typename T> \
    ALWAYS_INLINE static \
    T op ## V ## size(T L, const T R) { \
      _Pragma("unroll") \
      for (auto i = 0UL; i < NumVectorElems(L.accessor); ++i) { \
        L.accessor.elems[i] = out(op(in(L.accessor.elems[i]), \
                                     in(R.accessor.elems[i]))); \
      } \
      return L; \
    }

// Unary broadcast operator.
#define MAKE_UN_BROADCAST(op, size, accessor, in, out) \
    template <typename T> \
    ALWAYS_INLINE static \
    T op ## V ## size(T R) { \
      _Pragma("unroll") \
      for (auto i = 0UL; i < NumVectorElems(R.accessor); ++i) { \
        R.accessor.elems[i] = out(op(in(R.accessor.elems[i]))); \
      } \
      return R; \
    }

#define MAKE_BROADCASTS(op, make_int_broadcast, make_float_broadcast) \
    make_int_broadcast(U ## op, 8, bytes, Unsigned, Unsigned) \
    make_int_broadcast(U ## op, 16, words, Unsigned, Unsigned) \
    make_int_broadcast(U ## op, 32, dwords, Unsigned, Unsigned) \
    make_int_broadcast(U ## op, 64, qwords, Unsigned, Unsigned) \
    make_int_broadcast(S ## op, 8, bytes, Signed, Unsigned) \
    make_int_broadcast(S ## op, 16, words, Signed, Unsigned) \
    make_int_broadcast(S ## op, 32, dwords, Signed, Unsigned) \
    make_int_broadcast(S ## op, 64, qwords, Signed, Unsigned) \
    make_float_broadcast(F ## op, 32, floats, Identity, Identity) \
    make_float_broadcast(F ## op, 64, doubles, Identity, Identity) \

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
#undef MAKE_BROADCASTS
#undef MAKE_NOP

template <size_t n, typename T>
auto NthVectorElem(const T &vec) -> typename VectorType<T>::BaseType {
  static_assert(n <= NumVectorElems(vec),
                "Cannot access beyond end of vector.");
  return vec[n];
}

// Access the Nth element of an aggregate vector.
#define MAKE_EXTRACT(size, base_type, accessor, out, prefix) \
    template <size_t n, typename T> \
    base_type prefix ## ExtractV ## size(const T &vec) { \
      static_assert(n <= NumVectorElems(vec.accessor), \
                    "Cannot access beyond end of vector."); \
      return out(vec.accessor.elems[n]); \
    }

MAKE_EXTRACT(8, uint8_t, bytes, Unsigned, U)
MAKE_EXTRACT(16, uint16_t, words, Unsigned, U)
MAKE_EXTRACT(32, uint32_t, dwords, Unsigned, U)
MAKE_EXTRACT(64, uint64_t, qwords, Unsigned, U)
MAKE_EXTRACT(128, uint128_t, dqwords, Unsigned, U)
MAKE_EXTRACT(8, int8_t, bytes, Signed, S)
MAKE_EXTRACT(16, int16_t, words, Signed, S)
MAKE_EXTRACT(32, int32_t, dwords, Signed, S)
MAKE_EXTRACT(64, int64_t, qwords, Signed, S)
MAKE_EXTRACT(128, int128_t, dqwords, Signed, S)
MAKE_EXTRACT(32, float32_t, floats, Identity, F)
MAKE_EXTRACT(64, float64_t, doubles, Identity, F)
#undef MAKE_EXTRACT

// Access the Nth element of an aggregate vector.
#define MAKE_INSERT(size, base_type, accessor, out, prefix) \
    template <size_t n, typename T> \
    T prefix ## InsertV ## size(T vec, base_type val) { \
      static_assert(n <= NumVectorElems(vec.accessor), \
                    "Cannot access beyond end of vector."); \
      vec.accessor.elems[n] = out(val); \
      return vec; \
    }

MAKE_INSERT(8, uint8_t, bytes, Unsigned, U)
MAKE_INSERT(16, uint16_t, words, Unsigned, U)
MAKE_INSERT(32, uint32_t, dwords, Unsigned, U)
MAKE_INSERT(64, uint64_t, qwords, Unsigned, U)
MAKE_INSERT(128, uint128_t, dqwords, Unsigned, U)
MAKE_INSERT(8, int8_t, bytes, Unsigned, S)
MAKE_INSERT(16, int16_t, words, Unsigned, S)
MAKE_INSERT(32, int32_t, dwords, Unsigned, S)
MAKE_INSERT(64, int64_t, qwords, Unsigned, S)
MAKE_INSERT(128, int128_t, dqwords, Unsigned, S)
MAKE_INSERT(32, float32_t, floats, Identity, F)
MAKE_INSERT(64, float64_t, doubles, Identity, F)
#undef MAKE_EXTRACT

// Esthetically pleasing names that hide the implicit small-step semantics
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



// Make a predicate for querying the type of an operand.
#define MAKE_PRED(name, X, val) \
    template <typename T> \
    ALWAYS_INLINE static constexpr bool Is ## name(X<T>) { \
      return val; \
    }

MAKE_PRED(Register, Rn, true)
MAKE_PRED(Register, RnW, true)
MAKE_PRED(Register, Vn, true)
MAKE_PRED(Register, VnW, true)
MAKE_PRED(Register, Mn, false)
MAKE_PRED(Register, MnW, false)
MAKE_PRED(Register, In, false)

MAKE_PRED(Memory, Rn, false)
MAKE_PRED(Memory, RnW, false)
MAKE_PRED(Memory, Vn, false)
MAKE_PRED(Memory, VnW, false)
MAKE_PRED(Memory, Mn, true)
MAKE_PRED(Memory, MnW, true)
MAKE_PRED(Memory, In, false)

MAKE_PRED(Immediate, Rn, false)
MAKE_PRED(Immediate, RnW, false)
MAKE_PRED(Immediate, Vn, false)
MAKE_PRED(Immediate, VnW, false)
MAKE_PRED(Immediate, Mn, false)
MAKE_PRED(Immediate, MnW, false)
MAKE_PRED(Immediate, In, true)

#undef MAKE_PRED
#define MAKE_PRED(name, T, val) \
    ALWAYS_INLINE static constexpr bool Is ## name(T) { \
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

}  // namespace

#endif  // REMILL_ARCH_RUNTIME_OPERATORS_H_
