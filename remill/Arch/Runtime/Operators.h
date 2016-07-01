/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_OPERATORS_H_
#define REMILL_ARCH_RUNTIME_OPERATORS_H_

#if 0
namespace {

template <typename kBaseType, typename D, typename S>
struct VectorAssign;

template <typename kBaseType, typename D>
struct VectorAssign<kBaseType, D, D> {
  ALWAYS_INLINE static void assign(D &dest, const D &src) {
    dest = src;
  }
};

// Create a smaller-to-bigger vector assignment function. This will perform
// zero-extension, but this is not the preferred way of achieving zero-
// extensions. Instead, one should depend on the move constructor.
#define MAKE_VECTOR_ASSIGNER(base_type, sel) \
    template <typename D, typename S> \
    struct VectorAssign<base_type, D, S> { \
      ALWAYS_INLINE static void assign(D &dest, const S &src) { \
        if (sizeof(S) < sizeof(D)) { \
          _Pragma("unroll") \
          for (auto i = 0UL; i < (sizeof(D)/sizeof(base_type)); ++i) { \
            dest.sel[i] = 0; \
          } \
        } \
        enum : size_t { \
          kVecSize = sizeof(D) > sizeof(S) ? sizeof(S) : sizeof(D), \
          kNumElems = kVecSize / sizeof(base_type) \
        }; \
        _Pragma("unroll") \
        for (auto i = 0UL; i < kNumElems; ++i) { \
          dest.sel[i] = src[i]; \
        } \
      } \
    }

MAKE_VECTOR_ASSIGNER(uint8_t, bytes);
MAKE_VECTOR_ASSIGNER(uint16_t, words);
MAKE_VECTOR_ASSIGNER(uint32_t, dwords);
MAKE_VECTOR_ASSIGNER(uint64_t, qwords);
MAKE_VECTOR_ASSIGNER(uint128_t, dqwords);
MAKE_VECTOR_ASSIGNER(float, floats);
MAKE_VECTOR_ASSIGNER(double, doubles);

#undef MAKE_VECTOR_ASSIGNER

template <typename T>
struct VecWriter {

  // Same-type assignment of an aggregate vector.
  ALWAYS_INLINE void operator=(T val) const {
    *val_ref = val;
  }

  // Zero-extension assignment of one type of vector into another.
  template <typename V,
            typename=typename AggVectorInfo<V>::BT>
  ALWAYS_INLINE void operator=(V val) const {
    this->operator=(val.iwords);
  }

  // Fall-back for performing assignments of a smaller (non-aggregate) vector
  // type to a larger vector type, where the smaller type is already specialized
  // to a specific base type, E.g. `V=uint32v4_t` (128 bits) and `T=vec256_t`.
  //
  // This will zero-extend the value for the assignment.
  template <typename V,
            typename=typename VectorInfo<V>::VecType,
            typename=typename VectorInfo<V>::BaseType>
  ALWAYS_INLINE void operator=(V val) const {
    VectorAssign<typename VectorInfo<V>::BaseType, T, V>::assign(*val_ref, val);
  }

  // Fall-back for assigning a single value into a vector of a larger type.
  // This will assign the value as the first element in the vector.
  template <typename V,
            size_t=sizeof(typename SingletonVectorType<V>::BT)>
  ALWAYS_INLINE void operator=(V val) const {
    typedef typename SingletonVectorType<V>::BT VecType;
    VecType vec = {val};
    VectorAssign<V, T, VecType>::assign(*val_ref, vec);
  }

  T *val_ref;
};

#define MAKE_VEC_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __remill_memory_order = __remill_write_memory_v ## size (\
            __remill_memory_order, addr, val); \
      } \
      template <typename V, \
                typename=typename VectorInfo<V>::VecType, \
                typename=typename VectorInfo<V>::BaseType> \
      ALWAYS_INLINE void operator=(V val) const { \
        T vec; \
        VectorAssign<typename VectorInfo<V>::BaseType, T, V>::assign(vec, val);\
        __remill_memory_order = __remill_write_memory_v ## size ( \
            __remill_memory_order, addr, vec); \
      } \
      \
      addr_t addr; \
    }; \
    \
    ALWAYS_INLINE static T R(const Mn<T> mem) { \
      T ret_val; \
      __remill_memory_order = __remill_read_memory_v ## size ( \
          __remill_memory_order, mem.addr, ret_val); \
      return ret_val; \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    ALWAYS_INLINE static VecWriter<T> W(VnW<T> vec) { \
      return {vec.val_ref}; \
    }


MAKE_VEC_ACCESSORS(vec8_t, 8)
MAKE_VEC_ACCESSORS(vec16_t, 16)
MAKE_VEC_ACCESSORS(vec32_t, 32)
MAKE_VEC_ACCESSORS(vec64_t, 64)
MAKE_VEC_ACCESSORS(vec128_t, 128)
MAKE_VEC_ACCESSORS(vec256_t, 256)
MAKE_VEC_ACCESSORS(vec512_t, 512)

// Note: We apply `static_cast<T>` for `R(In<T>)` and `R(Rn<T>)` because the
//       internal storage type of these struct templates will be `addr_t` to
//       avoid these structs being passed `byval` and therefore not being
//       scalarized to their underlying types.

template <typename T>
ALWAYS_INLINE static T R(const In<T> imm) {
  return static_cast<T>(imm.val);
}

template <typename T>
ALWAYS_INLINE static T R(const Rn<T> reg) {
  return static_cast<T>(reg.val);
}

template <typename T>
ALWAYS_INLINE static T R(const Vn<T> vec) {
  return *(vec.val);
}

// Disallow writes to read-only register values.
template <typename T>
[[noreturn]] inline static void W(Rn<T>) {
  __builtin_unreachable();
}

// Disallow writes to read-only memory locations.
template <typename T>
[[noreturn]] inline static void W(Mn<T>) {
  __builtin_unreachable();
}

// Disallow writes to immediate values.
template <typename T>
[[noreturn]] inline static void W(In<T>) {
  __builtin_unreachable();
}

// Disallow writes to read-only vector register values.
template <typename T>
[[noreturn]] inline static void W(Vn<T>) {
  __builtin_unreachable();
}

// Address of a memory operand.
template <typename T>
inline static addr_t A(Mn<T> m) {
  return m.addr;
}

template <typename T>
inline static addr_t A(MnW<T> m) {
  return m.addr;
}

namespace {
template <typename FromT, typename ToT>
inline static Vn<ToT> DownCastImpl(Vn<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid vector down-cast.");
  return {reinterpret_cast<ToT *>(in.val)};
}

template <typename FromT, typename ToT>
inline static VnW<ToT> DownCastImpl(VnW<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid vector down-cast.");
  return {reinterpret_cast<ToT *>(in.val_ref)};
}

template <typename FromT, typename ToT>
inline static Rn<ToT> DownCastImpl(Rn<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid register down-cast.");
  return {in.val};
}

template <typename FromT, typename ToT>
inline static RnW<ToT> DownCastImpl(RnW<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid register down-cast.");
  return {reinterpret_cast<ToT *>(in.val_ref)};
}


template <typename FromT, typename ToT>
inline static Mn<ToT> DownCastImpl(Mn<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid memory down-cast.");
  return {in.addr};
}

template <typename FromT, typename ToT>
inline static MnW<ToT> DownCastImpl(MnW<FromT> in) {
  static_assert(sizeof(ToT) < sizeof(FromT), "Invalid memory down-cast.");
  return {in.addr};
}
}

template <typename U, typename T>
inline static U DownCast(T in) {
  return DownCastImpl<typename BaseType<T>::BT,
                      typename BaseType<U>::BT>(in);
}

#define MAKE_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __remill_memory_order = __remill_write_memory_ ## size ( \
            __remill_memory_order, addr, val);\
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      return __remill_read_memory_ ## size (__remill_memory_order, mem.addr); \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE static T R(Rn<T> reg) { \
      return static_cast<T>(reg.val); \
    } \
    ALWAYS_INLINE static T &W(RnW<T> reg) { \
      return *(reg.val_ref); \
    } \
    \
    ALWAYS_INLINE static T &W(T &ref) { \
      return ref; \
    } \
    ALWAYS_INLINE static T R(T imm) { \
      return imm; \
    } \
    ALWAYS_INLINE static T U(RnW<T>) { \
      return __remill_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(MnW<T>) { \
      return __remill_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(Rn<T>) { \
      return __remill_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(Mn<T>) { \
      return __remill_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(In<T>) { \
      return __remill_undefined_ ## size (); \
    }

MAKE_ACCESSORS(uint8_t, 8)
MAKE_ACCESSORS(uint16_t, 16)
MAKE_ACCESSORS(uint32_t, 32)
MAKE_ACCESSORS(uint64_t, 64)
#undef MAKE_ACCESSORS

#define MAKE_FLOAT_ACCESSORS(T, base_type, acc, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(const T &val) const { \
        __remill_memory_order = __remill_write_memory_f ## size ( \
            __remill_memory_order, addr, val);\
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      T val; \
      __remill_memory_order = __remill_read_memory_f ## size ( \
          __remill_memory_order, mem.addr, val); \
      return val; \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE static T R(Rn<T> reg) { \
      return reg.val; \
    } \
    ALWAYS_INLINE static T &W(RnW<T> reg) { \
      return *(reg.val_ref); \
    } \
    \
    ALWAYS_INLINE static T &W(T &ref) { \
      return ref; \
    } \
    ALWAYS_INLINE static T R(const T &val) { \
      return val; \
    } \
    struct Float ## size ## VecOps { \
      template <typename U> \
      ALWAYS_INLINE static base_type Read0(U val) { \
        return val.acc[0]; \
      } \
      template <typename U> \
      ALWAYS_INLINE static void Write0(U &dst, base_type src) { \
        dst.acc[0] = src; \
      } \
      template <typename U> \
      ALWAYS_INLINE static auto Read(U val) -> decltype(val.acc) { \
        return val.acc; \
      } \
      template <typename U, typename V> \
      ALWAYS_INLINE static void Write(U &dst, V src) { \
        dst.acc = src; \
      } \
    };

MAKE_FLOAT_ACCESSORS(float32_t, float, floats, 32)
MAKE_FLOAT_ACCESSORS(float64_t, double, doubles, 64)

#undef MAKE_FLOAT_ACCESSORS

}  // namespace
#endif

struct Memory;
struct State;

// Something has gone terribly wrong and we need to stop because there is
// an error.
//
// TODO(pag): What happens if there's a signal handler? How should we
//            communicate the error class?
#define StopFailure() \
    do { \
      __remill_error(state, Read(REG_XIP)); \
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

template <typename T>
ALWAYS_INLINE static
T _Read(Memory *, const Vn<T> reg) {
  return *reg.val;
}

// Make read operators for reading integral values from memory.
#define MAKE_MREAD(size, ...) \
    ALWAYS_INLINE static \
    uint ## size ## _t _Read(Memory *&memory, Mn<uint ## size ## _t> op) { \
      return __remill_read_memory_ ## size (memory, op.addr); \
    }

MAKE_MREAD(8)
MAKE_MREAD(16)
MAKE_MREAD(32)
MAKE_MREAD(64)

#undef MAKE_MREAD

// Make read operators for reading vectors and floating point numbers from
// memory.
#define MAKE_MREADV(size, type_prefix, val_prefix) \
    ALWAYS_INLINE static \
    type_prefix ## size ## _t _Read( \
        Memory *&memory, Mn<type_prefix ## size ## _t> op) { \
      type_prefix ## size ## _t val; \
      memory = __remill_read_memory_ ## val_prefix ## size ( \
          memory, op.addr, val); \
      return val; \
    }

MAKE_MREADV(8, vec, v)
MAKE_MREADV(16, vec, v)
MAKE_MREADV(32, vec, v)
MAKE_MREADV(64, vec, v)
MAKE_MREADV(128, vec, v)
MAKE_MREADV(256, vec, v)
MAKE_MREADV(512, vec, v)

//MAKE_MREADV(32, float, f)
//MAKE_MREADV(64, float, f)
//MAKE_MREADV(80, float, f)

#undef MAKE_MREADV

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
#define MAKE_MWRITE(type, size) \
    ALWAYS_INLINE static \
    Memory *_Write(Memory *memory, MnW<type> op, const type val) { \
      return __remill_write_memory_ ## size (memory, op.addr, val); \
    }

MAKE_MWRITE(uint8_t, 8)
MAKE_MWRITE(uint16_t, 16)
MAKE_MWRITE(uint32_t, 32)
MAKE_MWRITE(uint64_t, 64)

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
    make_int_op(S ## name, int8_t, op) \
    make_int_op(S ## name, int16_t, op) \
    make_int_op(S ## name, int32_t, op) \
    make_int_op(S ## name, int64_t, op) \
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
