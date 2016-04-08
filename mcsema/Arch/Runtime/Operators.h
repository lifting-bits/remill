/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_RUNTIME_OPERATORS_H_
#define MCSEMA_ARCH_RUNTIME_OPERATORS_H_

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
            typename=typename AggVectorInfo<V>::Type>
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
            size_t=sizeof(typename SingletonVectorType<V>::Type)>
  ALWAYS_INLINE void operator=(V val) const {
    typedef typename SingletonVectorType<V>::Type VecType;
    VecType vec = {val};
    VectorAssign<V, T, VecType>::assign(*val_ref, vec);
  }

  T *val_ref;
};

#define MAKE_VEC_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __mcsema_memory_order = __mcsema_write_memory_v ## size (\
            __mcsema_memory_order, addr, val); \
      } \
      template <typename V, \
                typename=typename VectorInfo<V>::VecType, \
                typename=typename VectorInfo<V>::BaseType> \
      ALWAYS_INLINE void operator=(V val) const { \
        T vec; \
        VectorAssign<typename VectorInfo<V>::BaseType, T, V>::assign(vec, val);\
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      \
      addr_t addr; \
    }; \
    \
    ALWAYS_INLINE static T R(const Mn<T> mem) { \
      T ret_val; \
      __mcsema_memory_order = __mcsema_read_memory_v ## size ( \
          __mcsema_memory_order, mem.addr, ret_val); \
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
  return DownCastImpl<typename BaseType<T>::Type,
                      typename BaseType<U>::Type>(in);
}

#define MAKE_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __mcsema_memory_order = __mcsema_write_memory_ ## size ( \
            __mcsema_memory_order, addr, val);\
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      return __mcsema_read_memory_ ## size (__mcsema_memory_order, mem.addr); \
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
      return __mcsema_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(MnW<T>) { \
      return __mcsema_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(Rn<T>) { \
      return __mcsema_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(Mn<T>) { \
      return __mcsema_undefined_ ## size (); \
    } \
    ALWAYS_INLINE static T U(In<T>) { \
      return __mcsema_undefined_ ## size (); \
    }

MAKE_ACCESSORS(uint8_t, 8)
MAKE_ACCESSORS(uint16_t, 16)
MAKE_ACCESSORS(uint32_t, 32)
MAKE_ACCESSORS(uint64_t, 64)
#undef MAKE_ACCESSORS

#define MAKE_FLOAT_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(const T &val) const { \
        __mcsema_memory_order = __mcsema_write_memory_f ## size ( \
            __mcsema_memory_order, addr, val);\
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      T val; \
      __mcsema_memory_order = __mcsema_read_memory_f ## size ( \
          __mcsema_memory_order, mem.addr, val); \
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
    }

MAKE_FLOAT_ACCESSORS(float32_t, 32)
MAKE_FLOAT_ACCESSORS(float64_t, 64)

#undef MAKE_FLOAT_ACCESSORS

}  // namespace

#endif  // MCSEMA_ARCH_RUNTIME_OPERATORS_H_
