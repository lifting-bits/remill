/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_ARCH_RUNTIME_OPERATORS_H_
#define MCSEMA_ARCH_RUNTIME_OPERATORS_H_

namespace {

template <typename kBaseType, typename VecType, typename IntVecType>
struct VectorAssign;

// Create a smaller-to-bigger vector assignment function. This will perform
// zero-extension, but this is not the preferred way of achieving zero-
// extensions. Instead, one should depend on the move constructor.
#define MAKE_VECTOR_ASSIGNER(base_type, sel) \
    template <typename VecType, typename IntVecType> \
    struct VectorAssign<base_type, VecType, IntVecType> { \
      ALWAYS_INLINE static void assign(VecType *dest, const IntVecType &src) { \
        _Pragma("unroll") \
        for (auto i = 0UL; i < (sizeof(VecType)/sizeof(base_type)); ++i) { \
          dest->sel[i] = 0; \
        } \
        _Pragma("unroll") \
        for (auto i = 0UL; i < (sizeof(IntVecType)/sizeof(base_type)); ++i) { \
          dest->sel[i] = src[i]; \
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
  typedef decltype(T().bytes) BytesType;
  typedef decltype(T().words) WordsType;
  typedef decltype(T().dwords) DwordsType;
  typedef decltype(T().qwords) QwordsType;
  typedef decltype(T().dqwords) DqwordsType;  // Special case: `vec64_t`.
  typedef decltype(T().floats) FloatsType;
  typedef decltype(T().doubles) DoublesType;
  ALWAYS_INLINE void operator=(T val) const {
    *val_ref = val;
  }
  ALWAYS_INLINE void operator=(BytesType val) const {
    val_ref->bytes = val;
  }
  ALWAYS_INLINE void operator=(WordsType val) const {
    val_ref->words = val;
  }
  ALWAYS_INLINE void operator=(DwordsType val) const {
    val_ref->dwords = val;
  }
  ALWAYS_INLINE void operator=(QwordsType val) const {
    val_ref->qwords = val;
  }
  ALWAYS_INLINE void operator=(DqwordsType val) const {
    val_ref->dqwords = val;
  }
  ALWAYS_INLINE void operator=(FloatsType val) const {
    val_ref->floats = val;
  }
  ALWAYS_INLINE void operator=(DoublesType val) const {
    val_ref->doubles = val;
  }

  // Fall-back for performing assignments of a smaller vector type to
  // a larger vector type, where the smaller type is already specialized
  // to a specific base type, E.g. `V=uint32v4_t` (128 bits) and `T=vec256_t`.
  template <typename V,
            size_t=sizeof(typename VectorInfo<V>::VecType),
            size_t=sizeof(typename VectorInfo<V>::BaseType)>
  ALWAYS_INLINE void operator=(V val) const {
    VectorAssign<typename VectorInfo<V>::BaseType, T, V>::assign(val_ref, val);
  }

  // Fall-back for assigning a single value into a vector of a larger type.
  // This will assign the value as the first element in the vector.
  template <typename V,
            size_t=sizeof(typename SingletonVectorType<V>::Type)>
  ALWAYS_INLINE void operator=(V val) const {
    typedef typename SingletonVectorType<V>::Type VecType;
    VecType vec = {val};
    VectorAssign<V, T, VecType>::assign(val_ref, vec);
  }

  T *val_ref;
};

#define MAKE_VEC_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      typedef decltype(T().bytes) BytesType; \
      typedef decltype(T().words) WordsType; \
      typedef decltype(T().dwords) DwordsType; \
      typedef decltype(T().qwords) QwordsType; \
      typedef decltype(T().floats) FloatsType; \
      typedef decltype(T().doubles) DoublesType; \
      ALWAYS_INLINE void operator=(T val) const { \
        __mcsema_memory_order = __mcsema_write_memory_v ## size (\
            __mcsema_memory_order, addr, val); \
      } \
      ALWAYS_INLINE void operator=(BytesType val) const { \
        T vec; \
        vec.bytes = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      ALWAYS_INLINE void operator=(WordsType val) const { \
        T vec; \
        vec.words = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      ALWAYS_INLINE void operator=(DwordsType val) const { \
        T vec; \
        vec.dwords = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      ALWAYS_INLINE void operator=(QwordsType val) const { \
        T vec; \
        vec.qwords = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      ALWAYS_INLINE void operator=(FloatsType val) const { \
        T vec; \
        vec.floats = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      ALWAYS_INLINE void operator=(DoublesType val) const { \
        T vec; \
        vec.doubles = val; \
        __mcsema_memory_order = __mcsema_write_memory_v ## size ( \
            __mcsema_memory_order, addr, vec); \
      } \
      addr_t addr; \
    }; \
    \
    ALWAYS_INLINE static T R(const Mn<T> mem) { \
      return __mcsema_read_memory_v ## size (__mcsema_memory_order, mem.addr); \
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

// Convert a byte array into an 80-bit floating point value.
ALWAYS_INLINE static arch_float80_t R(const float80_t &reg) {
  return *reinterpret_cast<const arch_float80_t *>(&(reg));
}

ALWAYS_INLINE static arch_float80_t &W(float80_t &reg) {
  return *reinterpret_cast<arch_float80_t *>(&(reg));
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

#define MAKE_FLOAT_ACCESSORS(T, IT, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __mcsema_memory_order = __mcsema_write_memory_ ## size ( \
            __mcsema_memory_order, addr, reinterpret_cast<IT &&>(val));\
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      const IT ival = __mcsema_read_memory_ ## size ( \
          __mcsema_memory_order, mem.addr); \
      return reinterpret_cast<const T &&>(ival); \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE static T R(Rn<T> reg) { \
      const IT ival = static_cast<IT>(reg.val); \
      return reinterpret_cast<const T &&>(ival); \
    } \
    ALWAYS_INLINE static T &W(RnW<T> reg) { \
      return *reinterpret_cast<T *>(reg.val_ref); \
    } \
    \
    ALWAYS_INLINE static T &W(T &ref) { \
      return ref; \
    } \
    ALWAYS_INLINE static T R(T imm) { \
      return imm; \
    }

MAKE_FLOAT_ACCESSORS(float32_t, uint32_t, 32)
MAKE_FLOAT_ACCESSORS(float64_t, uint64_t, 64)

#undef MAKE_FLOAT_ACCESSORS
}  // namespace

#endif  // MCSEMA_ARCH_RUNTIME_OPERATORS_H_
