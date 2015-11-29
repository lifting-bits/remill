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
      ALWAYS_INLINE static void assign(VecType &dest, \
                                              const IntVecType &src) { \
        _Pragma("unroll") \
        for (auto i = 0UL; i < sizeof(IntVecType); ++i) { \
          dest.sel[i] = src[i]; \
        } \
        _Pragma("unroll") \
        for (auto i = sizeof(IntVecType); i < sizeof(VecType); ++i) { \
          dest.sel[i] = 0; \
        } \
      } \
    }

MAKE_VECTOR_ASSIGNER(uint8_t, bytes);
MAKE_VECTOR_ASSIGNER(uint16_t, words);
MAKE_VECTOR_ASSIGNER(uint32_t, dwords);
MAKE_VECTOR_ASSIGNER(uint64_t, qwords);
MAKE_VECTOR_ASSIGNER(uint128_t, dqwords);

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
    val_ref = val;
  }
  ALWAYS_INLINE void operator=(BytesType val) const {
    val_ref.bytes = val;
  }
  ALWAYS_INLINE void operator=(WordsType val) const {
    val_ref.words = val;
  }
  ALWAYS_INLINE void operator=(DwordsType val) const {
    val_ref.dwords = val;
  }
  ALWAYS_INLINE void operator=(QwordsType val) const {
    val_ref.qwords = val;
  }
  ALWAYS_INLINE void operator=(DqwordsType val) const {
    val_ref.dqwords = val;
  }
  ALWAYS_INLINE void operator=(FloatsType val) const {
    val_ref.floats = val;
  }
  ALWAYS_INLINE void operator=(DoublesType val) const {
    val_ref.doubles = val;
  }

  // Fallback for performing assignments of a smaller vector type to
  // a larger vector type, where the smaller type is already specialized
  // to a specific base type, E.g. `V=uint32v4_t` (128 bits) and `T=vec256_t`.
  template <typename V,
            typename std::enable_if<sizeof(V)<sizeof(T),int>::type=0>
  ALWAYS_INLINE void operator=(V val) const {
    VectorAssign<typename VectorInfo<V>::BaseType, T, V>::assign(val_ref, val);
  }

  T &val_ref;
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
        __mcsema_write_memory_v ## size (addr, val); \
      } \
      ALWAYS_INLINE void operator=(BytesType val) const { \
        T vec; \
        vec.bytes = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE void operator=(WordsType val) const { \
        T vec; \
        vec.words = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE void operator=(DwordsType val) const { \
        T vec; \
        vec.dwords = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE void operator=(QwordsType val) const { \
        T vec; \
        vec.qwords = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE void operator=(FloatsType val) const { \
        T vec; \
        vec.floats = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE void operator=(DoublesType val) const { \
        T vec; \
        vec.doubles = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      addr_t addr; \
    }; \
    \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      T vec; \
      __mcsema_read_memory_v ## size (mem.addr, vec); \
      return vec; \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    ALWAYS_INLINE static VecWriter<T> W(VnW<T> vec) { \
      return {vec.val_ref}; \
    }

MAKE_VEC_ACCESSORS(vec64_t, 64)
MAKE_VEC_ACCESSORS(vec128_t, 128)
MAKE_VEC_ACCESSORS(vec256_t, 256)
MAKE_VEC_ACCESSORS(vec512_t, 512)

template <typename T>
ALWAYS_INLINE static T R(In<T> imm) {
  return imm.val;
}

template <typename T>
ALWAYS_INLINE static T R(Rn<T> reg) {
  return reg.val;
}

template <typename T>
ALWAYS_INLINE static T R(Vn<T> vec) {
  return vec.val;
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

#define MAKE_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE void operator=(T val) const { \
        __mcsema_write_memory_ ## size (addr, val); \
      } \
      addr_t addr; \
    }; \
    ALWAYS_INLINE static T R(Mn<T> mem) { \
      return __mcsema_read_memory_ ## size (mem.addr); \
    } \
    ALWAYS_INLINE static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE static T R(Rn<T> reg) { \
      return reg.val; \
    } \
    ALWAYS_INLINE static T &W(RnW<T> reg) { \
      return reg.val_ref; \
    } \
    \
    ALWAYS_INLINE static T &W(T &ref) { \
      return ref; \
    }\
    ALWAYS_INLINE static T R(T imm) { \
      return imm; \
    }

MAKE_ACCESSORS(uint8_t, 8)
MAKE_ACCESSORS(uint16_t, 16)
MAKE_ACCESSORS(uint32_t, 32)
MAKE_ACCESSORS(uint64_t, 64)
#undef MAKE_ACCESSORS

}  // namespace

#endif  // MCSEMA_ARCH_RUNTIME_OPERATORS_H_
