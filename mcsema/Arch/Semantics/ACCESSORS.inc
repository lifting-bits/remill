/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

#define MAKE_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      ALWAYS_INLINE inline void operator=(T val) const { \
        __mcsema_write_memory_ ## size (addr, val); \
      } \
      uintptr_t addr; \
    }; \
    ALWAYS_INLINE inline static T R(Mn<T> mem) { \
      return __mcsema_read_memory_ ## size (mem.addr); \
    } \
    ALWAYS_INLINE inline static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE inline static T R(Rn<T> reg) { \
      return reg.val; \
    } \
    ALWAYS_INLINE inline static T &W(RnW<T> reg) { \
      return reg.val_ref; \
    } \
    \
    ALWAYS_INLINE inline static T &W(T &ref) { \
      return ref; \
    }\
    ALWAYS_INLINE inline static T R(T imm) { \
      return imm; \
    }

#define MAKE_VEC_ACCESSORS(T, size) \
    struct MemoryWriter ## T { \
      typedef decltype(T().bytes) BytesType; \
      typedef decltype(T().words) WordsType; \
      typedef decltype(T().dwords) DwordsType; \
      typedef decltype(T().qwords) QwordsType; \
      typedef decltype(T().floats) FloatsType; \
      typedef decltype(T().doubles) DoublesType; \
      ALWAYS_INLINE inline void operator=(T val) const { \
        __mcsema_write_memory_v ## size (addr, val); \
      } \
      ALWAYS_INLINE inline void operator=(BytesType val) const { \
        T vec; \
        vec.bytes = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE inline void operator=(WordsType val) const { \
        T vec; \
        vec.words = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE inline void operator=(DwordsType val) const { \
        T vec; \
        vec.dwords = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE inline void operator=(QwordsType val) const { \
        T vec; \
        vec.qwords = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE inline void operator=(FloatsType val) const { \
        T vec; \
        vec.floats = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      ALWAYS_INLINE inline void operator=(DoublesType val) const { \
        T vec; \
        vec.doubles = val; \
        __mcsema_write_memory_v ## size (addr, vec); \
      } \
      uintptr_t addr; \
    }; \
    \
    struct VecWriter ## T { \
      typedef decltype(T().bytes) BytesType; \
      typedef decltype(T().words) WordsType; \
      typedef decltype(T().dwords) DwordsType; \
      typedef decltype(T().qwords) QwordsType; \
      typedef decltype(T().floats) FloatsType; \
      typedef decltype(T().doubles) DoublesType; \
      ALWAYS_INLINE inline void operator=(T val) const { \
        val_ref = val; \
      } \
      ALWAYS_INLINE inline void operator=(BytesType val) const { \
        val_ref.bytes = val; \
      } \
      ALWAYS_INLINE inline void operator=(WordsType val) const { \
        val_ref.words = val; \
      } \
      ALWAYS_INLINE inline void operator=(DwordsType val) const { \
        val_ref.dwords = val; \
      } \
      ALWAYS_INLINE inline void operator=(QwordsType val) const { \
        val_ref.qwords = val; \
      } \
      ALWAYS_INLINE inline void operator=(FloatsType val) const { \
        val_ref.floats = val; \
      } \
      ALWAYS_INLINE inline void operator=(DoublesType val) const { \
        val_ref.doubles = val; \
      } \
      T &val_ref; \
    }; \
    \
    ALWAYS_INLINE inline static T R(Mn<T> mem) { \
      return __mcsema_read_memory_v ## size (mem.addr); \
    } \
    ALWAYS_INLINE inline static MemoryWriter ## T W(MnW<T> mem) { \
      return MemoryWriter ## T {mem.addr}; \
    } \
    \
    ALWAYS_INLINE inline static T R(Vn<T> vec) { \
      return vec.val; \
    } \
    ALWAYS_INLINE inline static VecWriter ## T W(VnW<T> vec) { \
      return {vec.val_ref}; \
    }

MAKE_ACCESSORS(uint8_t, 8)
MAKE_ACCESSORS(uint16_t, 16)
MAKE_ACCESSORS(uint32_t, 32)
MAKE_ACCESSORS(uint64_t, 64)

MAKE_VEC_ACCESSORS(vec64_t, 64)
MAKE_VEC_ACCESSORS(vec128_t, 128)
MAKE_VEC_ACCESSORS(vec256_t, 256)
MAKE_VEC_ACCESSORS(vec512_t, 512)

#undef MAKE_ACCESSORS

}  // namespace
