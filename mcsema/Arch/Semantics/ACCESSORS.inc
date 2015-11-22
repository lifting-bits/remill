/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

#define MAKE_ACCESSORS(T, size) \
    struct MemoryWriter ## size { \
      ALWAYS_INLINE inline void operator=(T val) const { \
        __mcsema_write_memory_ ## size (addr, val); \
      } \
      uintptr_t addr; \
    }; \
    ALWAYS_INLINE inline static T R(Mn<T> mem) { \
      return __mcsema_read_memory_ ## size (mem.addr); \
    } \
    ALWAYS_INLINE inline static MemoryWriter ## size W(MnW<T> mem) { \
      return MemoryWriter ## size {mem.addr}; \
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

MAKE_ACCESSORS(uint8_t, 8)
MAKE_ACCESSORS(uint16_t, 16)
MAKE_ACCESSORS(uint32_t, 32)
MAKE_ACCESSORS(uint64_t, 64)
MAKE_ACCESSORS(vec128_t, 128)
MAKE_ACCESSORS(vec256_t, 256)
MAKE_ACCESSORS(vec512_t, 512)

#undef MAKE_ACCESSORS

}  // namespace
