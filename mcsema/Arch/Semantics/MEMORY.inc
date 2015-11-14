/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

extern "C" {

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
extern uintptr_t __mcsema_compute_address(const State &state,
                                          uintptr_t address,
                                          int address_space);

// Memory read intrinsics.
extern uint8_t __mcsema_read_memory_8(uintptr_t);
extern uint16_t __mcsema_read_memory_16(uintptr_t);
extern uint32_t __mcsema_read_memory_32(uintptr_t);
extern uint64_t __mcsema_read_memory_64(uintptr_t);
extern vec128_t __mcsema_read_memory_128(uintptr_t);
extern vec256_t __mcsema_read_memory_256(uintptr_t);
extern vec512_t __mcsema_read_memory_512(uintptr_t);

// Memory write intrinsics.
extern void __mcsema_write_memory_8(uintptr_t, uint8_t);
extern void __mcsema_write_memory_16(uintptr_t, uint16_t);
extern void __mcsema_write_memory_32(uintptr_t, uint32_t);
extern void __mcsema_write_memory_64(uintptr_t, uint64_t);
extern void __mcsema_write_memory_128(uintptr_t, vec128_t);
extern void __mcsema_write_memory_256(uintptr_t, vec256_t);
extern void __mcsema_write_memory_512(uintptr_t, vec512_t);

}  // extern C

template <typename T>
struct Mn;

#define MAKE_TYPE(prefix, T, size) \
    template <> \
    struct Mn<T> { \
      ALWAYS_INLINE \
      inline void operator=(T that) { \
        __mcsema_write_memory_ ## size (addr, that); \
      } \
      ALWAYS_INLINE \
      inline void Write(T val) const { \
        return __mcsema_write_memory_ ## size (addr, val); \
      } \
      ALWAYS_INLINE \
      inline T Read(void) const { \
        return __mcsema_read_memory_ ## size (addr); \
      } \
      ALWAYS_INLINE \
      inline static void Write(uintptr_t addr_, T val) { \
        return __mcsema_write_memory_ ## size (addr_, val); \
      } \
      ALWAYS_INLINE \
      inline static T Read(uintptr_t addr_) { \
        return __mcsema_read_memory_ ## size (addr_); \
      } \
      uintptr_t addr; \
    }; \
    using prefix ## size = prefix ## n < T > ;



MAKE_TYPE(M, uint8_t, 8);
MAKE_TYPE(M, uint16_t, 16);
MAKE_TYPE(M, uint32_t, 32);
MAKE_TYPE(M, uint64_t, 64);
MAKE_TYPE(M, vec128_t, 128);
MAKE_TYPE(M, vec256_t, 256);
MAKE_TYPE(M, vec512_t, 512);
