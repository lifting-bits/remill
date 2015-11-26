/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

extern "C" {

// Address computation intrinsic. This is only used for non-zero
// `address_space`d memory accesses.
extern addr_t __mcsema_compute_address(const State &state,
                                          addr_t address,
                                          int address_space);

// Memory read intrinsics.
extern uint8_t __mcsema_read_memory_8(addr_t);
extern uint16_t __mcsema_read_memory_16(addr_t);
extern uint32_t __mcsema_read_memory_32(addr_t);
extern uint64_t __mcsema_read_memory_64(addr_t);

extern void __mcsema_read_memory_v64(addr_t, vec64_t &);
extern void __mcsema_read_memory_v128(addr_t, vec128_t &);
extern void __mcsema_read_memory_v256(addr_t, vec256_t &);
extern void __mcsema_read_memory_v512(addr_t, vec512_t &);

// Memory write intrinsics.
extern void __mcsema_write_memory_8(addr_t, uint8_t);
extern void __mcsema_write_memory_16(addr_t, uint16_t);
extern void __mcsema_write_memory_32(addr_t, uint32_t);
extern void __mcsema_write_memory_64(addr_t, uint64_t);

extern void __mcsema_write_memory_v64(addr_t, const vec64_t &);
extern void __mcsema_write_memory_v128(addr_t, const vec128_t &);
extern void __mcsema_write_memory_v256(addr_t, const vec256_t &);
extern void __mcsema_write_memory_v512(addr_t, const vec512_t &);

extern bool __mcsema_undefined_bool(void);
extern uint8_t __mcsema_undefined_8(void);
extern uint16_t __mcsema_undefined_16(void);
extern uint32_t __mcsema_undefined_32(void);
extern uint64_t __mcsema_undefined_64(void);

// Inlining control. The idea here is that sometimes we want to defer inlining
// until a later time, and we need to communicate what should eventually be
// inlined, even if it's not currently inlined.
extern void __mcsema_defer_inlining(void);

// Control-flow intrinsics.
extern void __mcsema_error(State &);
extern void __mcsema_function_call(State &);
extern void __mcsema_function_return(State &);
extern void __mcsema_jump(State &);
extern void __mcsema_system_call(State &);
extern void __mcsema_system_return(State &);
extern void __mcsema_interrupt_call(State &);
extern void __mcsema_interrupt_return(State &);

}  // extern C

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_intrinsics(void) {
  (void) __mcsema_read_memory_8;
  (void) __mcsema_read_memory_16;
  (void) __mcsema_read_memory_32;
  (void) __mcsema_read_memory_64;
  (void) __mcsema_read_memory_v64;
  (void) __mcsema_read_memory_v128;
  (void) __mcsema_read_memory_v256;
  (void) __mcsema_read_memory_v512;

  (void) __mcsema_write_memory_8;
  (void) __mcsema_write_memory_16;
  (void) __mcsema_write_memory_32;
  (void) __mcsema_write_memory_64;
  (void) __mcsema_write_memory_v64;
  (void) __mcsema_write_memory_v128;
  (void) __mcsema_write_memory_v256;
  (void) __mcsema_write_memory_v512;

  (void) __mcsema_compute_address;  // Used for segmented addresses.

  (void) __mcsema_defer_inlining;

  (void) __mcsema_error;
  (void) __mcsema_function_call;
  (void) __mcsema_function_return;
  (void) __mcsema_jump;
  (void) __mcsema_system_call;
  (void) __mcsema_system_return;
  (void) __mcsema_interrupt_call;
  (void) __mcsema_interrupt_return;

  (void) __mcsema_undefined_bool;
  (void) __mcsema_undefined_8;
  (void) __mcsema_undefined_16;
  (void) __mcsema_undefined_32;
  (void) __mcsema_undefined_64;
}
