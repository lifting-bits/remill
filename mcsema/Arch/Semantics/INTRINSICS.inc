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

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_memory_intrinsics(void) {
  (void) __mcsema_read_memory_8;
  (void) __mcsema_read_memory_16;
  (void) __mcsema_read_memory_32;
  (void) __mcsema_read_memory_64;
  (void) __mcsema_read_memory_128;
  (void) __mcsema_read_memory_256;
  (void) __mcsema_read_memory_512;
  (void) __mcsema_write_memory_8;
  (void) __mcsema_write_memory_16;
  (void) __mcsema_write_memory_32;
  (void) __mcsema_write_memory_64;
  (void) __mcsema_write_memory_128;
  (void) __mcsema_write_memory_256;
  (void) __mcsema_write_memory_512;
  (void) __mcsema_compute_address;
}

// Control-flow intrinsics.
[[gnu::used]]
extern void __mcsema_error(State &);

[[gnu::used]]
extern void __mcsema_function_call(State &);

[[gnu::used]]
extern void __mcsema_function_return(State &);

[[gnu::used]]
extern void __mcsema_jump(State &);

[[gnu::used]]
extern void __mcsema_system_call(State &);

[[gnu::used]]
extern void __mcsema_system_return(State &);

[[gnu::used]]
extern void __mcsema_interrupt_call(State &);

[[gnu::used]]
extern void __mcsema_interrupt_return(State &);

// This is just a hack to make sure all these functions appear in the bitcode
// file!
[[gnu::used]]
void __mcsema_control_intrinsics(void) {
  (void) __mcsema_error;
  (void) __mcsema_function_call;
  (void) __mcsema_function_return;
  (void) __mcsema_jump;
  (void) __mcsema_system_call;
  (void) __mcsema_system_return;
  (void) __mcsema_interrupt_call;
  (void) __mcsema_interrupt_return;
}

}  // extern C
