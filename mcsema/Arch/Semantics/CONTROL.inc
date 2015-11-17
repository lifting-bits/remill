/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

extern "C" {

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
