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

}  // extern
