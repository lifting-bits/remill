/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EXECUTOR_RUNTIME_H_
#define TOOLS_VMILL_EXECUTOR_RUNTIME_H_

#include <string>

namespace remill {
namespace vmill {

// Runtime specification. This defines what opaque runtime functions need to be
// available to support an execution. What these functions mean and do is
// executor-specific. In a native executor, these would be pointers to C/C++
// functions.
struct Runtime {
  void * const read_memory_8;
  void * const read_memory_16;
  void * const read_memory_32;
  void * const read_memory_64;

  void * const write_memory_8;
  void * const write_memory_16;
  void * const write_memory_32;
  void * const write_memory_64;

  void * const read_memory_f32;
  void * const read_memory_f64;
  void * const read_memory_f80;

  void * const write_memory_f32;
  void * const write_memory_f64;
  void * const write_memory_f80;

  void * const error;
  void * const jump;
  void * const function_call;
  void * const function_return;
  void * const async_hyper_call;

  void * const sync_hyper_call;

  void * const barrier_load_load;
  void * const barrier_load_store;
  void * const barrier_store_load;
  void * const barrier_store_store;
  void * const atomic_begin;
  void * const atomic_end;

  void * const undefined_8;
  void * const undefined_16;
  void * const undefined_32;
  void * const undefined_64;
  void * const undefined_f32;
  void * const undefined_f64;

  void * const defer_inlining;
  void * const mark_as_used;

  // Used to look up the runtime functions. Returns `nullptr` if the runtime
  // function is not defined.
  void *GetImplementation(const std::string &name) const;

 private:
  Runtime(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EXECUTOR_RUNTIME_H_
