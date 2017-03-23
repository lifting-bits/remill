/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cstddef>
#include <unordered_map>

#include "tools/vmill/Executor/Runtime.h"

namespace remill {
namespace vmill {

static const std::unordered_map<std::string, size_t> kRuntimeOffset = {
    {"__remill_read_memory_8", offsetof(Runtime, read_memory_8)},
    {"__remill_read_memory_16", offsetof(Runtime, read_memory_16)},
    {"__remill_read_memory_32", offsetof(Runtime, read_memory_32)},
    {"__remill_read_memory_64", offsetof(Runtime, read_memory_64)},
    {"__remill_write_memory_8", offsetof(Runtime, write_memory_8)},
    {"__remill_write_memory_16", offsetof(Runtime, write_memory_16)},
    {"__remill_write_memory_32", offsetof(Runtime, write_memory_32)},
    {"__remill_write_memory_64", offsetof(Runtime, write_memory_64)},
    {"__remill_read_memory_f32", offsetof(Runtime, read_memory_f32)},
    {"__remill_read_memory_f64", offsetof(Runtime, read_memory_f64)},
    {"__remill_read_memory_f80", offsetof(Runtime, read_memory_f80)},
    {"__remill_write_memory_f32", offsetof(Runtime, write_memory_f32)},
    {"__remill_write_memory_f64", offsetof(Runtime, write_memory_f64)},
    {"__remill_write_memory_f80", offsetof(Runtime, write_memory_f80)},
    {"__remill_error", offsetof(Runtime, error)},
    {"__remill_jump", offsetof(Runtime, jump)},
    {"__remill_function_call", offsetof(Runtime, function_call)},
    {"__remill_function_return", offsetof(Runtime, function_return)},
    {"__remill_async_hyper_call", offsetof(Runtime, async_hyper_call)},
    {"__remill_sync_hyper_call", offsetof(Runtime, sync_hyper_call)},
    {"__remill_barrier_load_load", offsetof(Runtime, barrier_load_load)},
    {"__remill_barrier_load_store", offsetof(Runtime, barrier_load_store)},
    {"__remill_barrier_store_load", offsetof(Runtime, barrier_store_load)},
    {"__remill_barrier_store_store", offsetof(Runtime, barrier_store_store)},
    {"__remill_atomic_begin", offsetof(Runtime, atomic_begin)},
    {"__remill_atomic_end", offsetof(Runtime, atomic_end)},
    {"__remill_undefined_8", offsetof(Runtime, undefined_8)},
    {"__remill_undefined_16", offsetof(Runtime, undefined_16)},
    {"__remill_undefined_32", offsetof(Runtime, undefined_32)},
    {"__remill_undefined_64", offsetof(Runtime, undefined_64)},
    {"__remill_undefined_f32", offsetof(Runtime, undefined_f32)},
    {"__remill_undefined_f64", offsetof(Runtime, undefined_f64)},
    {"__remill_defer_inlining", offsetof(Runtime, defer_inlining)},
    {"__remill_mark_as_used", offsetof(Runtime, mark_as_used)},
};

// Used to look up the runtime functions.
void *Runtime::GetImplementation(const std::string &name) const {
  const auto offset_it = kRuntimeOffset.find(name);
  if (kRuntimeOffset.end() == offset_it) {
    return nullptr;
  } else {
    auto addr = reinterpret_cast<uintptr_t>(this);
    return *reinterpret_cast<void **>(addr + offset_it->second);
  }
}

}  // namespace vmill
}  // namespace remill
