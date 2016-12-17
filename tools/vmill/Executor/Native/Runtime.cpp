/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstring>

#include "remill/Arch/Runtime/Types.h"
#include "remill/Arch/Runtime/HyperCall.h"

#include "tools/vmill/Executor/Native/Runtime.h"

namespace remill {
namespace vmill {
extern "C" {

uint8_t __remill_read_memory_8(Memory *, uintptr_t addr) {
  return *reinterpret_cast<uint8_t *>(addr);
}

Memory *__remill_write_memory_8(Memory *memory, uintptr_t addr,
                                const uint8_t in) {
  *reinterpret_cast<uint8_t *>(addr) = in;
  return memory;
}

uint16_t __remill_read_memory_16(Memory *, uintptr_t addr) {
  return *reinterpret_cast<uint16_t *>(addr);
}

Memory *__remill_write_memory_16(Memory *memory, uintptr_t addr,
                                 const uint16_t in) {
  *reinterpret_cast<uint16_t *>(addr) = in;
  return memory;
}

uint32_t __remill_read_memory_32(Memory *, uintptr_t addr) {
  return *reinterpret_cast<uint32_t *>(addr);
}
Memory *__remill_write_memory_32(Memory *memory, uintptr_t addr,
                                 const uint32_t in) {
  *reinterpret_cast<uint32_t *>(addr) = in;
  return memory;
}

uint64_t __remill_read_memory_64(Memory *, uintptr_t addr) {
  return *reinterpret_cast<uint64_t *>(addr);
}

Memory *__remill_write_memory_64(Memory *memory, uintptr_t addr,
                                 const uint64_t in) {
  *reinterpret_cast<uint64_t *>(addr) = in;
  return memory;
}

float32_t __remill_read_memory_f32(Memory *, addr_t addr) {
  return *reinterpret_cast<float32_t *>(addr);
}

Memory *__remill_write_memory_f32(Memory *memory, addr_t addr, float32_t in) {
  *reinterpret_cast<float32_t *>(addr) = in;
  return memory;
}

float64_t __remill_read_memory_f64(Memory *, addr_t addr) {
  return *reinterpret_cast<float64_t *>(addr);
}

Memory *__remill_write_memory_f64(Memory *memory, addr_t addr, float64_t in) {
  *reinterpret_cast<float64_t *>(addr) = in;
  return memory;
}

float64_t __remill_read_memory_f80(Memory *, addr_t addr) {
  return *reinterpret_cast<float64_t *>(addr);  // TODO(pag): hacky?
}

Memory *__remill_write_memory_f80(Memory *memory, addr_t addr, float64_t val) {
  *reinterpret_cast<float64_t *>(addr) = val;
  return memory;
}

Memory *__remill_barrier_load_load(Memory *memory) { return memory; }
Memory *__remill_barrier_load_store(Memory *memory) { return memory; }
Memory *__remill_barrier_store_load(Memory *memory) { return memory; }
Memory *__remill_barrier_store_store(Memory *memory) { return memory; }
Memory *__remill_atomic_begin(Memory *memory) { return memory; }
Memory *__remill_atomic_end(Memory *memory) { return memory; }


ExecutionStatus __remill_error(Memory *, State &, addr_t) {
  return ExecutionStatus::kError;
}

Memory *__remill_sync_hyper_call(
    Memory *, State &, SyncHyperCall::Name) {
  __builtin_unreachable();
}

ExecutionStatus __remill_function_call(Memory *, State &, addr_t) {
  return ExecutionStatus::kFunctionCall;
}

ExecutionStatus __remill_function_return(Memory *, State &, addr_t) {
  return ExecutionStatus::kFunctionReturn;
}

ExecutionStatus __remill_jump(Memory *, State &, addr_t) {
  return ExecutionStatus::kJump;
}

ExecutionStatus __remill_async_hyper_call(Memory *, State &, addr_t) {
  return ExecutionStatus::kAsyncHyperCall;
}

uint8_t __remill_undefined_8(void) {
  return 0;
}

uint16_t __remill_undefined_16(void) {
  return 0;
}

uint32_t __remill_undefined_32(void) {
  return 0;
}

uint64_t __remill_undefined_64(void) {
  return 0;
}

float32_t __remill_undefined_f32(void) {
  return 0.0;
}

float64_t __remill_undefined_f64(void) {
  return 0.0;
}

void __remill_defer_inlining(void) {}
void __remill_mark_as_used(void *) {}

}  // extern C
}  // namespace vmill
}  // namespace remill
