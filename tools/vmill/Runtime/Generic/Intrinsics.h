/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_RUNTIME_INTRINSICS_H_
#define TOOLS_VMILL_RUNTIME_INTRINSICS_H_

#include "remill/Arch/Runtime/Intrinsics.h"

extern "C" {

// Create a new address space.
[[gnu::used, gnu::const]]
extern Memory *__vmill_create_address_space(void);

// Clone an address space. The clone will be a copy-on-write version of the
// original. It is safe to use the original and clone concurrently.
[[gnu::used, gnu::const]]
extern Memory *__vmill_clone_address_space(Memory *);

// Destroy an address space. This deletes all memory ranges. All future uses
// of the `Memory` pointer are considered invalid.
[[gnu::used]]
extern void __vmill_destroy_address_space(Memory *);

// Returns true if the memory at address `addr` is readable.
[[gnu::used, gnu::const]]
extern bool __vmill_can_read_byte(Memory *memory, addr_t addr);

// Returns true if the memory at address `addr` is writable.
[[gnu::used, gnu::const]]
extern bool __vmill_can_write_byte(Memory *memory, addr_t addr);

// Requests a new memory allocation from the VMM. The caller is responsible
// for specifying where the memory should be allocated. This means that the
// caller is in charge of emulating the `mmap` behavior of a program, e.g.
// to emulate things like ASLR. This also means that passing in `0` is a valid
// thing and that it can/will be allocated.
extern Memory *__vmill_allocate_memory(Memory *memory, addr_t where,
                                       addr_t size);

// Tells the VMM to free some memory.
extern Memory *__vmill_free_memory(Memory *memory, addr_t where, addr_t size);

// Tells the VMM to change the permissions of some memory range.
extern Memory *__vmill_protect_memory(Memory *memory, addr_t where,
                                      addr_t size, bool can_read,
                                      bool can_write, bool can_exec);

// Returns the end of the mapped range of memory whose address is greater
// than `where`. This permits forward iteration through mapped memory ranges.
//
// If `A` is a mapped address, then `__vmill_next_memory_end(memory, A)` is
// the ending of the memory map containing `A`.
extern addr_t __vmill_next_memory_end(Memory *memory, addr_t where);

// Returns the beginning of the mapped range of memory whose address is less
// than or equal to `where`. This permits backward iteration through mapped
// memory ranges.
//
// If `A` is a mapped address, then `__vmill_prev_memory_begin(memory, A)` is
// the beginning of the memory map containing `A`.
extern addr_t __vmill_prev_memory_begin(Memory *memory, addr_t where);

}  // extern C

size_t NumReadableBytes(Memory *memory, addr_t addr, size_t size);
size_t NumWritableBytes(Memory *memory, addr_t addr, size_t size);

inline static bool CanReadMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumReadableBytes(memory, addr, size);
}

inline static bool CanWriteMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumWritableBytes(memory, addr, size);
}

Memory *CopyToMemory(Memory *memory, addr_t addr,
                     const void *data, size_t size);

void CopyFromMemory(Memory *memory, void *data, addr_t addr, size_t size);

template <typename T>
inline static T ReadMemory(Memory *memory, addr_t addr) {
  T val{};
  CopyFromMemory(memory, &val, addr, sizeof(T));
  return val;
}

template <typename T>
inline static bool TryReadMemory(Memory *memory, addr_t addr, T *val) {
  if (CanReadMemory(memory, addr, sizeof(T))) {
    CopyFromMemory(memory, val, addr, sizeof(T));
    return true;
  } else {
    return false;
  }
}

template <typename T>
inline static bool TryWriteMemory(Memory *&memory, addr_t addr, const T &val) {
  if (CanWriteMemory(memory, addr, sizeof(T))) {
    memory = CopyToMemory(memory, addr, &val, sizeof(T));
    return true;
  } else {
    return false;
  }
}

size_t CopyStringFromMemory(Memory *memory, addr_t addr,
                            char *val, size_t max_len);

size_t CopyStringToMemory(Memory *memory, addr_t addr, const char *val,
                          size_t len);

inline static addr_t AlignToPage(addr_t addr) {
  return addr & ~4095UL;
}

inline static addr_t AlignToNextPage(addr_t addr) {
  return (addr + 4095UL) & ~4095UL;
}

#endif  // TOOLS_VMILL_RUNTIME_INTRINSICS_H_
