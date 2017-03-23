/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <algorithm>

#include "tools/vmill/Runtime/Generic/Intrinsics.h"

size_t NumReadableBytes(Memory *memory, addr_t addr, size_t size) {
  addr_t i = 0;
  for (; i < size; i += 4096) {
    if (!__vmill_can_read_byte(memory, addr + static_cast<addr_t>(i))) {
      return i ? ((addr + i) & ~4095UL) - addr : 0;
    }
  }
  return std::min<size_t>(i, size);
}

size_t NumWritableBytes(Memory *memory, addr_t addr, size_t size) {
  addr_t i = 0;
  for (; i < size; i += 4096) {
    if (!__vmill_can_write_byte(memory, addr + static_cast<addr_t>(i))) {
      return i ? ((addr + i) & ~4095UL) - addr : 0;
    }
  }
  return std::min<size_t>(i, size);
}

Memory *CopyToMemory(Memory *memory, addr_t addr,
                     const void *data, size_t size) {
  auto data_bytes = reinterpret_cast<const uint8_t *>(data);
  for (size_t i = 0; i < size; ++i) {
    memory = __remill_write_memory_8(
        memory, addr + static_cast<addr_t>(i), data_bytes[i]);
  }
  return memory;
}

void CopyFromMemory(Memory *memory, void *data, addr_t addr, size_t size) {
  auto data_bytes = reinterpret_cast<uint8_t *>(data);
  for (size_t i = 0; i < size; ++i) {
    data_bytes[i] = __remill_read_memory_8(
        memory, addr + static_cast<addr_t>(i));
  }
}

size_t CopyStringFromMemory(Memory *memory, addr_t addr,
                            char *val, size_t max_len) {
  size_t i = 0;
  max_len = NumReadableBytes(memory, addr, max_len);
  for (; i < max_len; ++i) {
    val[i] = static_cast<char>(__remill_read_memory_8(memory, addr));
    if (!val[i]) {
      break;
    }
  }
  return i;
}

size_t CopyStringToMemory(Memory *memory, addr_t addr, const char *val,
                          size_t len) {
  size_t i = 0;
  len = NumWritableBytes(memory, addr, len);
  for (; i < len; ++i) {
    memory = __remill_write_memory_8(
        memory, addr, static_cast<uint8_t>(val[i]));
    if (!val[i]) {
      break;
    }
  }
  return i;
}

#define USED(sym) \
  __remill_mark_as_used(reinterpret_cast<const void *>(&sym))

extern "C" void __remill_mark_as_used(const void *);

[[gnu::used]]
extern "C" void __vmill_intrinsics(void) {
  USED(__vmill_create_address_space);
  USED(__vmill_clone_address_space);
  USED(__vmill_destroy_address_space);

  USED(__vmill_can_read_byte);
  USED(__vmill_can_write_byte);

  USED(__vmill_allocate_memory);
  USED(__vmill_free_memory);
  USED(__vmill_protect_memory);

  USED(__vmill_next_memory_end);
  USED(__vmill_prev_memory_begin);
}
