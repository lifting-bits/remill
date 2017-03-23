/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <algorithm>
#include <random>

namespace {

static constexpr uint64_t kPageSize = 4096;
static constexpr uint64_t kMmapMinAddr = 65536;
static constexpr uint64_t k1GiB = 1ULL << 30ULL;
static constexpr uint64_t k3GiB = k1GiB * 3ULL;
static constexpr uint64_t k4GiB = k1GiB * 4ULL;

// Minimum allowed address for an `mmap`. On 64-bit, this is any address
// above the 4 GiB. In 32-bit, this is anything above 1 GiB.
static constexpr addr_t kAllocMin = IF_64BIT_ELSE(k4GiB, k1GiB);

// Maximum allowed address for an `mmap`.
static constexpr addr_t kAllocMax = IF_64BIT_ELSE((1ULL << 47ULL), k3GiB);

#if 32 == ADDRESS_SIZE_BITS
static std::ranlux24_base gRandGen(0  /* seed */);
#else
static std::ranlux48_base gRandGen(0  /* seed */);
#endif

// Go and find an address to map. This performs mostly opaque requests to the
// VMill memory manager as a way of finding a hole in memory. The idea here is
// that we don't want to completely shadow the structure maintained in VMill
// for the address space, so instead we'll just make queries to it.
static addr_t FindRegionToMap(Memory *memory, addr_t size) {
  for (auto i = 0; i < 16; ++i) {
    auto guess = static_cast<addr_t>(gRandGen() * kPageSize);
    auto where = std::min<addr_t>(guess, kAllocMax - size);

    auto next_end = __vmill_next_memory_end(memory, where);

    // There is no next mapping. This implies that `where` is not part of
    // any mapping. That being the case, `where` must be beyond any other
    // mapping, and so we have trivially discovered a hole.
    if (!next_end) {
      return where;
    }

    auto next_begin = __vmill_prev_memory_begin(memory, next_end - 1);
    if (next_begin <= where) {
      continue;  // `where` is inside of an existing range.
    }

    if ((where + size) <= next_begin) {
      return where;  // Found a hole big enough in front of the next mapping.
    }
  }

  // Linearly search for a hole.
  addr_t candidate = 0;
  for (auto max = kAllocMax; max >= kAllocMin; ) {
    auto prev_begin = __vmill_prev_memory_begin(memory, max - 1);
    auto prev_end = __vmill_next_memory_end(memory, prev_begin);

    // There is at least enough space between the end of one mapped
    // region and the beginning of another.
    if ((prev_end + size) <= max) {
      if ((max - prev_end - size) > kPageSize) {
        return max - size - kPageSize;  // At least one page of redzone.
      } else {
        candidate = max - size;
      }
    }

    max = prev_begin;
  }

  return candidate;
}

// Emulate an `brk` system call.
static Memory *SysBrk(Memory *memory, State *state,
                      const SystemCallABI &syscall) {
  return syscall.SetReturn(memory, state, -ENOMEM);
}

// Emulate an `mmap` system call.
static Memory *SysMmap(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  addr_t addr = 0;
  addr_t size = 0;
  int prot = 0;
  int flags = 0;
  int fd = -1;
  off_t offset = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size, &prot, &flags,
                          &fd, &offset)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  size = AlignToPage(size);
  if (!size) {  // Size not page aligned.
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // TODO(pag): Not quite right, we have limited support for file-backed memory
  //            mappings.
  if (-1 != fd) {
    if (STDIN_FILENO == fd || STDOUT_FILENO == fd || STDERR_FILENO == fd) {
      return syscall.SetReturn(memory, state, -EACCES);

    } else if (-1 > fd) {
      return syscall.SetReturn(memory, state, -EBADFD);

    } else if (0 > offset || offset % 4096) {  // Not page-aligned.
      return syscall.SetReturn(memory, state, -EINVAL);
    }

    if (offset > (offset + static_cast<ssize_t>(size))) {  // Signed overflow.
      return syscall.SetReturn(memory, state, -EOVERFLOW);
    }
  }

  // Unsupported flags.
  if ((MAP_SHARED & flags) || (MAP_GROWSDOWN & flags) || (MAP_32BIT & flags)) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Required flags.
  if (!(MAP_PRIVATE & flags)) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // A mapping can't be both anonymous and file-backed.
  if (fd && (MAP_ANONYMOUS & flags)) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  // Check the  hinted address.
  if (MAP_FIXED & flags) {
    addr = AlignToPage(addr);
    if (!addr) {
      return syscall.SetReturn(memory, state, -EINVAL);

    } else if (addr < kMmapMinAddr) {
      addr = kMmapMinAddr;  // Silently round it up to the minimum.
    }
  } else {
    addr = 0;  // TODO(pag): Is it right to not check this?
  }

  // Try to go and find a region of memory to map, assuming that one has
  // not been explicitly requested.
  if (!addr) {
    addr = FindRegionToMap(memory, size);
    if (!addr) {
      return syscall.SetReturn(memory, state, -ENOMEM);
    }
  }

  // Try to emulate file-backed `mmap`s by reading in the contents from disk.
  //
  // TODO(pag): In the future we could probably handle shared mappings by
  //            stealing a new fd (with `dup`), and recording some meta-data
  //            to note when to flush the mapped data.
  off_t old_offset = 0;
  if (fd) {
    old_offset = lseek(fd, 0, SEEK_CUR);
    if (-1 == old_offset) {
      return syscall.SetReturn(memory, state, -errno);
    }

    // Seek to the end of the range where we want to `mmap`. This is a dumb
    // way of checking to see that the region of memory is big enough to be
    // `mmap`ed.
    if (-1 == lseek(fd, offset + static_cast<off_t>(size), SEEK_SET)) {
      memory = syscall.SetReturn(memory, state, -errno);
    }

    if (-1 == lseek(fd, offset, SEEK_SET)) {
      memory = syscall.SetReturn(memory, state, -errno);
      lseek(fd, old_offset, SEEK_SET);  // Maintain transparency.
      return memory;
    }
  }

  // Allocate the RW memory.
  memory = __vmill_allocate_memory(memory, addr, size);

  // Copy data from the file into the memory mapping.
  if (fd) {
    for (addr_t i = 0; i < size; ) {
      auto ret = read(fd, gIOBuffer, kIOBufferSize);

      // Failed to copy part of the file into memory, need to reset the seek
      // head to its prior value to maintain transparency, then free the just
      // allocated memory.
      if (-1 == ret) {
        memory = syscall.SetReturn(memory, state, -errno);
        lseek(fd, old_offset, SEEK_SET);  // Reset.
        return __vmill_free_memory(memory, addr, size);

      } else {
        auto num_copied_bytes = static_cast<addr_t>(ret);
        memory = CopyToMemory(memory, addr, gIOBuffer, num_copied_bytes);
        i += num_copied_bytes;
      }
    }

    lseek(fd, old_offset, SEEK_SET);  // Reset.
  }

  bool can_read = PROT_READ & prot;
  bool can_write = PROT_WRITE & prot;
  bool can_exec = PROT_EXEC & prot;

  // Change the memory permissions if they are not the default ones.
  if (can_exec || !can_read || !can_write) {
    memory = __vmill_protect_memory(memory, addr, size, can_read,
                                    can_write, can_exec);
  }

  return syscall.SetReturn(memory, state, addr);
}

// Emulate an `munmap` system call.
static Memory *SysMunmap(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  addr_t addr = 0;
  addr_t size = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size)) {
    return syscall.SetReturn(memory, state, -EFAULT);

  } else if (addr != (addr & ~4095UL)) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  memory = __vmill_free_memory(memory, addr, size);
  return syscall.SetReturn(memory, state, 0);
}


// Emulate an `mprotect` system call.
static Memory *SysMprotect(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  addr_t addr = 0;
  addr_t size = 0;
  int prot = 0;
  if (!syscall.TryGetArgs(memory, state, &addr, &size, &prot)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  bool can_read = PROT_READ & prot;
  bool can_write = PROT_WRITE & prot;
  bool can_exec = PROT_EXEC & prot;

  memory = __vmill_protect_memory(memory, addr, size, can_read,
                                  can_write, can_exec);

  return syscall.SetReturn(memory, state, 0);
}

}  // namespace
