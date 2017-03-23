/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CONTEXT_ADDRESSSPACE_H_
#define TOOLS_VMILL_CONTEXT_ADDRESSSPACE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

namespace remill {
namespace vmill {

// Basic information about some region of mapped memory within an address space.
struct AddressRange {
  uint64_t base_address;
  uint64_t limit_address;

  // Permissions.
  bool can_read;
  bool can_write;
  bool can_exec;

  inline uint64_t Size(void) const {
    return limit_address - base_address;
  }

  inline bool operator<(const AddressRange &other) const {
    return base_address < other.limit_address;
  }
};

// Forward declaration of underlying memory map type.
class MemoryMap;
using MemoryMapPtr = std::shared_ptr<MemoryMap>;

// Version hash for executable memory maps.
using CodeVersion = uint64_t;

// Basic memory implementation.
class AddressSpace {
 public:
  AddressSpace(void);

  // Creates a copy/clone of another address space.
  explicit AddressSpace(const AddressSpace &);

  // Kill this address space. This prevents future allocations, and removes
  // all existing ranges.
  void Kill(void);

  // Returns `true` if the byte at address `addr` is readable,
  // writable, or executable, respectively.
  bool CanRead(uint64_t addr);
  bool CanWrite(uint64_t addr);
  bool CanExecute(uint64_t addr);

  // Read/write a byte to memory. Returns `false` if the read or write failed.
  bool TryRead(uint64_t addr, uint8_t *val);
  bool TryWrite(uint64_t addr, uint8_t val);

  // Read a byte as an executable byte. This is used for instruction decoding.
  // Returns `false` if the read failed. This will update `version_out` to
  // represent the version of the memory range being read.
  bool TryReadExecutable(uint64_t addr, uint8_t *val, CodeVersion *version_out);

  // Change the permissions of some range of memory. This can split memory
  // maps.
  void SetPermissions(uint64_t base, size_t size, bool can_read,
                      bool can_write, bool can_exec);

  // Adds a new memory mapping with default read/write permissions.
  void AddMap(uint64_t base, size_t size);

  // Removes a memory mapping.
  void RemoveMap(uint64_t base, size_t size);

  // Log out the current state of the memory maps.
  void LogMaps(void);

  // Does a query and produces:
  //
  //  Into `glb`: The base address of the nearest mapped memory range whose
  //              base address is less-than-or-equal to `find`. This is a
  //              kind of greatest lower bound.
  //
  //  Into `lub`: The limit address of the nearest mapped memory range whose
  //              limit address is greater than `find`. This is a kind of
  //              least upper bound.
  //
  // The purpose of this function is to permit opaque queries into the
  // structure of the memory layout, without requiring a complete
  // understanding thereof. This function can be used by a runtime to
  // implement something like `mmap`, where the implementation needs to
  // find a hole in memory big enough to satisfy the request. Ideally, the
  // runtime should not have to duplicate/shadow the map information
  // maintained by vmill.
  //
  // The value placed into `lub` is zero if `find` is greater than-or-equal-to
  // the maximum `limit_address` of any mapped range.
  //
  // The value placed into `glb` is the maximum value for a `uint64_t` if
  // there is no memory map whose `base_address` is less-than-or-equal-to
  // `find`.
  void NearestMemoryMap(uint64_t find, uint64_t *glb, uint64_t *lub);

 private:
  AddressSpace(AddressSpace &&) = delete;
  AddressSpace &operator=(const AddressSpace &) = delete;
  AddressSpace &operator=(const AddressSpace &&) = delete;

  // Check that the ranges are sane.
  void CheckRanges(std::vector<MemoryMapPtr> &r, bool is_sorted);

  // Recreate the `range_base_to_index` and `range_limit_to_index` indices.
  void CreateIndex(void);

  // Find the memory map containing `addr`. If none is found then a "null"
  // map pointer is returned, whose operations will all fail.
  MemoryMapPtr &FindRange(uint64_t addr);

  // Used to represent an invalid memory map.
  MemoryMapPtr invalid_map;

  // List of mapped memory page ranges.
  std::vector<MemoryMapPtr> maps;

  // Maps base/limits into the `ranges` vector.
  std::map<uint64_t, unsigned> map_base_to_index;
  std::map<uint64_t, unsigned> map_limit_to_index;

  // First-level cache.
  MemoryMapPtr last_map;
  uint64_t last_map_base;
  uint64_t last_map_limit;

  // A cache mapping pages accessed to the range.
  std::unordered_map<uint64_t, MemoryMapPtr> page_to_map;

  // Is the address space dead? This means that all operations on it
  // will be muted.
  bool is_dead;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CONTEXT_ADDRESSSPACE_H_
