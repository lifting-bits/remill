/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <limits>

#include "remill/Arch/Arch.h"
#include "remill/OS/OS.h"

#include "third_party/murmurhash/MurmurHash2.h"

#include "tools/vmill/Context/AddressSpace.h"

namespace remill {
namespace vmill {
namespace {

enum : uint64_t {
  k1MiB = 1ULL << 20ULL,
  k1GiB = 1ULL << 30ULL,
  k4GiB = k1GiB * 4ULL,

  kPageSize = 4096ULL,
  kPageShift = (kPageSize - 1ULL),
  kPageMask = ~kPageShift
};

static const AddressRange kZeroRange = {};

static constexpr inline uint64_t AlignDownToPage(uint64_t addr) {
  return addr & kPageMask;
}

static constexpr inline uint64_t RoundUpToPage(uint64_t size) {
  return (size + kPageShift) & kPageMask;
}

}  // namespace

// Backing store for some region of mapped memory within an address space.
class MemoryMap : public AddressRange {
 public:
  explicit MemoryMap(const AddressRange &info);
  ~MemoryMap(void);

  void SetCanRead(bool new_can_read);
  void SetCanWrite(bool new_can_write);
  void SetCanExecute(bool new_can_exec);

  inline bool CanRead(void) const {
    return can_read;
  }

  inline bool CanWrite(void) const {
    return can_write;
  }

  inline bool CanExecute(void) const {
    return can_read && can_exec;
  }

  // Clones this memory map. The underlying operation is to create two new
  // memory maps. The first is the map returned representing the clone. The
  // second is a memory map that becomes a new parent of the current and clone,
  // effectively making the current map a clone itself.
  MemoryMapPtr Clone(void);

  // Clones a sub range of this memory map. If the sub range is the same as
  // the current range, then we return the current memory map. The ideal
  // scenario is that we reduce the amount of actual cloning that needs to
  // happen.
  MemoryMapPtr CloneOrKeepRange(const MemoryMapPtr &self,
                                uint64_t cut_base, uint64_t cut_limit);

  using ReadFuncType = bool (MemoryMap::*)(uint64_t, uint8_t *);
  using WriteFuncType = bool (MemoryMap::*)(uint64_t, uint8_t);

  // Read bytes from a memory range.
  [[gnu::always_inline, gnu::gnu_inline]]
  inline bool Read(uint64_t addr, uint8_t *val) {
    return (this->*do_read)(addr, val);
  }

  // Write bytes to a memory range.
  [[gnu::always_inline, gnu::gnu_inline]]
  inline bool Write(uint64_t addr, uint8_t val) {
    if (addr == 0x877a43d) {
      asm("nop;");
    }
    return (this->*do_write)(addr, val);
  }

  // Read a byte as an executable byte. This is used for instruction decoding.
  bool ReadExecutable(uint64_t addr, uint8_t *val, CodeVersion *version_out);

 private:
  MemoryMap(void) = delete;

  bool ReadZero(uint64_t addr, uint8_t *val);
  bool ReadFromParent(uint64_t addr, uint8_t *val);
  bool ReadFromMem(uint64_t addr, uint8_t *val);
  bool ReadFail(uint64_t addr, uint8_t *val);

  bool WriteInit(uint64_t addr, uint8_t val);
  bool WriteCopyParent(uint64_t addr, uint8_t val);
  bool WriteToMem(uint64_t addr, uint8_t val);
  bool WriteFail(uint64_t addr, uint8_t val);


  // Pointer to the parent memory map. This is used for copy-on-write
  // mappings.
  MemoryMapPtr parent;

  // Points to some allocated data.
  uint8_t *base;

  // Access functions that are aware of the current state of the memory.
  ReadFuncType do_read;
  WriteFuncType do_write;

  // Used to approximately detect at least some self-modification.
  bool seen_write_since_exec;
  bool seen_exec;

  // Content hash used for tracking executable range versions.
  CodeVersion version;
};

MemoryMap::~MemoryMap(void) {
  if (base) {
    delete[] base;
  }
}

MemoryMap::MemoryMap(const AddressRange &info)
    : AddressRange(info),
      parent(nullptr),
      base(nullptr),
      do_read(CanRead() ? &MemoryMap::ReadZero : &MemoryMap::ReadFail),
      do_write(CanWrite() ? &MemoryMap::WriteInit : &MemoryMap::WriteFail),
      seen_write_since_exec(false),
      seen_exec(false),
      version(0) {}

bool MemoryMap::ReadZero(uint64_t, uint8_t *val) {
  *val = 0;
  return true;
}

bool MemoryMap::ReadFromParent(uint64_t addr, uint8_t *val) {
  return (parent.get()->*do_read)(addr, val);
}

bool MemoryMap::ReadFromMem(uint64_t addr, uint8_t *val) {
  *val = base[addr - base_address];
  return true;
}

bool MemoryMap::ReadFail(uint64_t, uint8_t *) {
  return false;
}

bool MemoryMap::WriteInit(uint64_t addr, uint8_t val) {
  base = new uint8_t[Size()];
  memset(base, 0, Size());
  do_write = &MemoryMap::WriteToMem;
  do_read = &MemoryMap::ReadFromMem;
  return WriteToMem(addr, val);
}

bool MemoryMap::WriteCopyParent(uint64_t addr, uint8_t val) {
  base = new uint8_t[Size()];
  memcpy(base, parent->base, Size());
  parent.reset();
  do_write = &MemoryMap::WriteToMem;
  do_read = &MemoryMap::ReadFromMem;
  return WriteToMem(addr, val);
}

bool MemoryMap::WriteToMem(uint64_t addr, uint8_t val) {
  base[addr - base_address] = val;
  seen_write_since_exec = true;
  return true;
}

bool MemoryMap::WriteFail(uint64_t, uint8_t) {
  return false;
}

bool MemoryMap::ReadExecutable(uint64_t addr, uint8_t *val,
                               CodeVersion *version_out) {
  if (!CanExecute()) {
    return false;
  }

  if (seen_write_since_exec || !seen_exec) {
    auto old_version = version;
    version = MurmurHash64A(
        base,
        Size(),
        (base_address % kPageSize) * (limit_address % kPageSize));

    if (seen_write_since_exec) {
      DLOG(WARNING)
          << "  ReadExecutable: Self-modifying code detected in range ["
          << std::hex << base_address << ", "
          << std::hex << limit_address << "). Old version "
          << std::hex << old_version << ", new version "
          << std::hex << version;
    } else {
      DLOG(INFO)
        << "  ReadExecutable: Initial possible code exec for range ["
        << std::hex << base_address << ", "
        << std::hex << limit_address << "). New version "
        << std::hex << version;
    }

    seen_write_since_exec = false;
  }

  seen_exec = true;
  if (version_out) {
    *version_out = version;
  }
  return Read(addr, val);
}

MemoryMapPtr MemoryMap::Clone(void) {

  // This is a page with actual data in it. Create a new parent of this page
  // and steal this page's memory, putting it into the new parent, making this
  // page a copy-on-write version of the parent.
  if (base) {
    auto reparent = std::make_shared<MemoryMap>(*this);
    reparent->base = base;
    reparent->version = version;
    reparent->do_read = do_read;
    reparent->do_write = do_write;
    reparent->seen_exec = seen_exec;
    reparent->seen_write_since_exec = seen_write_since_exec;

    base = nullptr;
    parent = reparent;
    do_read = CanRead() ? &MemoryMap::ReadFromParent : &MemoryMap::ReadFail;
    do_write = CanWrite() ? &MemoryMap::WriteCopyParent : &MemoryMap::WriteFail;
  }

  // This is a copy-on-write page that passes through from its parent.
  if (parent) {
    auto ret = std::make_shared<MemoryMap>(*this);
    ret->parent = parent;
    ret->do_read = do_read;
    ret->do_write = do_write;
    ret->version = version;
    ret->seen_exec = seen_exec;
    ret->seen_write_since_exec = seen_write_since_exec;
    return ret;

  // This is an empty page that isn't yet initialized; cloning it should just
  // produce a new such empty page.
  } else {
    return std::make_shared<MemoryMap>(*this);
  }
}

MemoryMapPtr MemoryMap::CloneOrKeepRange(
    const MemoryMapPtr &self, uint64_t cut_base, uint64_t cut_limit) {

  // The sub-range and this range are the same; return this range.
  if (cut_base == base_address && cut_limit == limit_address) {
    if (parent) {
      return parent;
    } else {
      return self;
    }

  // Copy-on-write of a parent; take a slice of the parent.
  } else if (parent) {
    auto ret = Clone();
    ret->base_address = std::max(cut_base, base_address);
    ret->limit_address = std::min(cut_limit, limit_address);

    // Treat a slice as being a kind of write. We only do this if we've seen
    // an exec of the parent. Consider the case of mapping in the data of
    // an ELF, doing relocation fixups, then changing a portion of the map
    // into executable. That part will never have been executable, so we don't
    // want to trigger a rehash of it.
    if (seen_exec) {
      ret->seen_write_since_exec = true;
    }

    return ret;

  // Copy a slice of of the parent.
  } else if (base) {
    auto ret = std::make_shared<MemoryMap>(*this);
    ret->base_address = std::max(cut_base, base_address);
    ret->limit_address = std::min(cut_limit, limit_address);
    ret->base = new uint8_t[ret->Size()];
    ret->do_read = do_read;
    ret->do_write = do_write;

    // See above comment.
    if (seen_exec) {
      ret->seen_write_since_exec = true;
    }

    memcpy(ret->base, &(base[ret->base_address - base_address]), ret->Size());
    return ret;

  // This range is empty, so return a new empty range.
  } else {
    auto ret = std::make_shared<MemoryMap>(*this);
    ret->base_address = cut_base;
    ret->limit_address = cut_limit;
    return ret;
  }
}

void MemoryMap::SetCanRead(bool new_can_read) {
  if (can_read == new_can_read) {
    return;
  }

  // Going from readable -> not readable
  if (!new_can_read) {
    do_read = &MemoryMap::ReadFail;

  // Copy-on-write, going from not readable -> readable
  } else if (parent) {
    do_read = &MemoryMap::ReadFromParent;

  // Memory backed, going from not readable -> readable
  } else if (base) {
    do_read = &MemoryMap::ReadFromMem;

  // Uninitialized, going from not readable -> readable
  } else {
    do_read = &MemoryMap::ReadZero;
  }

  can_read = new_can_read;
}

void MemoryMap::SetCanWrite(bool new_can_write) {
  if (can_write == new_can_write) {
    return;
  }

  // Going from writable -> not writable
  if (!new_can_write) {
    do_write = &MemoryMap::WriteFail;

  // Copy-on-write, going from not writable -> writable
  } else if (parent) {
    do_write = &MemoryMap::WriteCopyParent;

  // Memory backed, going from not readable -> readable
  } else if (base) {
    do_write = &MemoryMap::WriteToMem;

  // Uninitialized, going from not readable -> readable
  } else {
    do_write = &MemoryMap::WriteInit;
  }

  can_write = new_can_write;
}

void MemoryMap::SetCanExecute(bool new_can_exec) {
  can_exec = new_can_exec;

  if (!seen_exec && can_exec) {
    seen_write_since_exec = false;
  }
}

AddressSpace::AddressSpace(void)
    : invalid_map(std::make_shared<MemoryMap>(kZeroRange)),
      last_map(invalid_map),
      last_map_base(0),
      last_map_limit(0),
      page_to_map(256),
      is_dead(false) {}

AddressSpace::AddressSpace(const AddressSpace &parent)
    : AddressSpace() {
  is_dead = parent.is_dead;

  if (!is_dead) {
    for (const auto &range : parent.maps) {
      maps.push_back(range->Clone());
    }
    CreateIndex();
  }
}

// Clear out the contents of this address space.
void AddressSpace::Kill(void) {
  maps.clear();
  page_to_map.clear();
  map_base_to_index.clear();
  map_limit_to_index.clear();
  is_dead = true;
}

bool AddressSpace::CanRead(uint64_t addr) {
  return FindRange(addr)->CanRead();
}

bool AddressSpace::CanWrite(uint64_t addr) {
  return FindRange(addr)->CanWrite();
}

bool AddressSpace::CanExecute(uint64_t addr) {
  return FindRange(addr)->CanExecute();
}

// Read/write a byte to memory.
bool AddressSpace::TryRead(uint64_t addr, uint8_t *val) {
  return FindRange(addr)->Read(addr, val);
}

bool AddressSpace::TryWrite(uint64_t addr, uint8_t val) {
  return FindRange(addr)->Write(addr, val);
}

// Read a byte as an executable byte. This is used for instruction decoding.
bool AddressSpace::TryReadExecutable(uint64_t addr, uint8_t *val,
                                     CodeVersion *version_out) {
  return FindRange(addr)->ReadExecutable(addr, val, version_out);
}

namespace {

// Return a vector of memory maps, where none of the maps overlap with the
// range of memory `[base, limit)`.
std::vector<MemoryMapPtr> RemoveRange(
    const std::vector<MemoryMapPtr> &ranges, uint64_t base, uint64_t limit) {

  std::vector<MemoryMapPtr> new_ranges;
  new_ranges.reserve(ranges.size() + 1);

  DLOG(INFO)
      << "  RemoveRange: [" << std::hex << base << ", "
      << std::hex << limit << ")";

  for (auto &map : ranges) {

    // No overlap between `map` and the range to remove.
    if (map->limit_address <= base || map->base_address >= limit) {
      DLOG(INFO)
          << "    Keeping with no overlap ["
          << std::hex << map->base_address << ", "
          << std::hex << map->limit_address << ")";
      new_ranges.push_back(map);

    // `map` is fully contained in the range to remove.
    } else if (map->base_address >= base && map->limit_address <= limit) {
      DLOG(INFO)
          << "    Removing with full containment ["
          << std::hex << map->base_address << ", "
          << std::hex << map->limit_address << ")";
      continue;

    // The range to remove is fully contained in `map`.
    } else if (map->base_address < base && map->limit_address > limit) {
      DLOG(INFO)
          << "    Splitting with overlap ["
          << std::hex << map->base_address << ", "
          << std::hex << map->limit_address << ") into "
          << "[" << std::hex << map->base_address << ", "
          << std::hex << base << ") and ["
          << std::hex << limit << ", " << std::hex << map->limit_address << ")";
      new_ranges.push_back(map->CloneOrKeepRange(
          map, map->base_address, base));
      new_ranges.push_back(map->CloneOrKeepRange(
          map, limit, map->limit_address));

    // The range to remove is a prefix of `map`.
    } else if (map->base_address == base) {
      DLOG(INFO)
          << "    Keeping prefix [" << std::hex << limit << ", "
          << std::hex << map->limit_address << ")";
      new_ranges.push_back(map->CloneOrKeepRange(
          map, limit, map->limit_address));

    // The range to remove is a suffix of `map`.
    } else {
      DLOG(INFO)
          << "    Keeping suffix ["
          << std::hex << map->base_address << ", "
          << std::hex << base << ")";
      new_ranges.push_back(map->CloneOrKeepRange(
          map, map->base_address, base));
    }
  }

  return new_ranges;
}

// Return a vector of memory maps, containing only memory maps that fall in
// the range `[base, limit)`.
std::vector<MemoryMapPtr> KeepRange(
    const std::vector<MemoryMapPtr> &ranges, uint64_t base, uint64_t limit) {

  std::vector<MemoryMapPtr> new_ranges;
  new_ranges.reserve(2);

  DLOG(INFO)
      << "  KeepRange: [" << std::hex << base << ", "
      << std::hex << limit << ")";

  for (auto &map : ranges) {
    if (map->limit_address <= base || map->base_address >= limit) {
      DLOG(INFO)
          << "    Not keeping [" << std::hex << base << ", "
          << std::hex << limit << ")";
      continue;
    } else {
      auto sub_range = map->CloneOrKeepRange(map, base, limit);
      DLOG(INFO)
          << "    Keeping sub range [" << std::hex << sub_range->base_address
          << ", " << std::hex << sub_range->limit_address << ") of ["
          << std::hex << map->base_address << ", " << std::hex
          << map->limit_address << ")";
      new_ranges.push_back(sub_range);
    }
  }

  return new_ranges;
}

}  // namespace

void AddressSpace::SetPermissions(uint64_t base_, size_t size, bool can_read,
                                  bool can_write, bool can_exec) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  DLOG(INFO)
      << "SetPermissions: [" << std::hex << base << ", "
      << std::hex << limit << ") to "
      << "can_read=" << can_read << " can_write="
      << can_write << " can_exec=" << can_exec;

  // Check to see if the exact range already exists before splitting.
  auto &existing_range = FindRange(base);
  if (existing_range->base_address == base &&
      existing_range->limit_address == limit) {

    if (existing_range->can_read == can_read &&
        existing_range->can_write == can_write &&
        existing_range->can_exec == can_exec) {
      DLOG(INFO)
          << "  Existing range already has correct permissions";
    } else {
      DLOG(INFO)
          << "  Set permissions on existing range";

      existing_range->SetCanRead(can_read);
      existing_range->SetCanWrite(can_write);
      existing_range->SetCanExecute(can_exec);
    }
    return;
  }

  if (is_dead) {
    LOG(ERROR)
        << "Trying to set permissions on range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }

  auto old_ranges = RemoveRange(maps, base, limit);
  auto new_ranges = KeepRange(maps, base, limit);

  CheckRanges(old_ranges, true);
  CheckRanges(new_ranges, true);

  for (auto &range : new_ranges) {
    range->SetCanRead(can_read);
    range->SetCanWrite(can_write);
    range->SetCanExecute(can_exec);
  }

  maps.swap(old_ranges);
  maps.insert(maps.end(), new_ranges.begin(), new_ranges.end());

  CheckRanges(maps, false);
  CreateIndex();
}

void AddressSpace::AddMap(uint64_t base_, size_t size) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  if (is_dead) {
    LOG(ERROR)
        << "Trying to map range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }

  DLOG(INFO)
      << "AddMap: [" << std::hex << base << ", " << std::hex << limit << ")";

  auto old_ranges = RemoveRange(maps, base, limit);
  CheckRanges(old_ranges, true);
  AddressRange new_range = {base, limit, true, true, false};
  maps.swap(old_ranges);
  maps.push_back(std::make_shared<MemoryMap>(new_range));
  CheckRanges(maps, false);
  CreateIndex();
}

void AddressSpace::RemoveMap(uint64_t base_, size_t size) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  DLOG(INFO)
      << "RemoveMap: [" << std::hex << base << ", " << std::hex << limit << ")";

  if (is_dead) {
    LOG(ERROR)
        << "Trying to unmap range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }

  maps = RemoveRange(maps, base, limit);
  CheckRanges(maps, true);
  CreateIndex();
}

void AddressSpace::NearestMemoryMap(
    uint64_t find, uint64_t *glb, uint64_t *lub) {

  *glb = std::numeric_limits<uint64_t>::max();
  *lub = 0;

  if (is_dead) {
    LOG(ERROR)
        << "Trying to query upper and lower bounds of "
        << std::hex << find << " in destroyed address space.";
    return;
  }

  auto lower_bound = map_base_to_index.lower_bound(find);
  auto upper_bound = map_limit_to_index.upper_bound(find);

  if (lower_bound != map_base_to_index.end()) {
    *glb = lower_bound->first;
  }

  if (upper_bound != map_limit_to_index.end()) {
    *lub = upper_bound->first;
  }
}

// Check that the ranges are sane.
void AddressSpace::CheckRanges(std::vector<MemoryMapPtr> &r, bool is_sorted) {
#if !defined(NDEBUG)
  if (!is_sorted) {
    std::sort(r.begin(), r.end(),
              [] (const MemoryMapPtr &left, const MemoryMapPtr &right) {
                return left->base_address < right->base_address;
              });
  }

  if (1 >= r.size()) {
    return;  // Trivially sorted.
  }

  auto it = r.begin();
  auto it_end = r.end() - 1;

  for (; it != it_end; ) {
    const auto &curr = *it;
    const auto &next = *++it;

    CHECK(curr->base_address < curr->limit_address)
        << "Invalid range bounds [" << std::hex << curr->base_address << ", "
        << std::hex << curr->limit_address << ")";

    CHECK(curr->limit_address <= next->base_address)
          << "Overlapping ranges [" << std::hex << curr->base_address << ", "
          << std::hex << curr->limit_address << ") and ["
          << std::hex << next->base_address << ", "
          << std::hex << next->limit_address << ")";
  }

#else
  (void) r;
  (void) is_sorted;
#endif  // !defined(NDEBUG)
}

void AddressSpace::CreateIndex(void) {
  last_map = invalid_map;
  last_map_base = 0;
  last_map_limit = 0;
  page_to_map.clear();
  map_base_to_index.clear();
  map_limit_to_index.clear();

  if (maps.empty()) {
    return;
  }

  unsigned i = 0;
  for (const auto &range : maps) {
    map_base_to_index[range->limit_address - 1] = i;
    map_limit_to_index[range->base_address] = i;
    ++i;
  }
}

MemoryMapPtr &AddressSpace::FindRange(uint64_t addr) {
  auto page_addr = AlignDownToPage(addr);

  // First level cache; depends on data locality.
  if (last_map_base <= addr && addr < last_map_limit) {
    return last_map;
  }

  // Second level cache, depends on prior lookups.
  auto &range = page_to_map[page_addr];
  if (is_dead) {
    LOG(ERROR)
        << "Trying to find memory map associated with address "
        << std::hex << addr << " in destroyed address space.";
    range = invalid_map;  // Backup invalid map.
  }

  if (range) {
    last_map = range;
    last_map_base = range->base_address;
    last_map_limit = range->limit_address;
    return range;
  }

  // Third-level cache; depends on locality and crossing pages.
  auto prev_range_it = page_to_map.find(page_addr - kPageSize);
  if (prev_range_it != page_to_map.end() &&
      addr < prev_range_it->second->limit_address) {
    range = prev_range_it->second;
    return range;
  }

  range = invalid_map;  // Backup invalid map.
  if (maps.empty()) {
    LOG(ERROR)
        << "Cannot find range for address 0x" << std::hex << addr
        << " in empty address space";
    return range;
  }

  // Last level, do a full search, using the index map to find the right range.
  auto found = false;
  auto lower_bound = map_base_to_index.lower_bound(addr);
  if (lower_bound != map_base_to_index.end()) {
    auto &lb_range = maps[lower_bound->second];
    if (lb_range->base_address <= addr && addr < lb_range->limit_address) {
      range = lb_range;
      last_map = range;
      last_map_base = range->base_address;
      last_map_limit = range->limit_address;
      found = true;
    }
  }

  DLOG_IF(WARNING, !found)
      << "Did not find valid page range for address 0x" << std::hex << addr;

  return range;
}

// Log out the current state of the memory maps.
void AddressSpace::LogMaps(void) {
  CheckRanges(maps, false);
  LOG(INFO)
      << "Memory maps:";
  for (const auto &range : maps) {
    LOG(INFO)
        << "  [" << std::hex << range->base_address << ", "
        << std::hex << range->limit_address << ") with permissions "
        << "can_read=" << range->can_read << " can_write="
        << range->can_write << " can_exec=" << range->can_exec;
  }
}

}  // namespace vmill
}  // namespace remill
