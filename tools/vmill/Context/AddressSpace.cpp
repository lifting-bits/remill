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

static inline uint64_t AlignDownToPage(uint64_t addr) {
  return addr & kPageMask;
}

static inline uint64_t RoundUpToPage(uint64_t size) {
  return (size + kPageShift) & kPageMask;
}

}  // namespace

// Backing store for some region of mapped memory within an address space.
class MemoryMap : protected std::enable_shared_from_this<MemoryMap>,
                  protected AddressRange {
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
  MemoryMapPtr CloneOrKeepRange(uint64_t cut_base, uint64_t cut_limit);

  typedef bool (MemoryMap::*ReadFuncType)(uint64_t, uint8_t *);
  typedef bool (MemoryMap::*WriteFuncType)(uint64_t, uint8_t );

  // Read bytes from a memory range.
  [[gnu::always_inline, gnu::gnu_inline]]
  inline bool Read(uint64_t addr, uint8_t *val) {
    return this->*do_read(addr, val);
  }

  // Write bytes to a memory range.
  [[gnu::always_inline, gnu::gnu_inline, gnu::naked]]
  inline bool Write(uint64_t addr, uint8_t val) {
    return this->*do_write(addr, val);
  }

  // Read a byte as an executable byte. This is used for instruction decoding.
  bool ReadExecutable(uint64_t addr, uint8_t *val, CodeVersion *version_out);

 private:
  MemoryMap(void) = delete;
  MemoryMap(const MemoryMap &) = delete;

  bool ReadZero(uint64_t addr, uint8_t *val);
  bool ReadFromParent(uint64_t addr, uint8_t *val);
  bool ReadFromMem(uint64_t addr, uint8_t *val);
  bool ReadFail(uint64_t addr, uint8_t *val);

  bool WriteInit(uint64_t addr, uint8_t val);
  bool WriteCopyParent(uint64_t addr, uint8_t val);
  bool WriteToMem(uint64_t addr, uint8_t val);
  bool WriteFail(uint64_t addr, uint8_t val);

  // Get a shared pointer to this memory map or the parent memory map.
  MemoryMapPtr Link(void);

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
    delete base;
  }
}

MemoryMap::MemoryMap(const AddressRange &info)
    : AddressRange(info),
      parent(nullptr),
      base(nullptr),
      do_read(CanRead() ? ReadZero : ReadFail),
      do_write(CanWrite() ? WriteInit : WriteFail),
      seen_write_since_exec(false),
      seen_exec(false),
      version(0) {}

MemoryMapPtr MemoryMap::Link(void) {
  if (parent) {
    return parent;
  } else {
    return shared_from_this();
  }
}

bool MemoryMap::ReadZero(uint64_t, uint8_t *val) {
  *val = 0;
  return true;
}

bool MemoryMap::ReadFromParent(uint64_t addr, uint8_t *val) {
  return parent->*do_read(addr, val);
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
  do_write = WriteToMem;
  do_read = ReadFromMem;
  return WriteToMem(addr, val);
}

bool MemoryMap::WriteCopyParent(uint64_t addr, uint8_t val) {
  base = new uint8_t[Size()];
  memcpy(base, parent->base, Size());
  parent.reset();
  do_write = WriteToMem;
  do_read = ReadFromMem;
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

  if (seen_write_since_exec && seen_exec) {
    version = MurmurHash64A(
        base,
        Size(),
        (base_address % kPageSize) * (limit_address % kPageSize));

    seen_write_since_exec = false;
  }

  seen_exec = true;
  *version_out = version;
  return Read(addr, val);
}

MemoryMapPtr MemoryMap::Clone(void) {

  // This is a page with actual data in it. Create a new parent of this page
  // and steal this page's memory, putting it into the new parent, making this
  // page a copy-on-write version of the parent.
  if (base) {
    auto reparent = new MemoryMap(*this);
    reparent->base = base;
    reparent->version = version;
    reparent->do_read = do_read;
    reparent->do_write = do_write;
    reparent->seen_exec = seen_exec;
    reparent->seen_write_since_exec = seen_write_since_exec;

    base = nullptr;
    parent = reparent->Link();
    do_read = CanRead() ? ReadFromParent : ReadFail;
    do_write = CanWrite() ? WriteCopyParent : WriteFail;
  }

  // This is a copy-on-write page that passes through from its parent.
  if (parent) {
    auto copy = new MemoryMap(*this);
    copy->parent = parent;
    copy->do_read = do_read;
    copy->do_write = do_write;
    copy->version = version;
    copy->seen_exec = seen_exec;
    copy->seen_write_since_exec = seen_write_since_exec;
    return copy->Link();

  // This is an empty page that isn't yet initialized; cloning it should just
  // produce a new such empty page.
  } else {
    return (new MemoryMap(*this))->Link();
  }
}

MemoryMapPtr MemoryMap::CloneOrKeepRange(
    uint64_t cut_base, uint64_t cut_limit) {

  // The sub-range and this range are the same; return this range.
  if (cut_base == base_address && cut_limit == limit_address) {
    return Link();

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
    auto ret = new MemoryMap(*this);
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
    return ret->Link();

  // This range is empty, so return a new empty range.
  } else {
    auto ret = new MemoryMap(*this);
    ret->base_address = cut_base;
    ret->limit_address = cut_limit;
    return ret->Link();
  }
}

void MemoryMap::SetCanRead(bool new_can_read) {
  if (can_read == new_can_read) {
    return;
  }

  // Going from readable -> not readable
  if (!new_can_read) {
    do_read = ReadFail;

  // Copy-on-write, going from not readable -> readable
  } else if (parent) {
    do_read = ReadFromParent;

  // Memory backed, going from not readable -> readable
  } else if (base) {
    do_read = ReadFromMem;

  // Uninitialized, going from not readable -> readable
  } else {
    do_read = ReadZero;
  }

  can_read = new_can_read;
}

void MemoryMap::SetCanWrite(bool new_can_write) {
  if (can_write == new_can_write) {
    return;
  }

  // Going from writable -> not writable
  if (!new_can_write) {
    do_read = WriteFail;

  // Copy-on-write, going from not writable -> writable
  } else if (parent) {
    do_read = WriteCopyParent;

  // Memory backed, going from not readable -> readable
  } else if (base) {
    do_read = WriteToMem;

  // Uninitialized, going from not readable -> readable
  } else {
    do_read = WriteInit;
  }

  can_write = new_can_write;
}

// Note: Intentionally doesn't update `seen_write_since_exec` or `seen_exec`.
void MemoryMap::SetCanExecute(bool new_can_exec) {
  can_exec = new_can_exec;
}

AddressSpace::AddressSpace(void)
    : invalid_map(new MemoryMap(kZeroRange)),
      is_dead(false) {}

AddressSpace::AddressSpace(const AddressSpace &parent)
    : AddressSpace() {
  is_dead = parent.is_dead;

  if (!is_dead) {
    for (const auto &range : parent.ranges) {
      ranges.push_back(range->Clone());
    }
    CreateIndex();
  }
}

// Clear out the contents of this address space.
void AddressSpace::Kill(void) {
  ranges.clear();
  page_to_range.clear();
  range_base_to_index.clear();
  range_limit_to_index.clear();
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

  for (auto &map : ranges) {

    // No overlap between `map` and the range to remove.
    if (map->limit_address <= base || map->base_address >= limit) {
      new_ranges.push_back(map);

    // `map` is fully contained in the range to remove.
    } else if (map->base_address >= base && map->limit_address <= limit) {
      continue;

    // The range to remove is fully contained in `map`.
    } else if (map->base_address < base && map->limit_address > limit) {
      new_ranges.push_back(map->CloneOrKeepRange(map->base_address, base));
      new_ranges.push_back(map->CloneOrKeepRange(limit, map->limit_address));

    // The range to remove contains either a prefix or suffix of `map`.
    } else {
      new_ranges.push_back(map->CloneOrKeepRange(base, limit));
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

  for (auto &map : ranges) {
    if (map->limit_address <= base || map->base_address >= limit) {
      continue;
    } else {
      new_ranges.push_back(map->CloneOrKeepRange(base, limit));
    }
  }

  return new_ranges;
}

}  // namespace

void AddressSpace::SetPermissions(uint64_t base_, size_t size, bool can_read,
                                  bool can_write, bool can_exec) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  if (is_dead) {
    LOG(ERROR)
        << "Trying to set permissions on range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }
  auto old_ranges = RemoveRange(ranges, base, limit);
  auto new_ranges = KeepRange(ranges, base, limit);

  CheckRanges(old_ranges, true);
  CheckRanges(new_ranges, true);

  for (auto &range : new_ranges) {
    range->SetCanRead(can_read);
    range->SetCanWrite(can_write);
    range->SetCanExecute(can_exec);
  }

  ranges.swap(old_ranges);
  ranges.insert(ranges.end(), new_ranges.begin(), new_ranges.end());

  CheckRanges(ranges, false);
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

  auto old_ranges = RemoveRange(ranges, base, limit);
  CheckRanges(old_ranges, true);
  AddressRange new_range = {base, limit, true, true, false};
  ranges.swap(old_ranges);
  ranges.push_back((new MemoryMap(new_range))->Link());
  CheckRanges(ranges, false);
  CreateIndex();
}

void AddressSpace::RemoveMap(uint64_t base_, size_t size) {
  auto base = AlignDownToPage(base_);
  auto limit = base + RoundUpToPage(size);

  if (is_dead) {
    LOG(ERROR)
        << "Trying to unmap range ["
        << std::hex << base << ", " << std::hex << limit
        << ") in destroyed address space.";
    return;
  }

  ranges = RemoveRange(ranges, base, limit);
  CheckRanges(ranges, true);
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

  auto lower_bound = range_base_to_index.lower_bound(find);
  auto upper_bound = range_limit_to_index.upper_bound(find);

  if (lower_bound != range_base_to_index.end()) {
    *glb = lower_bound->first;
  }

  if (upper_bound != range_limit_to_index.end()) {
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
  page_to_range.clear();
  range_base_to_index.clear();
  range_limit_to_index.clear();

  unsigned i = 0;
  for (const auto &range : ranges) {
    range_base_to_index[range->base_address] = i;
    range_limit_to_index[range->limit_address] = i;
    ++i;
  }
}

MemoryMapPtr &AddressSpace::FindRange(uint64_t addr) {
  auto page_addr = AlignDownToPage(addr);
  auto &range = page_to_range[page_addr];
  if (is_dead) {
    LOG(ERROR)
        << "Trying to find memory map associated with address "
        << std::hex << addr << " in destroyed address space.";
    range = invalid_map->Link();  // Backup invalid map.
  }

  if (range) {
    return range;
  }

  // See if locality is a good guess to find this page range based on a
  // previous one.
  auto prev_range_it = page_to_range.find(page_addr - kPageSize);
  if (prev_range_it != page_to_range.end() &&
      addr < prev_range_it->second->limit_address) {
    range = *prev_range_it;
    return range;
  }

  range = invalid_map->Link();  // Backup invalid map.

  auto lower_bound = range_base_to_index.lower_bound(addr);
  if (lower_bound != range_base_to_index.end()) {
    auto &lb_range = ranges[lower_bound->second];
    if (lb_range->base_address <= addr && addr < lb_range->limit_address) {
      range = lb_range;
    }
  }

  return range;
}

}  // namespace vmill
}  // namespace remill
