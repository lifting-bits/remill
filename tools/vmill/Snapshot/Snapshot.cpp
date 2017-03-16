/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "remill/OS/FileSystem.h"

#include "tools/vmill/Arch/X86/Snapshot.h"
#include "tools/vmill/Snapshot/File.h"
#include "tools/vmill/Snapshot/Snapshot.h"

namespace remill {
namespace vmill {
namespace {

static size_t BeginOfMachineState(const Snapshot *snapshot) {
  size_t end = sizeof(SnapshotFile);
  for (auto &map : snapshot->file->pages) {
    auto end_in_file = map.offset_in_file +
        (map.limit_address - map.base_address);
    end = std::max(end, end_in_file);
  }
  return end;
}

}  // namespace

ArchStateSnapshot::ArchStateSnapshot(const ArchState *state_, size_t size_)
    : state(state_),
      size(size_) {}

ArchStateSnapshot::~ArchStateSnapshot(void) {
  munmap(const_cast<ArchState *>(state), size);
}

Snapshot::~Snapshot(void) {
  munmap(const_cast<SnapshotFile *>(file), sizeof(SnapshotFile));
  close(fd);
}

Snapshot::Snapshot(const std::string &path_, const SnapshotFile *file_, int fd_)
    : path(path_),
      file(file_),
      fd(fd_) {}

std::unique_ptr<Snapshot> Snapshot::Open(const std::string &path) {
  const auto snapshot_fd = open(path.c_str(), O_RDONLY);
  CHECK(-1 != snapshot_fd)
      << "Unable to open snapshot file " << path
      << ": " << strerror(errno);

  auto snapshot_file_addr = mmap(nullptr, sizeof(SnapshotFile),
                                 PROT_READ,
                                 MAP_FILE | MAP_PRIVATE,
                                 snapshot_fd, 0);

  CHECK(snapshot_file_addr)
      << "Unable to mmap the snapshot file " << path
      << ": " << strerror(errno);

  // Load in and validate the snapshot file header.
  auto snapshot = reinterpret_cast<SnapshotFile *>(snapshot_file_addr);
  CHECK(!memcmp(kMagic, snapshot->magic, sizeof(kMagic)))
      << "Magic bytes of snapshot don't match expected values; "
      << "expected " << kMagic << " but got " << snapshot->magic;

  return std::unique_ptr<Snapshot>(new Snapshot(path, snapshot, snapshot_fd));
}

ArchName Snapshot::GetArch(void) const {
  return file->arch_name;
}

OSName Snapshot::GetOS(void) const {
  return file->os_name;
}

std::unique_ptr<ArchStateSnapshot> Snapshot::GetState(void) const {
  auto state_offset = BeginOfMachineState(this);
  auto file_size = FileSize(path, fd);

  CHECK(!(file_size % 4096))
      << "Snapshot file " << path << " size must be a multiple of 4096 bytes.";

  auto state_size = file_size - state_offset;
  CHECK(!(state_size % 4096))
      << "State size in snapshot file " << path
      << " must be a multiple of 4096 bytes.";

  auto state_mmap = mmap(nullptr, state_size, PROT_READ,
                         MAP_PRIVATE | MAP_FILE, fd,
                         state_offset);
  CHECK(MAP_FAILED != state_mmap)
      << "Could not mmap state structure from snapshot "
      << path << ": " << strerror(errno);

  auto state = reinterpret_cast<const ArchState *>(state_mmap);
  return std::unique_ptr<ArchStateSnapshot>(
      new ArchStateSnapshot(state, state_size));
}

// Check to see if there is any corruption in the recorded page info
// entries in the snapshot file.
void Snapshot::ValidatePageInfo(uint64_t max_address) const {
  const auto perm_min = static_cast<uint64_t>(PagePerms::kInvalid);
  const auto perm_max = static_cast<uint64_t>(PagePerms::kReadWriteExec);
  auto seen_last = false;
  auto next_address_min = 4096ULL;
  auto memory_size = 0ULL;
  auto header_size = sizeof(SnapshotFile);
  auto next_offset = header_size;

  for (const auto &info : file->pages) {

    // Check for corruption of the page permissions.
    const auto perm = static_cast<uint64_t>(info.perms);
    CHECK(perm_min <= perm && perm <= perm_max)
        << "Found PageInfo entry with invalid permission in " << path;

    // Check that an empty looking page info entry is actually empty.
    if (PagePerms::kInvalid == info.perms) {
      CHECK(!info.base_address && !info.limit_address && !info.offset_in_file)
          << "Found non-empty PageInfo entry with invalid permissions "
          << "in " << path;
      seen_last = true;
      continue;
    }

    CHECK(!seen_last)
        << "Found non-empty PageInfo entry after an empty PageInfo entry "
        << "in " << path;

    CHECK(info.base_address >= next_address_min)
        << "Found out of order PageInfo entry in " << path;

    next_address_min = info.limit_address;

    CHECK(info.base_address < info.limit_address)
        << "Found PageInfo describing empty or negative sized page range "
        << "in " << path;

    CHECK(info.limit_address <= max_address)
        << "Found PageInfo entry whose limit address " << info.limit_address
        << " exceeds the maximum allowed address " << max_address << " in "
        << path;

    auto range_size = info.limit_address - info.base_address;

    CHECK(0 == (range_size % 4096))
        << "Found PageInfo entry whose memory is not a multiple of the "
        << "page size in " << path;

    CHECK(info.offset_in_file == next_offset)
        << "Memory for PageInfo entry is not at the right place in " << path;

    DLOG(INFO)
        << "Found memory for range [" << std::hex << info.base_address << ", "
        << std::hex << info.limit_address << ") at file offset "
        << std::dec << info.offset_in_file << " with " << range_size
        << " bytes";

    memory_size += range_size;
    next_offset += range_size;
  }

  CHECK(0 < memory_size)
      << "No memory saved in snapshot " << path;

  const auto file_size = FileSize(path, fd);
  CHECK(file_size < max_address)
      << "Snapshot file " << path << " is somehow too big.";

  CHECK(file_size == next_offset)
      << "Snapshot " << path << " is not the right size.";

  CHECK(file_size == (header_size + memory_size))
      << "Snapshot " << path << " is not the right size. Header size is "
      << header_size << ", memory size is " << memory_size
      << ", and file size is " << file_size;
}

}  // namespace vmill
}  // namespace remill
