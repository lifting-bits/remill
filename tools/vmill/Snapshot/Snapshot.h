/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_
#define TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_

#include <cstdint>
#include <string>

namespace remill {

enum ArchName : uint32_t;
enum OSName : uint32_t;

namespace vmill {

struct SnapshotFile;

// Program snapshot loaded from disk.
class Snapshot {
 public:
  ~Snapshot(void);

  // Open a snapshot from a file.
  static Snapshot *Open(const std::string &path);

  ArchName GetArch(void) const;

  OSName GetOS(void) const;

  // Check to see if there is any corruption in the recorded page info
  // entries in the snapshot file.
  void ValidatePageInfo(uint64_t max_addr) const;

  const std::string path;
  const SnapshotFile * const file;
  const int fd;

 private:

  // Returns the size of the `SnapshotFile` struct and the arch-specific
  // `State` struct that make up the header of the snapshot file.
  uint64_t HeaderSize(void) const;

  Snapshot(void) = delete;
  Snapshot(const std::string &path_, const SnapshotFile *file_, int fd_);
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_
