/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_
#define TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_

#include <cstdint>
#include <memory>
#include <string>

struct ArchState;

namespace remill {

enum ArchName : uint32_t;
enum OSName : uint32_t;

namespace vmill {

class Snapshot;
struct SnapshotFile;

// A snapshot of the arch state from a snapshot file.
class ArchStateSnapshot {
 public:
  ~ArchStateSnapshot(void);

  const ArchState * const state;
  const size_t size;

 private:
  friend class Snapshot;

  explicit ArchStateSnapshot(const ArchState *state_, size_t size_);
  ArchStateSnapshot(void) = delete;
};

// Program snapshot loaded from disk.
class Snapshot {
 public:
  ~Snapshot(void);

  // Open a snapshot from a file.
  static std::unique_ptr<Snapshot> Open(const std::string &path);

  ArchName GetArch(void) const;

  OSName GetOS(void) const;

  std::unique_ptr<ArchStateSnapshot> GetState(void) const;

  const std::string path;
  const SnapshotFile * const file;
  const int fd;

 private:
  Snapshot(void) = delete;
  Snapshot(const std::string &path_, const SnapshotFile *file_, int fd_);

  // Check to see if there is any corruption in the recorded page info
  // entries in the snapshot file.
  void ValidatePageInfo(void) const;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_SNAPSHOT_SNAPSHOT_H_
