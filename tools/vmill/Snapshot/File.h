/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_SNAPSHOT_FILE_H_
#define TOOLS_VMILL_SNAPSHOT_FILE_H_

#include "remill/Arch/Name.h"

#include "remill/OS/OS.h"

namespace remill {
namespace vmill {

class PagePerms {
 public:
  enum Set : uint64_t {
    kInvalid,
    kReadOnly,
    kWriteOnly,
    kReadWrite,
    kReadExec,
    kReadWriteExec
  };

  inline static bool CanRead(Set perms) {
    return kInvalid != perms && kWriteOnly != perms;
  }

  inline static bool CanWrite(Set perms) {
    return kWriteOnly == perms || kReadWrite == perms ||
           kReadWriteExec == perms;
  }

  inline static bool CanExec(Set perms) {
    return kReadExec == perms || kReadWriteExec == perms;
  }

 private:
  PagePerms(void) = delete;
};

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"

struct PageInfo {
  uint64_t base_address;
  uint64_t limit_address;
  uint64_t offset_in_file;
  PagePerms::Set perms;

  inline uint64_t Size(void) const {
    return limit_address - base_address;
  }

  inline bool CanRead(void) const {
    return PagePerms::CanRead(perms);
  }

  inline bool CanWrite(void) const {
    return PagePerms::CanWrite(perms);
  }

  inline bool CanExec(void) const {
    return PagePerms::CanExec(perms);
  }
};

static_assert(32 == sizeof(PageInfo), "Invalid packing of `PageInfo`.");


static constexpr char kMagic[8] = {'V', 'M', 'I', 'L', 'L', '\0', '\0', '\0'};

// Snapshot of a program's memory state.
//
// Note:  Snapshot files can only represent programs with a single thread. If
//        the program has more than one thread, then a snapshot must be taken
//        in advance of the first thread creation.
//
// Note:  The snapshot file format is the same for both 32- and 64-bit
//        applications. The main difference is really the interpretation
//        of the embedded `State` structure.
struct SnapshotFile {
  enum {
    kMaxNumPageInfos = 255
  };

  const char magic[8] = {kMagic[0], kMagic[1], kMagic[2], kMagic[3],
                         kMagic[4], kMagic[5], kMagic[6], kMagic[7]};

  // Info about the program represented by the snapshot. This is used to
  // decide how to emulate the program.
  ArchName arch_name;
  OSName os_name;

  // Get these because something like glibc might cache them, so when
  // executing and emulating syscalls we want to be sort of accurate.
  pid_t process_id;
  pid_t thread_id;

  uint64_t _padding0;

  PageInfo pages[kMaxNumPageInfos];
};

static_assert(sizeof(SnapshotFile) == (4096 * 2),
              "SnapshotFile header is not a multiple of the page size.");

#pragma clang diagnostic pop

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_SNAPSHOT_FILE_H_
