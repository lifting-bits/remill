/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>

#include <sstream>
#include <string>

#include "remill/OS/FileSystem.h"
#include "tools/vmill/Emulator/ByteCode/Cache.h"

DECLARE_string(workspace);

namespace remill {
namespace vmill {
namespace {

// Get the path to the code version-specific bytecode cache directory.
template <typename T, typename Self>
static Self *GetCacheFile(uint64_t code_version, const char *suffix) {
  std::stringstream ss;
  ss << FLAGS_workspace << "/bytecode.cache/";
  CHECK(TryCreateDirectory(ss.str()))
      << "Could not create bytecode cache directory " << ss.str()
      << ": " << strerror(errno);

  ss << std::hex << code_version << "." << suffix;
  return FileBackedCache<T>::template Open<Self>(ss.str());
}

}  // namespace

ByteCodeCache *ByteCodeCache::Create(uint64_t code_version) {
  return GetCacheFile<Operation, ByteCodeCache>(code_version, "bin");
}

ConstantPool *ConstantPool::Create(uint64_t code_version) {
  return GetCacheFile<Constant, ConstantPool>(code_version, "const");
}

ByteCodeIndex::ByteCodeIndex(void)
    : index() {}

ByteCodeIndex *ByteCodeIndex::Create(ByteCodeCache *cache) {
  auto index = new ByteCodeIndex;
  DLOG(INFO)
        << "Scanning bytecode cache for block entrypoints.";

  Operation *op = cache->begin();
  Operation * const last_op = cache->end();
  Operation *next_op = last_op;
  Operation *last_enter = op;
  uint64_t last_pc = 0;

  // Scan through the operations, finding the program counters associated
  // with each block.
  for (; op < last_op; op = next_op) {
    next_op = op + OpCode::kNumOpSlots[op->op_code];

    // Using greater-than check so that an OpCode::kEnterN can be at a
    // distance of `kUnresolvedVar` from the last one.
    if ((op - last_enter) >= 256) {
      break;
      LOG(FATAL)
          << "Operation block emulating code at PC " << std::hex << last_pc
          << " has too many operations! The maximum number of operations "
          << "per block emulation is 255.";
    }

    // Make sure the bytecode file doesn't contain any invalid operations.
    const auto op_as_uint = static_cast<uint8_t>(op->op_code);
    const auto invalid_as_uint = static_cast<uint8_t>(
        OpCode::kInvalid);

    CHECK(op_as_uint < invalid_as_uint)
        << "Found invalid operation in block emulating PC "
        << std::hex << last_pc;

    if (OpCode::kEnter32 == op->op_code) {
      auto enter_op = reinterpret_cast<Operation::Enter32 *>(op);
      last_pc = enter_op->ProgramCounter();
      last_enter = op;
      index->index[last_pc] = op;

    } else if (OpCode::kEnter64 == op->op_code) {
      auto enter_op = reinterpret_cast<Operation::Enter64 *>(op);
      last_pc = enter_op->ProgramCounter();
      last_enter = op;
      index->index[last_pc] = op;

    } else if (OpCode::kJump == op->op_code ||
               OpCode::kJumpFarForward == op->op_code) {
      CHECK(0 < op->_0)
          << "Infinite loop operation in block emulating PC "
          << std::hex << last_pc;

    } else if (OpCode::kNumBytesWritten[op->op_code] == 16) {
      CHECK(next_op < last_op ||
            next_op->op_code != OpCode::kAllocOverflowData)
          << "Operating writing 16 bytes into the data section requires "
          << "must be following by a AllocOverflowData operation.";
    }
  }

  DLOG(INFO)
      << "Loaded " << index->index.size() << " bytecode blocks from "
      << "the bytecode cache.";
  return index;
}

Operation *ByteCodeIndex::TryFind(uint64_t key) const {
  auto val_it = index.find(key);
  if (index.end() == val_it) {
    return nullptr;
  } else {
    return val_it->second;
  }
}

Operation *ByteCodeIndex::MustFind(uint64_t key) const {
  if (auto op = TryFind(key)) {
    return op;
  } else {
    LOG(FATAL)
        << "Unable to find bytecode operation associated with PC "
        << std::hex << key;
    return nullptr;
  }
}

void ByteCodeIndex::Insert(uint64_t key, Operation *val) {
  index[key] = val;
}

}  // namespace vmill
}  // namespace remill
