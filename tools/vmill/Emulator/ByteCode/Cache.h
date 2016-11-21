/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_BYTECODE_CACHE_H_
#define TOOLS_VMILL_EMULATOR_BYTECODE_CACHE_H_

#include <unordered_map>

#include "tools/vmill/Emulator/ByteCode/Operation.h"
#include "tools/vmill/Util/FileBackedCache.h"

namespace remill {
namespace vmill {

// Cache of the bytecode operations.
class ByteCodeCache final : public FileBackedCache<Operation> {
 public:
  static ByteCodeCache *Create(uint64_t code_version);

 private:
  using FileBackedCache<Operation>::Open;
  using FileBackedCache<Operation>::FileBackedCache;

  ByteCodeCache(void) = delete;
};

using Constant = uint64_t;

// Cache of constants used by the bytecode operations.
class ConstantPool final : public FileBackedCache<Constant> {
 public:
  static ConstantPool *Create(uint64_t code_version);

 private:
  using FileBackedCache<Constant>::Open;
  using FileBackedCache<Constant>::FileBackedCache;

  ConstantPool(void) = delete;
};

// Index of program counters to bytecode operations.
class ByteCodeIndex final {
 public:
  static ByteCodeIndex *Create(ByteCodeCache *cache);

  Operation *TryFind(uint64_t key) const;
  Operation *MustFind(uint64_t key) const;

  void Insert(uint64_t key, Operation *val);

 private:
  ByteCodeIndex(void);

  std::unordered_map<uint64_t, Operation *> index;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_BYTECODE_CACHE_H_
