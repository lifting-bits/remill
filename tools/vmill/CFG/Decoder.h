/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CFG_DECODER_H_
#define TOOLS_VMILL_CFG_DECODER_H_

#include <memory>
#include <unordered_set>

namespace remill {
class Arch;
class BlockHasher;

namespace cfg {
class Module;
}  // namespace cfg
namespace vmill {

using ByteReaderCallback = std::function<bool(uint64_t, uint8_t *)>;

enum DecodeMode {
  kDecodeRecursive,
  kDecodeLinear
};

// Uses an `Arch` to decode instructions, organize them into basic blocks,
// and packages those into a CFG data structure.
class Decoder {
 public:
  static std::unique_ptr<Decoder> Create(const Arch *arch_, DecodeMode mode_);

  // Starting from `start_pc`, read executable bytes out of a memory region
  // using `byte_reader`, and return a CFG.proto module for lifting. The blocks
  // in the module are labelled using IDs produced by `hasher`, which permits
  // higher level systems to support self-modifying code.
  std::unique_ptr<cfg::Module> DecodeToCFG(
      uint64_t start_pc, ByteReaderCallback byte_reader,
      BlockHasher &hasher);

 private:
  Decoder(void) = delete;

  Decoder(const Arch *arch_, DecodeMode mode_);

  const Arch * const arch;
  const DecodeMode mode;

  std::unordered_set<uint64_t> seen_blocks;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CFG_DECODER_H_
