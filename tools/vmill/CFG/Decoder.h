/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CFG_DECODER_H_
#define TOOLS_VMILL_CFG_DECODER_H_

#include <unordered_set>

#include "tools/vmill/BC/Callback.h"

namespace remill {
class Arch;
namespace vmill {

// Uses an `Arch` to decode instructions, organize them into basic blocks,
// and packages those into a CFG data structure.
class Decoder {
 public:
  explicit Decoder(const Arch *arch_);

  void DecodeToCFG(uint64_t start_pc, ByteReaderCallback byte_reader,
                   CFGCallback with_cfg);

 private:
  const Arch * const arch;

  std::unordered_set<uint64_t> seen_blocks;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CFG_DECODER_H_
