/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_CFG_BLOCKHASHER_H_
#define REMILL_CFG_BLOCKHASHER_H_


#include <cstdint>
#include <string>

namespace remill {
namespace cfg {
class Block;
}  // namespace cfg

// Used to create a position- and data-dependent hash of a basic block. This
// is part of the block versioning scheme to handle self-modifying code. The
// seed of the hasher should be a hash of some region of executable code.
//
// The reason we want a hash is so that we can identify blocks in a way that
// is representative of their content and location, as opposed to just being
// represented by their program counters.
class BlockHasher {
 public:
  BlockHasher(void);

  explicit BlockHasher(uint64_t seed_);

  uint64_t HashBlock(const cfg::Block &block) const;

  const uint64_t seed;
};

}  // namespace remill

#endif  // REMILL_CFG_BLOCKHASHER_H_
