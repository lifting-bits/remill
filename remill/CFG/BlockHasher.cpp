/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "remill/CFG/BlockHasher.h"
#include "remill/CFG/CFG.h"

#include "third_party/murmurhash/MurmurHash2.h"

namespace remill {

BlockHasher::BlockHasher(void)
    : BlockHasher(0) {}

BlockHasher::BlockHasher(uint64_t seed_)
    : seed(seed_) {}

uint64_t BlockHasher::HashBlock(const cfg::Block &block) const {
  std::string data;
  for (const auto &inst : block.instructions()) {
    auto pc = inst.address();
    auto pc_ptr = reinterpret_cast<char *>(&pc);
    auto &bytes = inst.bytes();
    data.insert(data.end(), pc_ptr, pc_ptr + sizeof(pc));
    data.insert(data.end(), bytes.begin(), bytes.end());
  }
  return MurmurHash64A(data.data(), data.size(), seed);
}


}  // namespace remill
