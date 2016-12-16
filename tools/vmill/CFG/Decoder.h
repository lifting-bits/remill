/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CFG_DECODER_H_
#define TOOLS_VMILL_CFG_DECODER_H_

#include "tools/vmill/BC/Callback.h"

namespace remill {
class Arch;
namespace vmill {

class Translator;

class InstructionDecoder {
 public:
  explicit InstructionDecoder(const Arch *arch_, const Translator *translator_);

  void DecodeToCFG(uint64_t start_pc, ByteReaderCallback byte_reader,
                   CFGCallback with_cfg) const;

 private:
  const Arch * const arch;
  const Translator * const translator;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CFG_DECODER_H_
