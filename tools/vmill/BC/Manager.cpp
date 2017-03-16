/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tools/vmill/BC/Manager.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"

DEFINE_bool(enable_linear_decode, false, "Enable linear scanning within "
                                         "the basic block decoder.");

namespace remill {
namespace vmill {
namespace {

static Decoder *CreateDecoder(const Arch *arch) {
  return new Decoder(
      arch, FLAGS_enable_linear_decode ? kDecodeLinear : kDecodeRecursive);
}

}  // namespace

BitcodeManager::BitcodeManager(const Arch *arch)
    : decoder(CreateDecoder(arch)),
      translator(Translator::Create(arch)) {}

}  // namespace vmill
}  // namespace remill
