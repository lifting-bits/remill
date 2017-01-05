/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

namespace remill {

Arch::Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(address_size_) {}

Arch::~Arch(void) {}

const Arch *Arch::Create(OSName os_name_, ArchName arch_name_) {
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Cannot create arch for unrecognized OS.";
      return nullptr;

    case kArchX86:
      DLOG(INFO) << "Using architecture: X86";
      return CreateX86(os_name_, arch_name_, 32);

    case kArchX86_AVX:
      DLOG(INFO) << "Using architecture: X86, feature set: AVX";
      return CreateX86(os_name_, arch_name_, 32);

    case kArchX86_AVX512:
      DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
      return CreateX86(os_name_, arch_name_, 32);

    case kArchAMD64:
      DLOG(INFO) << "Using architecture: AMD64";
      return CreateX86(os_name_, arch_name_, 64);

    case kArchAMD64_AVX:
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
      return CreateX86(os_name_, arch_name_, 64);

    case kArchAMD64_AVX512:
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
      return CreateX86(os_name_, arch_name_, 64);
  }
  return nullptr;
}

}  // namespace remill
