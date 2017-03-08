/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

namespace remill {
namespace {

static unsigned AddressSize(ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      LOG(FATAL)
          << "Cannot get address size for invalid arch.";
      return 0;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
      return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
      return 64;
  }
}

}  // namespace

Arch::Arch(OSName os_name_, ArchName arch_name_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(AddressSize(arch_name_)) {}

Arch::~Arch(void) {}

const Arch *Arch::Get(OSName os_name_, ArchName arch_name_) {
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchX86:
      DLOG(INFO) << "Using architecture: X86";
      return GetX86(os_name_, arch_name_);

    case kArchX86_AVX:
      DLOG(INFO) << "Using architecture: X86, feature set: AVX";
      return GetX86(os_name_, arch_name_);

    case kArchX86_AVX512:
      DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
      return GetX86(os_name_, arch_name_);

    case kArchAMD64:
      DLOG(INFO) << "Using architecture: AMD64";
      return GetX86(os_name_, arch_name_);

    case kArchAMD64_AVX:
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
      return GetX86(os_name_, arch_name_);

    case kArchAMD64_AVX512:
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
      return GetX86(os_name_, arch_name_);
  }
  return nullptr;
}

}  // namespace remill
