/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/Arch/Arch.h"

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

    case kArchAMD64:
      DLOG(INFO) << "Using architecture: AMD64";
      return CreateX86(os_name_, arch_name_, 64);
  }
  return nullptr;
}

ArchName Arch::GetName(const std::string &arch_name) {
  if (arch_name == "x86" ||
      arch_name == "x86_32" ||
      arch_name == "x86-32") {
    return kArchX86;

  } else if (arch_name == "amd64" ||
             arch_name == "x86_64" ||
             arch_name == "x86-64" ||
             arch_name == "x64" ||
             arch_name == "intel64" ||
             arch_name == "emt64") {
    return kArchAMD64;

  } else {
    LOG(ERROR)
        << "Unrecognized architecture: " << arch_name << ".";
    return kArchInvalid;
  }
}

}  // namespace
