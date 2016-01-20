/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/X86/Arch.h"

#ifndef _WIN64
# define _WIN64 0
#endif

#ifndef __amd64__
# define __amd64__ 0
#endif

#ifndef __x86_64__
# define __x86_64__ 0
#endif

namespace mcsema {

Arch::Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(address_size_) {}

Arch::~Arch(void) {}

const Arch *Arch::Create(OSName os_name, ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      LOG(FATAL) << "Cannot create arch for unrecognized OS.";
      return nullptr;
    case kArchX86:
      VLOG(1) << "Using architecture: X86";
      return new x86::Arch(os_name, arch_name, 32);

    case kArchAMD64:
      VLOG(1) << "Using architecture: AMD64";
      return new x86::Arch(os_name, arch_name, 64);
  }
  return nullptr;
}

ArchName Arch::GetName(const std::string &arch_name) {
  if (arch_name == "x86") {
    return kArchX86;
  } else if (arch_name == "amd64") {
    return kArchAMD64;
  } else {
    LOG(ERROR)
        << "Unrecognized architecture: " << arch_name;
    return kArchInvalid;
  }
}

}  // namespace
