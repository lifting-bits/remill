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

#if _WIN64 || __amd64__ || __x86_64__
# define FALLBACK_ARCH_NAME "amd64"
#else
# define FALLBACK_ARCH_NAME "x86"
#endif

namespace mcsema {

Arch::Arch(unsigned addressSize_)
    : address_size(addressSize_) {}

Arch::~Arch(void) {}

const Arch *Arch::Create(ArchName arch_name) {
  switch (arch_name) {
    case kArchX86:
      VLOG(1) << "Using architecture: X86";
      return new x86::Arch(32);

    case kArchAMD64:
      VLOG(1) << "Using architecture: AMD64";
      return new x86::Arch(64);
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
        << "Unrecognized architecture: " << arch_name
        << "; using " << FALLBACK_ARCH_NAME << " instead.";

    std::string fallback_arch = FALLBACK_ARCH_NAME;
    return GetName(fallback_arch);
  }
}

}  // namespace
