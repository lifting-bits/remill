/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/X86/Arch.h"

namespace mcsema {

Arch::Arch(unsigned addressSize_)
    : address_size(addressSize_) {}

Arch::~Arch(void) {}

Arch *Arch::Create(std::string arch_name) {
  if (arch_name == "x86") {
    VLOG(1) << "Using architecture: " << arch_name;
    return new x86::Arch(32);

  } else if (arch_name == "amd64") {
    VLOG(1) << "Using architecture: " << arch_name;
    return new x86::Arch(64);

  } else {
    LOG(FATAL) << "Unrecognized architecture: " << arch_name;
    return nullptr;
  }
}

}  // namespace
