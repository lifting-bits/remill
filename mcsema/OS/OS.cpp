/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "mcsema/OS/OS.h"

namespace mcsema {

OSName GetOSName(std::string name) {
  if (name == "mac") {
    return kOSMacOSX;
  } else if (name == "linux") {
    return kOSLinux;
  } else {
    LOG(FATAL) << "Unsupported operating system: " << name;
    return kOSInvalid;
  }
}

}  // namespace mcsema
