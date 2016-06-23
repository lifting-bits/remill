/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/OS/OS.h"

namespace remill {

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

}  // namespace remill
