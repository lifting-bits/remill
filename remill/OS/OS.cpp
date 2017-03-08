/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/OS/OS.h"

namespace remill {

OSName GetOSName(std::string name) {
  if (name == "macos") {
    return kOSmacOS;
  } else if (name == "linux") {
    return kOSLinux;
  } else {
    return kOSInvalid;
  }
}

std::string GetOSName(OSName name) {
  switch (name) {
    case kOSInvalid:
      return "invalid";
    case kOSmacOS:
      return "macos";
    case kOSLinux:
      return "linux";
  }
}

}  // namespace remill
