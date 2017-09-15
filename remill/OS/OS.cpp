/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glog/logging.h>
#include <gflags/gflags.h>

#include "remill/OS/OS.h"

DEFINE_string(os, "", "Operating system name of the code being translated. "
                      "Valid OSes: linux, macos, windows.");

namespace remill {

OSName GetOSName(std::string name) {
  if (name == "macos") {
    return kOSmacOS;
  } else if (name == "linux") {
    return kOSLinux;
  } else if (name == "windows") {
    return kOSWindows;
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
    case kOSWindows:
      return "windows";
  }
  return "invalid";
}

}  // namespace remill
