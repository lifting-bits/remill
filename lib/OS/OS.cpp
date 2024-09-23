/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "remill/OS/OS.h"
#include "remill/Arch/Arch.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

namespace remill {

OSName GetOSName(const llvm::Triple &triple) {
  switch (triple.getOS()) {
    case llvm::Triple::OSType::MacOSX: return kOSmacOS;
    case llvm::Triple::OSType::Linux: return kOSLinux;
    case llvm::Triple::OSType::Win32: return kOSWindows;
    case llvm::Triple::OSType::Solaris: return kOSSolaris;
    default: break;
  }

  switch (triple.getObjectFormat()) {
    case llvm::Triple::ObjectFormatType::MachO: return kOSmacOS;
    case llvm::Triple::ObjectFormatType::ELF: return kOSLinux;
    case llvm::Triple::ObjectFormatType::COFF: return kOSWindows;
    default: break;
  }

  return kOSInvalid;
}

OSName GetOSName(std::string_view name) {
  if (name == "macos") {
    return kOSmacOS;
  } else if (name == "linux") {
    return kOSLinux;
  } else if (name == "windows") {
    return kOSWindows;
  } else if (name == "solaris") {
    return kOSSolaris;
  } else {
    return kOSInvalid;
  }
}

std::string_view GetOSName(OSName name) {
  switch (name) {
    case kOSInvalid: return "invalid";
    case kOSmacOS: return "macos";
    case kOSLinux: return "linux";
    case kOSWindows: return "windows";
    case kOSSolaris: return "solaris";
  }
  return "invalid";
}

}  // namespace remill
