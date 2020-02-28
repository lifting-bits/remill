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

#pragma once

#include <llvm/ADT/Triple.h>
#include <string>

#ifndef REMILL_OS
# if defined(__APPLE__)
#   define REMILL_ON_MACOS 1
#   define REMILL_ON_LINUX 0
#   define REMILL_ON_WINDOWS 0
#   define REMILL_OS "macos"
# elif defined(__linux__)
#   define REMILL_ON_MACOS 0
#   define REMILL_ON_LINUX 1
#   define REMILL_ON_WINDOWS 0
#   define REMILL_OS "linux"
# elif defined(WIN32) || defined(_WIN32) || defined(_WIN64) || defined(_MSC_VER)
#   define REMILL_ON_MACOS 0
#   define REMILL_ON_LINUX 0
#   define REMILL_ON_WINDOWS 1
#   define REMILL_OS "windows"
# else
#   define REMILL_ON_MACOS 0
#   define REMILL_ON_LINUX 0
#   define REMILL_ON_WINDOWS 0
#   error "Cannot infer current OS."
# endif
#endif

namespace remill {

enum OSName : uint32_t {
  kOSInvalid,
  kOSmacOS,
  kOSLinux,
  kOSWindows,
  kOSVxWorks
};

OSName GetOSName(const llvm::Triple &triple);

OSName GetOSName(std::string name_);

std::string GetOSName(OSName name);

}  // namespace remill
