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

#ifndef REMILL_OS_OS_H_
#define REMILL_OS_OS_H_

#include <string>

namespace remill {

enum OSName : uint32_t {
  kOSInvalid,
  kOSmacOS,
  kOSLinux,
  kOSWindows
};

OSName GetOSName(std::string name_);

std::string GetOSName(OSName name);

}  // namespace remill

#endif  // REMILL_OS_OS_H_
