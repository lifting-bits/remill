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

#include "remill/Arch/Name.h"

namespace remill {

ArchName GetArchName(const std::string &arch_name) {
  if (arch_name == "x86") {
    return kArchX86;

  } else if (arch_name == "x86_avx") {
    return kArchX86_AVX;

  } else if (arch_name == "x86_avx512") {
    return kArchX86_AVX512;

  } else if (arch_name == "amd64") {
    return kArchAMD64;

  } else if (arch_name == "amd64_avx") {
    return kArchAMD64_AVX;

  } else if (arch_name == "amd64_avx512") {
    return kArchAMD64_AVX512;

  } else if (arch_name == "aarch64") {
    return kArchAArch64LittleEndian;

  } else if (arch_name == "mips32") {
    return kArchMips32;

  } else if (arch_name == "mips64") {
    return kArchMips64;

  } else {
    return kArchInvalid;
  }
}

std::string GetArchName(ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      return "invalid";
    case kArchX86:
      return "x86";
    case kArchX86_AVX:
      return "x86_avx";
    case kArchX86_AVX512:
      return "x86_avx512";
    case kArchAMD64:
      return "amd64";
    case kArchAMD64_AVX:
      return "amd64_avx";
    case kArchAMD64_AVX512:
      return "amd64_avx512";
    case kArchMips32:
      return "mips32";
    case kArchMips64:
      return "mips64";
    case kArchAArch64LittleEndian:
      return "aarch64";
  }
}

}  // namespace remill
