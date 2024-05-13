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

#ifndef REMILL_ARCH
#  if defined(__x86_64__)
#    define REMILL_ARCH "amd64_avx"
#    define REMILL_ON_AMD64 1
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_AARCH32 0
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 0
#  elif defined(__i386__) || defined(_M_X86)
#    define REMILL_ARCH "x86"
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 1
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_AARCH32 0
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 0
#  elif defined(__aarch64__)
#    define REMILL_ARCH "aarch64"
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 1
#    define REMILL_ON_AARCH32 0
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 0
#  elif defined(__arm__)
#    define REMILL_ARCH "aarch32"
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_AARCH32 1
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 0
#  elif defined(__sparc__) || defined(__sparc) || defined(__sparc_v8__) || \
      defined(__sparc_v9__) || defined(__sparcv8) || defined(__sparcv9)
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_AARCH32 0
#    define REMILL_ON_PPC 0
#    if (defined(__LP64__) && __LP64__) || (defined(_LP64) && _LP64)
#      define REMILL_ARCH "sparc64"
#      define REMILL_ON_SPARC64 1
#      define REMILL_ON_SPARC32 0
#    else
#      define REMILL_ARCH "sparc32"
#      define REMILL_ON_SPARC64 0
#      define REMILL_ON_SPARC32 1
#    endif
#  elif defined(__PPC__)
#    define REMILL_ARCH "ppc"
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_AARCH32 0
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 1
#  else
#    error "Cannot infer current architecture."
#    define REMILL_ARCH "invalid"
#    define REMILL_ON_AMD64 0
#    define REMILL_ON_X86 0
#    define REMILL_ON_AARCH64 0
#    define REMILL_ON_SPARC64 0
#    define REMILL_ON_SPARC32 0
#    define REMILL_ON_PPC 0
#  endif
#endif

#include <string_view>

namespace llvm {
class Triple;
}  // namespace llvm
namespace remill {

enum ArchName : uint32_t {
  kArchInvalid,

  kArchX86,
  kArchX86_AVX,
  kArchX86_AVX512,
  kArchX86_SLEIGH,

  kArchAMD64,
  kArchAMD64_AVX,
  kArchAMD64_AVX512,
  kArchAMD64_SLEIGH,

  kArchAArch32LittleEndian,
  kArchAArch64LittleEndian,
  kArchAArch64LittleEndian_SLEIGH,

  kArchSparc32,
  kArchSparc64,
  kArchSparc32_SLEIGH,

  kArchThumb2LittleEndian,

  kArchPPC,
  kArchMIPS,
};

ArchName GetArchName(const llvm::Triple &triple);

// Convert the string name of an architecture into a canonical form.
ArchName GetArchName(std::string_view arch_name);

std::string_view GetArchName(ArchName);

}  // namespace remill
