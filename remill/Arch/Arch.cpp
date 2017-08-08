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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <memory>
#include <unordered_map>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/OS/OS.h"

DEFINE_string(arch, "",
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64, "
              "mips32, mips64");

DECLARE_string(os);

namespace remill {
namespace {

static unsigned AddressSize(ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      LOG(FATAL) << "Cannot get address size for invalid arch.";
      return 0;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
    case kArchMips32:
      return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchMips64:
    case kArchAArch64LittleEndian:
      return 64;
  }
  return 0;
}

// Used for static storage duration caches of `Arch` specializations. The
// `std::unique_ptr` makes sure that the `Arch` objects are freed on `exit`
// from the program.
using ArchPtr = std::unique_ptr<const Arch>;
using ArchCache = std::unordered_map<uint32_t, ArchPtr>;

}  // namespace

Arch::Arch(OSName os_name_, ArchName arch_name_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(AddressSize(arch_name_)) {}

Arch::~Arch(void) {}

const Arch *Arch::Get(OSName os_name_, ArchName arch_name_) {
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchAArch64LittleEndian: {
      static ArchCache gArchAArch64LE;
      auto &arch = gArchAArch64LE[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AArch64, feature set: Little Endian";
        arch = ArchPtr(GetAArch64(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86: {
      static ArchCache gArchX86;
      auto &arch = gArchX86[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchMips32: {
      static ArchCache gArchMips;
      auto &arch = gArchMips[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: 32-bit MIPS";
        arch = ArchPtr(GetMips(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchMips64: {
      static ArchCache gArchMips64;
      auto &arch = gArchMips64[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: 64-bit MIPS";
        arch = ArchPtr(GetMips(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86_AVX: {
      static ArchCache gArchX86_AVX;
      auto &arch = gArchX86_AVX[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86, feature set: AVX";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86_AVX512: {
      static ArchCache gArchX86_AVX512;
      auto &arch = gArchX86_AVX512[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64: {
      static ArchCache gArchAMD64;
      auto &arch = gArchAMD64[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64_AVX: {
      static ArchCache gArchAMD64_AVX;
      auto &arch = gArchAMD64_AVX[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64_AVX512: {
      static ArchCache gArchAMD64_AVX512;
      auto &arch = gArchAMD64_AVX512[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }
  }
  return nullptr;
}

const Arch *Arch::GetMips(OSName, ArchName) {
  return nullptr;
}

const Arch *GetHostArch(void) {
  static const Arch *gHostArch = nullptr;
  if (!gHostArch) {
    gHostArch = Arch::Get(GetOSName(REMILL_OS), GetArchName(REMILL_ARCH));
  }
  return gHostArch;
}

const Arch *GetTargetArch(void) {
  static const Arch *gTargetArch = nullptr;
  if (!gTargetArch) {
    gTargetArch = Arch::Get(GetOSName(FLAGS_os), GetArchName(FLAGS_arch));
  }
  return gTargetArch;
}

bool Arch::IsX86(void) const {
  switch (arch_name) {
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      return true;
    default:
      return false;
  }
}

bool Arch::IsAMD64(void) const {
  switch (arch_name) {
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      return true;
    default:
      return false;
  }
}

bool Arch::IsAArch64(void) const {
  return remill::kArchAArch64LittleEndian == arch_name;
}

}  // namespace remill
