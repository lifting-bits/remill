/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

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
  }
}

}  // namespace remill
