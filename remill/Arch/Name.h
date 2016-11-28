/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_NAME_H_
#define REMILL_ARCH_NAME_H_

#include <string>

namespace remill {

enum ArchName : uint32_t {
  kArchInvalid,
  kArchX86,
  kArchX86_AVX,
  kArchX86_AVX512,
  kArchAMD64,
  kArchAMD64_AVX,
  kArchAMD64_AVX512
};

// Convert the string name of an architecture into a canonical form.
ArchName GetArchName(const std::string &arch_name);

}  // namespace remill

#endif  // REMILL_ARCH_NAME_H_
