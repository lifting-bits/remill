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

#include <string_view>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {

// Describes the arguments to a basic block function.
enum : size_t {
  kStatePointerArgNum = 0,
  kPCArgNum = 1,
  kMemoryPointerArgNum = 2,
  kNumBlockArgs = 3
};

extern const std::string_view kMemoryVariableName;
extern const std::string_view kStateVariableName;
extern const std::string_view kPCVariableName;
extern const std::string_view kNextPCVariableName;
extern const std::string_view kReturnPCVariableName;
extern const std::string_view kBranchTakenVariableName;

extern const std::string_view kInvalidInstructionISelName;
extern const std::string_view kUnsupportedInstructionISelName;
extern const std::string_view kIgnoreNextPCVariableName;

}  // namespace remill
