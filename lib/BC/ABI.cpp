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

#include "remill/BC/ABI.h"

namespace remill {

const std::string_view kMemoryVariableName = "MEMORY";
const std::string_view kStateVariableName = "STATE";
const std::string_view kPCVariableName = "PC";
const std::string_view kNextPCVariableName = "NEXT_PC";
const std::string_view kReturnPCVariableName = "RETURN_PC";
const std::string_view kBranchTakenVariableName = "BRANCH_TAKEN";

const std::string_view kInvalidInstructionISelName = "INVALID_INSTRUCTION";
const std::string_view kUnsupportedInstructionISelName =
    "UNSUPPORTED_INSTRUCTION";

const std::string_view kIgnoreNextPCVariableName = "IGNORE_NEXT_PC";

}  // namespace remill
