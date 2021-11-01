/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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


#include <remill/Arch/Arch.h>

#include <memory>
#include <unordered_map>
#include <vector>

namespace llvm {
class FunctionType;
class PointerType;
class StructType;
}  // namespace llvm
namespace remill {

struct Register;

class ArchImpl {
 public:
  // State type.
  llvm::StructType *state_type{nullptr};

  // Memory pointer type.
  llvm::PointerType *memory_type{nullptr};

  // Lifted function type.
  llvm::FunctionType *lifted_function_type{nullptr};

  // Metadata type ID for remill registers.
  unsigned reg_md_id{0};

  std::vector<std::unique_ptr<Register>> registers;
  std::vector<const Register *> reg_by_offset;
  std::unordered_map<std::string, const Register *> reg_by_name;
};

}  // namespace remill
