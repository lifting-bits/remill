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

#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <remill/BC/InstructionLifter.h>

#include <functional>
#include <ios>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/DataLayout.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

namespace remill {

class InstructionLifter::Impl {
 public:
  Impl(const Arch *arch_, const IntrinsicTable *intrinsics_);

  // Architecture being used for lifting.
  const Arch *const arch;

  // Machine word type for this architecture.
  llvm::IntegerType *const word_type;

  // Set of intrinsics.
  const IntrinsicTable *const intrinsics;

  // Cache of looked up registers inside of `last_func`.
  std::unordered_map<std::string, llvm::Value *> reg_ptr_cache;

  // The function into which we're lifting. If This gets out of date, we
  // clear out `reg_ptr_cache`.
  llvm::Function *last_func{nullptr};

  llvm::Module *const module;
  llvm::Function *const invalid_instruction;
  llvm::Function *const unsupported_instruction;
};

}  // namespace remill
