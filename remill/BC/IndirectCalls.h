/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <unordered_map>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "remill/BC/UnfoldUtils.h"

namespace remill {

  static inline
  std::vector<llvm::Function *> GetIndirectCallers(llvm::Module &module) {

    std::vector<llvm::Function *> out;

    auto get_calls = [](auto call) {
      return llvm::dyn_cast<llvm::CallInst>(call);
    };

    auto collect_indirect = [&](auto call) {
      if (llvm::CallSite(call).isIndirectCall())
        out.push_back(call->getFunction());
    };

    for (auto &func : module) {
      FilterAndApply(&func, get_calls, collect_indirect);
    }

    return out;
  }

  static inline
  std::vector<llvm::Function *> HasAddressTaken(llvm::Module &module) {

    std::vector<llvm::Function *> out;
    for (auto &func : module) {

      if (func.hasAddressTaken()) {
        out.push_back(&func);
      }

    }

    return out;
  }
} // namespace remill
