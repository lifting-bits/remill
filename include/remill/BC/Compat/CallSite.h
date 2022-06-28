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

#include <llvm/IR/Instruction.h>

#include "remill/BC/Version.h"

#include <llvm/Analysis/InlineCost.h>
#include <llvm/IR/AbstractCallSite.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace remill::compat::llvm {

struct CallSite {
  ::llvm::CallBase *cb;

  CallSite(::llvm::Instruction *inst)
      : cb(::llvm::dyn_cast_or_null<::llvm::CallBase>(inst)) {}

  CallSite(::llvm::User *user)
      : CallSite(::llvm::dyn_cast_or_null<::llvm::Instruction>(user)) {}

  bool isCall() const {
    return cb && ::llvm::isa<::llvm::CallInst>(*cb);
  }

  ::llvm::Value *getCalledValue() {
    if (!static_cast<bool>(*this)) {
      return nullptr;
    }
    return cb->getCalledOperand();
  }

  ::llvm::Function *getCalledFunction() const {
    if (!*this) {
      return nullptr;
    }
    return cb->getCalledFunction();
  }

  void setCalledFunction(::llvm::Function *fn) {
    return cb->setCalledFunction(fn);
  }

  operator bool() const {
    return cb;
  }

  ::llvm::CallBase *getInstruction() {
    return cb;
  }
};

}  // namespace remill::compat::llvm
