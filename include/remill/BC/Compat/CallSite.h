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


/* In llvm-11 llvm::CallSite got partially replace by llvm::AbstractCallSite
 * for read-only operations and llvm::CallBase was made public (was considered
 * implementation before)
 * This header tries to provide at least some compatibility for what is
 * currently used.
 */

#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)

#  include <llvm/IR/CallSite.h>
namespace remill::compat::llvm {

struct CallSite : private ::llvm::CallSite {
  using parent = ::llvm::CallSite;

  /* List of "allowed" methods (thanks to private inheritance)
     * that prevent user from accidentally using functionality that
     * would break other llvm version.
     * If you want to add method here, make sure other versions have it
     * as well.
     */
  using parent::isCall;
  using parent::isInvoke;
  using parent::parent;
  using parent::operator bool;
  using parent::getCalledFunction;
  using parent::getCalledValue;
  using parent::getInstruction;
  using parent::setCalledFunction;
};

}  // namespace remill::compat::llvm

#else

#  include <llvm/Analysis/InlineCost.h>
#  include <llvm/IR/AbstractCallSite.h>
#  include <llvm/Transforms/Utils/Cloning.h>
namespace remill::compat::llvm {

struct CallSite {
  ::llvm::CallBase *cb;

  CallSite(::llvm::Instruction *inst)
      : cb(::llvm::dyn_cast_or_null<::llvm::CallBase>(inst)) {}

  CallSite(::llvm::User *user)
      : CallSite(::llvm::dyn_cast_or_null<::llvm::Instruction>(user)) {}

  bool isInvoke() const {
    return cb && ::llvm::isa<::llvm::InvokeInst>(*cb);
  }

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

#endif
