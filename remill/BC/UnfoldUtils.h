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

#include <llvm/IR/Instructions.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/Module.h>

#include <remill/BC/Util.h>

#include <unordered_set>

namespace remill {

static inline void UnsafeErase(llvm::Function *func) {
  if (!func) {
    return;
  }

  func->replaceAllUsesWith(
    llvm::UndefValue::get(llvm::PointerType::getUnqual(func->getFunctionType())));
  func->eraseFromParent();
}

// Apply passed function to every instruction that satisfies filter (which will
// usually be llvm::dyn_cast).
template<typename LLVMFunc, typename Filter, typename Apply>
void FilterAndApply(LLVMFunc *func, Filter &&filter, Apply apply) {
  for (auto &bb : *func) {
    for (auto &inst : bb) {
      if (auto casted = filter(&inst)) {
        apply(casted);
      }
    }
  }
}

template<typename LLVMModule>
auto GetExplicitState(LLVMModule &module) {
  auto state = module.getNamedGlobal("__mcsema_reg_state");
  return state;
}

static inline const llvm::GlobalVariable *GetExplicitState(const llvm::Function *func) {
  return GetExplicitState(*func->getParent());
}

// Filter only instructions of type T from function
// TODO: Extend this, probably using stack-like structure
template<typename T>
std::vector<T *> Filter(llvm::Function *func) {
  std::vector<T *> out;
  for (auto &bb : *func) {
    for (auto &inst : bb) {
      if (auto casted = llvm::dyn_cast<T>(&inst)) {
        out.push_back(casted);
      }
    }
  }
  return out;
}

// Iterate over getAggregateOperand() until the instruction can be casted to Begin
// Return Begin or nullptr on failure.
template<typename Inst, typename Begin>
Begin *GetBeginOfChain(Inst *val) {
  if (!val) {
    return nullptr;
  }

  if (auto end = llvm::dyn_cast<Begin>(val->getAggregateOperand())) {
    return end;
  }

  return GetBeginOfChain<Inst, Begin>(llvm::dyn_cast<Inst>(val->getAggregateOperand()));
}

// Iterate users (in case there is more than one nullptr is returned), until it can
// be casted to End
// Return End or nullptr on failure
template<typename Inst, typename End>
End *GetEndOfChain(llvm::Value *val) {
  if (!val) {
    return nullptr;
  }

  if (!val->hasOneUse()) {
    return nullptr;
  }

  if (auto end = llvm::dyn_cast<End>(*val->user_begin())) {
     return end;
  }
  return GetEndOfChain<Inst, End>(llvm::dyn_cast<Inst>(*val->user_begin()));

}

// Checks if value can escape into different function
// This can be used to determine whether argument is only passed around in recursion
// without actually being used for anything else
struct _EscapeArgument {

  std::unordered_set<llvm::Value *> _seen;
  llvm::Function *_func;

  llvm::Value *_origin = nullptr;
  uint64_t _arg_idx = -1;

  _EscapeArgument(llvm::Function *func) : _func(func) {}

  bool SpreadForward(llvm::Value *val) {
    bool acc = true;
    for (auto user : val->users()) {
      acc &= Forward(user);
    }
    return acc;
  }

  bool SpreadBackward(llvm::Value *val) {
    bool acc = true;
    for (auto &use : val->uses()) {
      acc &= Backward(use);
    }
    return acc;
  }


  bool Forward(llvm::Value *val) {

    if (_seen.count(val)) {
      return true;
    }
    _seen.insert(val);

    if (auto phi = llvm::dyn_cast<llvm::PHINode>(val)) {
      bool acc = SpreadForward(phi);
      for (auto &use: phi->incoming_values()) {
        acc &= Backward(use);
      }
      return acc;
    }

    if (auto call = llvm::dyn_cast<llvm::CallInst>(val)) {
      return llvm::CallSite(call).getCalledFunction() == _func &&
             NthArgument(_func, _arg_idx) == _origin;
    }

    if (auto insert = llvm::dyn_cast<llvm::InsertValueInst>(val)) {
      return GetEndOfChain<llvm::InsertValueInst, llvm::ReturnInst>(insert) &&
             *insert->idx_begin() == _arg_idx;
    }

    return false;
  }


  bool Backward(llvm::Value *val) {

    if (_seen.count(val)) {
      return true;
    }
    _seen.insert(val);

    if (auto arg = llvm::dyn_cast<llvm::Argument>(val)) {
      return arg == _origin;
    }

    if (auto phi = llvm::dyn_cast<llvm::PHINode>(val)) {
      bool acc = true;
      for (auto &use: phi->incoming_values()) {
        if (use == llvm::UndefValue::get(use->getType())) {
          continue;
        }
        acc &= Backward(use);
      }
      return acc;
    }

    if (auto extract = llvm::dyn_cast<llvm::ExtractValueInst>(val)) {
      auto call = GetBeginOfChain<llvm::ExtractValueInst, llvm::CallInst>(extract);
      return call &&
             llvm::CallSite(call).getCalledFunction() == _func &&
             // The order is important! It needs to be passed as the same param
             *extract->idx_begin() == _arg_idx;
    }

    return false;
  }

  // Returns true if argument origin on position arg_idx in args list
  // is used for something other than being passed around
  bool Run(llvm::Value *origin, uint64_t arg_idx) {
    _arg_idx = arg_idx;
    _origin = origin;
    return SpreadForward(origin);
  }
};


struct _EscapeArgumentFromReturn : _EscapeArgument {
 using _EscapeArgument::_EscapeArgument;

  // Returns true if argument origin on position arg_idx in return struct
  // is used for something other than being returned around
  bool Run(llvm::Value *origin, uint64_t arg_idx) {
    _arg_idx = arg_idx;
    _origin = NthArgument(_func, _arg_idx);
    return SpreadBackward(origin);
  }
};

} // namespace remill
