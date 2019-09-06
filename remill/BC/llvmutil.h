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

#include <unordered_set>

namespace pipes {

template< typename In, typename Out >
struct Walker {

};

template< typename ... Next >
struct In {

  template<typename Callback>
  static bool Walk(llvm::Value *value, Callback CB) {
    return false;
  }

};

template< typename Head, typename ... Next >
struct In< Head, Next ... > {

  template<typename Callback>
  static bool Walk(llvm::Value *value, Callback CB) {
    if (auto head = llvm::dyn_cast<Head>(value)) {
      return CB(head);
    }
    return Walk<Next...>(value, CB);
  }
};


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

#if 1
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

#else
template<typename Inst, typename End>
End *GetEndOfChain(llvm::Value *val) {
  auto inst = llvm::dyn_cast<Inst>(val);
  if (!inst) {
    return nullptr;
  }

  while (inst) {
    if (!inst->hasOneUse()) {
      return nullptr;
    }
    if (auto end = llvm::dyn_cast<End>(*inst->user_begin())) {
      return end;
    }
    inst = llvm::dyn_cast<Inst>(*inst->user_begin());
  }
  return nullptr;
}
#endif

#define DUMP(inst) \
  inst->print(llvm::errs()); \
  std::cerr << std::endl

struct _Walker {

  std::unordered_set<llvm::Instruction *> _seen;
  llvm::Function *_func;

  _Walker(llvm::Function *_func) : _func(_func) {
    std::cerr << "_Walker " << _func->getName().str() << std::endl;
  }

  ~_Walker() {
    std::cerr << "\n***" << std::endl;
  }

  bool RWalk(llvm::Value *origin) {
    bool acc = true;

    for (auto &use : origin->uses()) {
      //std::cerr << "RWALK" << std::endl;
      //DUMP(use);
      if (auto extract = llvm::dyn_cast<llvm::ExtractValueInst>(use)) {
        if (auto end =
            GetBeginOfChain<llvm::ExtractValueInst, llvm::ReturnInst>(extract)) {
          acc &= llvm::CallSite(end).getCalledFunction() == _func;
        }

      }
    }
    return acc;
  }

  bool NewOrigin(llvm::Value *origin, llvm::PHINode *phi) {
    bool acc = true;
    //std::cerr << "NewOrigin" << std::endl;
    acc &= Walk(phi);
    for (auto &use : phi->uses()) {
      DUMP(use);
      if (use == origin) continue;

      acc &= RWalk(use);
    }
    return acc;
  }

  bool Walk(llvm::Value *origin) {
    //std::cerr << "Origin" << std::endl;
    //DUMP(origin);
    //std::cerr << "Walk" << std::endl;
    bool acc = true;
    for (auto user : origin->users()) {
      if (!acc) return false;
      //DUMP(user);
      if (auto phi = llvm::dyn_cast<llvm::PHINode>(user)) {
        //std::cerr << "Was phi!" << std::endl;
        acc &= NewOrigin(origin, phi);
      }

      else if (auto call = llvm::dyn_cast<llvm::CallInst>(user)) {
        if (llvm::CallSite(call).getCalledFunction() == _func) {
          acc &= true;
        }
      }

      else if (auto insert = llvm::dyn_cast<llvm::InsertValueInst>(user)) {
        auto ret = GetEndOfChain<llvm::InsertValueInst, llvm::ReturnInst>(insert);
        if (ret) {
          acc &= true;
        }

      } else {
        return false;
      }
    }

    return acc;
  }
};

} // namespace pipes
