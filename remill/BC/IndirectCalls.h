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

  template<typename Inst>
  Inst *FirstTypedInst(llvm::Function *func) {
    for (auto &bb: *func) {
      for (auto &inst : bb) {
        if (auto casted = llvm::dyn_cast<Inst>(&inst);
            casted && llvm::CallSite(casted).isIndirectCall()) {
          return casted;
        }
      }
    }
    return nullptr;
  }


  struct ExplicateIndirectCall {

    llvm::Function *_func;
    llvm::LLVMContext &_ctx;

    llvm::BasicBlock *_base;
    llvm::BasicBlock *_after;
    llvm::BasicBlock *_tail;

    //llvm::PHINode *_phi;

    ExplicateIndirectCall(llvm::Function *func) :
      _func(func), _ctx(_func->getContext()) {}


    ~ExplicateIndirectCall() {
      llvm::IRBuilder<> ir { _tail };
      auto &unreachable = _tail->back();
      ir.CreateBr(_base);

      unreachable.eraseFromParent();

      //if (_phi->getNumIncomingValues() == 0) {
      //  _phi->eraseFromParent();
      //}
      _func->print(llvm::errs());
      std::cerr << std::endl;
    }

    void Split(llvm::CallInst *call) {
      auto bb = call->getParent();

      _base = bb->splitBasicBlock(call);
      _base->print(llvm::errs());

      _after = _base->splitBasicBlock(std::next(_base->begin(), 2));

      auto branch = llvm::dyn_cast<llvm::BranchInst>(&bb->back());
      _tail = CreateNewNode("_tail.0");
      branch->setSuccessor(0, _tail);


      llvm::IRBuilder<> ir{_after};
      ir.SetInsertPoint(&*_after->begin());

      //_phi = ir.CreatePHI(call->getFunctionType()->getReturnType(), 0);
     // _phi->addIncoming(ir.getInt64(0), _base);
      //call->replaceAllUsesWith(_phi);
    }

    llvm::BasicBlock *CreateNewNode(const std::string &name="") {
      auto node = llvm::BasicBlock::Create(_ctx, name, _func);

      llvm::IRBuilder<>{ node }.CreateUnreachable();
      return node;
    }


    llvm::BasicBlock *CreateCallBB(llvm::Function *target) {
      auto bb = llvm::BasicBlock::Create(_ctx, "C." + target->getName(), _func);

      llvm::IRBuilder<> ir{ bb };

      std::vector<llvm::Value *> new_args;
      for (auto &arg : _func->args()) {
        new_args.push_back(&arg);
        arg.print(llvm::errs());
        std::cerr << std::endl;
      }
      ir.CreateCall(target, new_args);
      //auto ret = ir.CreateCall(target, {_func->arg_begin(), _func->arg_end()});

      ir.CreateBr(_after);
      //_phi->addIncoming(ret, bb);
      return bb;
    }

    llvm::BasicBlock *CreateCase(llvm::Function *what, llvm::Function *target) {
      if (!target) {
        std::cerr << "NULL" << std::endl;
        return nullptr;
      }
      auto next = CreateNewNode();
      auto succes = CreateCallBB(target);

      auto &current = _tail; // _tail

      llvm::IRBuilder<> ir{ &current->back() };

      auto func_ptr = ir.CreateIntToPtr(
          &*std::next(_func->arg_begin()), what->getType());

      auto cmp = ir.CreateICmpEQ(func_ptr, what);

      ir.CreateCondBr(cmp, succes, next);

      current->back().eraseFromParent();

      _tail = next;
      return _tail;
    }

  };

} // namespace remill
