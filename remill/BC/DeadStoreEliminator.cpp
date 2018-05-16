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

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Module.h>

#include "remill/BC/DeadStoreEliminator.h"
#include "remill/BC/Util.h"

/* TODO(tim):
 * - Retrieve a State struct
 * - Recursively visit the struct's members and produce a flattened list of slots
 */

namespace remill {
// Return a vector of state slot records, where each
// "slot" of the State structure has its own SlotRecord.
std::vector<StateSlot> StateSlots(llvm::Module *module) {
  // get the state
  auto slots = std::vector<StateSlot>();
  auto state_ptr_type = StatePointerType(module);
  llvm::Type *type = state_ptr_type->getElementType();
  llvm::DataLayout dl = module->getDataLayout();
  StateVisitor vis(&dl);
  vis.visit(type);
  return vis.slots;
}

StateSlot::StateSlot(uint64_t begin_offset_, uint64_t end_offset_)
  : begin_offset(begin_offset_), end_offset(end_offset_) { }

StateVisitor::StateVisitor(llvm::DataLayout *dl_)
  : slots(std::vector<StateSlot>()), offset(0), dl(dl_) { }

void StateVisitor::visit(llvm::Type *ty) {
  if (ty == nullptr) {
    // skip
  } else if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(ty)) {
    for (auto elem_ty : struct_ty->elements()) {
      visit(elem_ty);
    }
  } else if (auto seq_ty = llvm::dyn_cast<llvm::SequentialType>(ty)) {
    auto first_ty = seq_ty->getElementType();
    if (auto int_ty = llvm::dyn_cast<llvm::IntegerType>(first_ty)) {
      // SPECIAL CASE
      // treat sequences of primitive types as one slot
      uint64_t len = dl->getTypeAllocSize(seq_ty);
      slots.push_back(remill::StateSlot(offset, offset + len));
      offset += len;
    } else {
      for (unsigned int i=0; i < seq_ty->getNumElements(); i++) {
        // repeat NumContained times
        // NOTE: will recalculate every time, rather than memoizing
        visit(first_ty);
      }
    }
  } else {  // BASE CASE
    //ty->dump();
    uint64_t len = dl->getTypeAllocSize(ty);
    slots.push_back(remill::StateSlot(offset, offset + len));
    offset += len;
  }
}

void AnalyzeAliases(llvm::Module *module) {
  auto slots = StateSlots(module);
  llvm::DataLayout dl = module->getDataLayout();
  auto bb_func = BasicBlockFunction(module);
  for (auto &func : *module) {
    if (&func != bb_func
        && func.getType() == bb_func->getType()
        && !func.isDeclaration())
    {
      // add state pointer
      auto sp = LoadStatePointer(&func);
      ForwardAliasVisitor fav(&dl, sp);
      //fav.offset_map.insert({LoadStatePointer(func), 0});
      std::vector<llvm::Instruction *> insts;
      for (auto &block : func) {
        for (auto &inst : block) {
          insts.push_back(&inst);
        }
      }
      fav.addInstructions(insts);
      fav.analyze();
      LOG(INFO) << "Offsets: " << fav.offset_map.size();
      LOG(INFO) << "Aliases: " << fav.alias_map.size();
      LOG(INFO) << "Excluded: " << fav.exclude.size();
    }
  }
}

enum class AliasResult {
  Progress,
  NoProgress,
  Error
};

ForwardAliasVisitor::ForwardAliasVisitor(llvm::DataLayout *dl_, llvm::Value *sp_)
  : offset_map({{sp_, 0}}),
    alias_map(),
    exclude(),
    curr_wl(),
    next_wl(),
    state_ptr(sp_),
    dl(dl_) { }

// Add instructions to the visitor's worklist.
void ForwardAliasVisitor::addInstructions(std::vector<llvm::Instruction *> &insts) {
  curr_wl.insert(insts.begin(), insts.end());
}

// Iterate through the current worklist, updating the offset_map and alias_map
// according to the instructions in the list. Any instruction that is not
// currently interpretable (some of its pointers are not yet in the offset_map)
// is withheld to the next analysis round in the next worklist.
// Analysis repeats until the current worklist is empty.
void ForwardAliasVisitor::analyze(void) {
  bool progress = true;
  // if any visit makes progress, continue the loop
  while (!curr_wl.empty() && progress) {
    LOG(INFO) << "FAV: " << curr_wl.size() << " instructions remaining";
    progress = false;
    for (auto inst : curr_wl) {
      switch (visit(inst)) {
        case AliasResult::Progress:
          progress = true;
          break;
        case AliasResult::NoProgress:
          next_wl.insert(inst);
          break;
        case AliasResult::Error:
          return;
      }
    }
    // update curr_wl to the next set of insts
    curr_wl.swap(next_wl);
    // reset upcoming insts
    next_wl.clear();
  }
}

AliasResult ForwardAliasVisitor::visitInstruction(llvm::Instruction &I) {
  return AliasResult::Progress;
}

AliasResult ForwardAliasVisitor::visitAllocaInst(llvm::AllocaInst &I) {
  LOG(INFO) << "Entered alloca instruction";
  exclude.insert(&I);
  LOG(INFO) << "excluding: " << LLVMThingToString(&I);
  return AliasResult::Progress;
}

// Visit a load instruction and update the alias map.
AliasResult ForwardAliasVisitor::visitLoadInst(llvm::LoadInst &I) {
  LOG(INFO) << "Entered load instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  // special case: loading the state ptr
  if (exclude.count(val) && I.getType() != state_ptr->getType()) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return AliasResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return AliasResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I);
      return AliasResult::Progress;
    }
  }
}

// Visit a store instruction and update the alias map.
AliasResult ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &I) {
  LOG(INFO) << "Entered store instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return AliasResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return AliasResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I);
      return AliasResult::Progress;
    }
  }
}

// Visit a GEP instruction and update the offset map.
AliasResult ForwardAliasVisitor::visitGetElementPtrInst(llvm::GetElementPtrInst &I) {
  LOG(INFO) << "Entered GEP instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return AliasResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      // no pointer found
      return AliasResult::NoProgress;
    } else {
      // get the offset
      llvm::APInt offset;
      if (I.accumulateConstantOffset(*dl, offset)) {
        // use offset (getRawData extracts the uint64_t)
        offset_map[&I] = *(ptr->second + offset.getRawData());
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return AliasResult::Progress;
      } else {
        // give up
        return AliasResult::Error;
      }
    }
  }
}

AliasResult ForwardAliasVisitor::visitCastInst(llvm::CastInst &I) {
  LOG(INFO) << "Entered inttoptr instruction";
  auto val = I.getOperand(0);
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return AliasResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return AliasResult::NoProgress;
    } else {
      // update value
      offset_map[&I] = ptr->second;
      LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
      return AliasResult::Progress;
    }
  }
}

AliasResult ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered add instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, true);
}

AliasResult ForwardAliasVisitor::visitSub(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered sub instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, false);
}

AliasResult ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &I, bool plus) {
  auto val1 = I.getOperand(0);
  auto val2 = I.getOperand(1);
  if (exclude.count(val1) || exclude.count(val2)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return AliasResult::Progress;
  } else {
    if (auto cint = llvm::dyn_cast<llvm::ConstantInt>(val1)) {
      auto ptr = offset_map.find(val2);
      if (ptr == offset_map.end()) {
        return AliasResult::NoProgress;
      } else {
        auto offset = (plus ? ptr->second + cint->getZExtValue() : ptr->second - cint->getZExtValue());
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return AliasResult::Progress;
      }
    } else if (auto cint = llvm::dyn_cast<llvm::ConstantInt>(val2)) {
      auto ptr = offset_map.find(val1);
      if (ptr == offset_map.end()) {
        return AliasResult::NoProgress;
      } else {
        auto offset = (plus ? ptr->second + cint->getZExtValue() : ptr->second - cint->getZExtValue());
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return AliasResult::Progress;
      }
    } else {
      // check if both are in the offset_map
      auto ptr1 = offset_map.find(val1);
      auto ptr2 = offset_map.find(val2);
      if (ptr1 == offset_map.end() || ptr2 == offset_map.end()) {
        return AliasResult::NoProgress;
      } else {
        auto offset = (plus ? ptr1->second + ptr2->second : ptr1->second - ptr2->second);
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return AliasResult::Progress;
      }
      // neither val is constant, so give up
      //return AliasResult::Error;
    }
  }
}

AliasResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &I) {
  LOG(INFO) << "Entered PHI node";
  // iterate over each operand
  auto in_offset_map = true;
  for (auto &operand : I.operands()) {
    if (exclude.count(operand)) {
      in_offset_map = false;
    } else {
      auto ptr = offset_map.find(operand);
      if (ptr == offset_map.end()) {
        return AliasResult::NoProgress;
      }
    }
  }
  if (in_offset_map) {
    //TODO(tim): modify offset_map
  } else {
    exclude.insert(&I);
  }
  return AliasResult::Progress;
}

}  // namespace remill
