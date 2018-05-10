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
    for (unsigned int i=0; i < seq_ty->getNumElements(); i++) {
      // repeat NumContained times
      // NOTE: will recalculate every time, rather than memoizing
      visit(first_ty);
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
  for (auto &func : *module) {
    // add state pointer
    auto fav = ForwardAliasVisitor(&dl);
    fav.offset_map.insert({LoadStatePointer(&func), 0});
    std::vector<llvm::Instruction *> insts;
    for (auto &block : func) {
      for (auto &inst : block) {
        insts.push_back(&inst);
      }
    }
    fav.addInstructions(insts);
    fav.analyze();
  }
}

ForwardAliasVisitor::ForwardAliasVisitor(llvm::DataLayout *dl_)
  : offset_map(), alias_map(), exclude(), curr_wl(), next_wl(), dl(dl_) { }

// Add instructions to the visitor's worklist.
void ForwardAliasVisitor::addInstructions(std::vector<llvm::Instruction *> &insts) {
  curr_wl.insert(insts.begin(), insts.end());
}

// Iterate through the current worklist, updating the offset_map and alias_map
// according to the instructions in the list. Any instruction that is not
// currently interpretable (some of its pointers are not yet in the offset_map)
// is withheld to the next analysis round in the next worklist.
// Analysis repeats until the current worklist is empty.
void ForwardAliasVisitor::analyze() {
  while (!curr_wl.empty()) {
    for (auto inst : curr_wl) {
      visit(inst);
    }
    // update curr_wl to the next set of insts
    curr_wl.swap(next_wl);
    // reset upcoming insts
    next_wl.clear();
  }
}

void ForwardAliasVisitor::visitAllocaInst(llvm::AllocaInst &I) {
  LOG(INFO) << "Entered alloca instruction";
  exclude.insert(&I);
}

// Visit a load instruction and update the alias map.
void ForwardAliasVisitor::visitLoadInst(llvm::LoadInst &I) {
  LOG(INFO) << "Entered load instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val) == 0) {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      next_wl.insert(&I);
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
    }
  }
}

// Visit a store instruction and update the alias map.
void ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &I) {
  LOG(INFO) << "Entered store instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val) == 0) {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      next_wl.insert(&I);
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
    }
  }
}

// Visit a GEP instruction and update the offset map.
void ForwardAliasVisitor::visitGetElementPtrInst(llvm::GetElementPtrInst &I) {
  LOG(INFO) << "Entered GEP instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val) > 0) {
    exclude.insert(&I);
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      // no pointer found
      next_wl.insert(&I);
    } else {
      // get the offset
      llvm::APInt offset;
      if (I.accumulateConstantOffset(*dl, offset)) {
        // use offset
        offset_map.insert({&I, ptr->second + offset});
      } else {
        // give up
        exclude.insert(&I);
      }
    }
  }
}

void ForwardAliasVisitor::visitGetPtrToIntInst(llvm::GetPtrToIntInst &I) {
  LOG(INFO) << "Entered ptrtoint instruction";
  // TODO: save int to alias map with offset to ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val) == 0) {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      next_wl.insert(&I);
    } else {
      offset_map.insert({&I, ptr->second});
    }
  }
}

void ForwardAliasVisitor::visitGetIntToPtrInst(llvm::GetIntToPtrInst &I) {
  LOG(INFO) << "Entered inttoptr instruction";
  auto val = &I;
  if (exclude.count(val) == 0) {
    auto ptr = offset_map.find(&I);
    if (ptr == offset_map.end()) {
      // TODO: add to offset_map?
      next_wl.insert(&I);
    } else {
      // update value
      offset_map[&I] = ptr->second;
    }
  }
}

void ForwardAliasVisitor::visitBitCastInst(llvm::BitCastInst &I) {
  LOG(INFO) << "Entered bitcast instruction";
  // will naturally fail if I.getOperand(0) does not point to a pointer
  auto val = I.getOperand(0);
  if (exclude.count(val) == 0) {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      next_wl.insert(&I);
    } else {
      offset_map.insert({&I, ptr->second});
    }
  }
}

void ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered add instruction";
  ForwardAliasVisitor::visitBinaryOp_(I);
}

void ForwardAliasVisitor::visitSub(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered sub instruction";
  ForwardAliasVisitor::visitBinaryOp_(I);
}

void ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &I) {
  auto val1 = I.getOperand(0);
  auto val2 = I.getOperand(1);
  // FIXME: shouldn't the cint be used?
  if (auto cint = llvm::dyn_cast<llvm::ConstantInt>(val1)) {
    if (exclude.count(val2) > 0) {
      exclude.insert(&I);
    } else {
      auto ptr = offset_map.find(val2);
      if (ptr == offset_map.end()) {
        next_wl.insert(&I);
      } else {
        offset_map.insert({&I, ptr->second});
      }
    }
  } else if (auto cint = llvm::dyn_cast<llvm::ConstantInt>(val2)) {
    if (exclude.count(val1) > 0) {
      exclude.insert(&I);
    } else {
      auto ptr = offset_map.find(val1);
      if (ptr == offset_map.end()) {
        next_wl.insert(&I);
      } else {
        offset_map.insert({&I, ptr->second});
      }
    }
  } else {
    // neither val is constant, so exclude
    exclude.insert(&I);
  }
}

}  // namespace remill
