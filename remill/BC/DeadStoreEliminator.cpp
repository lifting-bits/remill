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

StateSlot::StateSlot(uint64_t i_, uint64_t offset_, uint64_t size_)
  : i(i_), offset(offset_), size(size_) { }

StateVisitor::StateVisitor(llvm::DataLayout *dl_)
  : slots(std::vector<StateSlot>()), idx(0), offset(0), dl(dl_) { }

/* Update the StateVisitor's slots field to hold
 * a StateSlot for every byte offset into the state.
 * The StateSlot element is the same across each byte offset
 * that is within the element's begin offset and end offset.
 */
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
      for (uint64_t i=0; i<len; i++) {
        slots.push_back(remill::StateSlot(idx, offset, len));
      }
      // update StateVisitor fields
      idx++;
      offset += len;
    } else {
      for (unsigned int i=0; i < seq_ty->getNumElements(); i++) {
        // repeat NumContained times
        // NOTE: will recalculate every time, rather than memoizing
        visit(first_ty);
      }
    }
  } else {  // BASE CASE
    uint64_t len = dl->getTypeAllocSize(ty);
    for (uint64_t i=0; i<len; i++) {
      slots.push_back(remill::StateSlot(idx, offset, len));
    }
    // update StateVisitor fields
    idx++;
    offset += len;
  }
}

/* For each instruction in the alias map, add an AAMDNodes struct 
 * which specifies the aliasing stores and loads to the instruction's byte offset.
 */
void addAAMDNodes(AliasMap alias_map, std::vector<llvm::AAMDNodes> aamds) {
  for ( const auto &alias : alias_map ) {
    if (auto inst = llvm::dyn_cast<llvm::LoadInst>(alias.first)) {
      auto aamd = aamds[alias.second];
      inst->setAAMetadata(aamd);
    } else if (auto inst = llvm::dyn_cast<llvm::StoreInst>(alias.first)) {
      auto aamd = aamds[alias.second];
      inst->setAAMetadata(aamd);
    }
  }
}

/* Return a map of MDNode scopes and a vector of AAMDNodes based on the given vector of StateSlots,
 * where each byte offset (i.e. index) in the slots vector is mapped to a
 * corresponding AAMDNodes struct.
 */
std::pair<std::unordered_map<llvm::MDNode *, uint64_t>, std::vector<llvm::AAMDNodes>> generateAAMDInfo(
    std::vector<StateSlot> slots,
    llvm::LLVMContext &context) {
  std::vector<std::pair<llvm::MDNode *, uint64_t>> node_sizes;
  node_sizes.reserve(slots.size());
  for ( const auto &slot : slots ) {
    auto mdstr = llvm::MDString::get(context, "slot_" + std::to_string(slot.i));
    node_sizes.push_back(std::make_pair(llvm::MDNode::get(context, mdstr), slot.size));
  }
  std::vector<llvm::AAMDNodes> aamds;
  aamds.reserve(slots.size());
  for ( uint64_t i = 0; i < slots.size(); i++ ) {
    // noalias all slots != scope
    std::vector<llvm::Metadata *> noalias_vec;
    for ( uint64_t j = 0; j < slots.size(); j++ ) {
      if (i != j) {
        noalias_vec.push_back(node_sizes[j].first);
      }
    }
    llvm::MDNode *noalias = llvm::MDNode::get(context, llvm::MDTuple::get(context, noalias_vec));
    aamds.emplace_back(nullptr, node_sizes[i].first, noalias);
  }
  std::unordered_map<llvm::MDNode *, uint64_t> scopes(node_sizes.begin(), node_sizes.end());
  return std::make_pair(scopes, aamds);
}

std::unordered_map<llvm::MDNode *, uint64_t> AnalyzeAliases(llvm::Module *module, std::vector<StateSlot> slots) {
  auto aamd_sizes = generateAAMDInfo(slots, module->getContext());
  auto scope_sizes = aamd_sizes.first;
  auto aamds = aamd_sizes.second;
  llvm::DataLayout dl = module->getDataLayout();
  auto bb_func = BasicBlockFunction(module);
  for (auto &func : *module) {
    if (&func != bb_func
        && func.getType() == bb_func->getType()
        && !func.isDeclaration())
    {
      auto sp = LoadStatePointer(&func);
      ForwardAliasVisitor fav(&dl, sp);
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
      addAAMDNodes(fav.alias_map, aamds);
    }
  }
  return scope_sizes;
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

// Visit a cast instruction and update the offset map.
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

// Visit an add instruction and update the offset map.
AliasResult ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered add instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, true);
}

// Visit a sub instruction and update the offset map.
AliasResult ForwardAliasVisitor::visitSub(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered sub instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, false);
}

// Visit an add or sub instruction.
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
    }
  }
}

// Visit a PHI node and update the offset map.
AliasResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &I) {
  LOG(INFO) << "Entered PHI node";
  // iterate over each operand
  auto in_offset_map = false;
  uint64_t offset;
  for (auto &operand : I.operands()) {
    if (exclude.count(operand)) {
      // fail if some operands are excluded and others are state offsets
      if (in_offset_map) {
        return AliasResult::Error;
      }
    } else {
      auto ptr = offset_map.find(operand);
      if (ptr == offset_map.end()) {
        return AliasResult::NoProgress;
      } else {
        if (!in_offset_map) {
          offset = ptr->second;
          in_offset_map = true;
        } else {
          if (ptr->second != offset) {
            // bail if the offsets don't match
            return AliasResult::Error;
          }
        }
      }
    }
  }
  if (in_offset_map) {
    LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
    offset_map.insert({&I, offset});
  } else {
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    exclude.insert(&I);
  }
  return AliasResult::Progress;
}

// Return the scope of the given instruction.
llvm::MDNode *GetScopeFromInst(llvm::Instruction &I) {
  llvm::AAMDNodes N;
  I.getAAMetadata(N);
  return N.Scope;
}

void GenerateLiveSet(llvm::Module *module, std::unordered_map<llvm::MDNode *, uint64_t> &scopes) {
  //TODO(tim): iterate through instructions
  auto bb_func = BasicBlockFunction(module);
  size_t slots = scopes.size();
  for (auto &func : *module) {
    if (&func != bb_func
        && func.getType() == bb_func->getType()
        && !func.isDeclaration())
    {
      std::vector<bool> live;
      live.reserve(slots);
      for (size_t i=0; i < slots; i++) {
        live[i] = true;
      }
      for (auto &block : func) {
        for (auto &inst : block) {
          if (auto scope = GetScopeFromInst(inst)) {
            LOG(INFO) << "Found scope data in " << LLVMThingToString(&inst);
            if (llvm::isa<llvm::StoreInst>(&inst)) {
              // reset
              live[scopes[scope]] = false;
            } else if (llvm::isa<llvm::LoadInst>(&inst)) {
              // set
              live[scopes[scope]] = true;
            }
          } 
        }
      }
      LOG(INFO) << "Func " << LLVMThingToString(&func) << " liveset: "
        << live.size() << " slots, " << std::count(live.begin(), live.end(), true) << " live";
    }
  }
  return;
}

}  // namespace remill
