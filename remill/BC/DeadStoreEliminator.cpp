//
// Copyright (c) 2017 Trail of Bits, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <glog/logging.h>

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CFG.h>
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
  std::vector<StateSlot> slots;
  auto state_ptr_type = StatePointerType(module);
  auto type = state_ptr_type->getElementType();
  llvm::DataLayout dl = module->getDataLayout();
  StateVisitor vis(&dl);
  vis.Visit(type);
  return vis.slots;
}

StateSlot::StateSlot(uint64_t i_, uint64_t offset_, uint64_t size_)
  : i(i_),
    offset(offset_),
    size(size_) {}

StateVisitor::StateVisitor(llvm::DataLayout *dl_)
  : slots(),
    idx(0),
    offset(0),
    dl(dl_) {}

// Update the StateVisitor's slots field to hold
// a StateSlot for every byte offset into the state.
// The StateSlot element is the same across each byte offset
// that is within the element's begin offset and end offset.
void StateVisitor::Visit(llvm::Type *ty) {
  if (ty == nullptr) {
    // skip
  } else if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(ty)) {
    for (auto elem_ty : struct_ty->elements()) {
      Visit(elem_ty);
    }
  } else if (auto seq_ty = llvm::dyn_cast<llvm::SequentialType>(ty)) {
    auto first_ty = seq_ty->getElementType();
    if (first_ty->isIntegerTy() || first_ty->isFloatingPointTy()) {
      // SPECIAL CASE
      // treat sequences of primitive types as one slot
      uint64_t len = dl->getTypeAllocSize(seq_ty);
      for (uint64_t i = 0; i < len; i++) {
        slots.emplace_back(idx, offset, len);
      }
      // update StateVisitor fields
      idx++;
      offset += len;
    } else {
      for (unsigned int i = 0; i < seq_ty->getNumElements(); i++) {
        // repeat NumContained times
        // NOTE: will recalculate every time, rather than memoizing
        Visit(first_ty);
      }
    }
  } else {  // BASE CASE
    uint64_t len = dl->getTypeAllocSize(ty);
    for (uint64_t i = 0; i < len; i++) {
      slots.emplace_back(idx, offset, len);
    }
    // update StateVisitor fields
    idx++;
    offset += len;
  }
}

// For each instruction in the alias map, add an AAMDNodes struct 
// which specifies the aliasing stores and loads to the instruction's byte offset.
void AddAAMDNodes(AliasMap alias_map, std::vector<llvm::AAMDNodes> aamds) {
  for (const auto &alias : alias_map) {
    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(alias.first)) {
      auto aamd = aamds[alias.second];
      load_inst->setAAMetadata(aamd);
    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(alias.first)) {
      auto aamd = aamds[alias.second];
      store_inst->setAAMetadata(aamd);
    }
  }
}

// Return a map of MDNode scopes and a vector of AAMDNodes based on the given vector of StateSlots,
// where each byte offset (i.e. index) in the slots vector is mapped to a
// corresponding AAMDNodes struct.
AAMDInfo::AAMDInfo(std::vector<StateSlot> slots, llvm::LLVMContext &context) {
  std::vector<std::pair<llvm::MDNode *, uint64_t>> node_sizes;
  node_sizes.reserve(slots.size());
  for (const auto &slot : slots) {
    auto mdstr = llvm::MDString::get(context, "slot_" + std::to_string(slot.i));
    node_sizes.push_back(std::make_pair(llvm::MDNode::get(context, mdstr), slot.size));
  }
  std::vector<llvm::AAMDNodes> aamds;
  aamds.reserve(slots.size());
  for (uint64_t i = 0; i < slots.size(); i++) {
    // noalias all slots != scope
    std::vector<llvm::Metadata *> noalias_vec;
    for (uint64_t j = 0; j < slots.size(); j++) {
      if (i != j) {
        noalias_vec.push_back(node_sizes[j].first);
      }
    }
    llvm::MDNode *noalias = llvm::MDNode::get(context, llvm::MDTuple::get(context, noalias_vec));
    aamds.emplace_back(nullptr, node_sizes[i].first, noalias);
  }
  std::unordered_map<llvm::MDNode *, uint64_t> scopes(node_sizes.begin(), node_sizes.end());
  slot_scopes = scopes;
  slot_aamds = aamds;
}

ScopeMap AnalyzeAliases(llvm::Module *module, std::vector<StateSlot> slots) {
  AAMDInfo aamd_info(slots, module->getContext());
  llvm::DataLayout dl = module->getDataLayout();
  auto bb_func = BasicBlockFunction(module);
  for (auto &func : *module) {
    if (&func != bb_func && !func.isDeclaration() &&
        func.getFunctionType() == bb_func->getFunctionType()) {
      auto sp = LoadStatePointer(&func);
      ForwardAliasVisitor fav(&dl, sp);
      for (auto &block : func) {
        for (auto &inst : block) {
          fav.AddInstruction(&inst);
        }
      }
      if (fav.Analyze()) {
        LOG(INFO) << "Offsets: " << fav.offset_map.size();
        LOG(INFO) << "Aliases: " << fav.alias_map.size();
        LOG(INFO) << "Excluded: " << fav.exclude.size();
        AddAAMDNodes(fav.alias_map, aamd_info.slot_aamds);
      }
    }
  }
  return aamd_info.slot_scopes;
}

enum class VisitResult {
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
    dl(dl_) {}

void ForwardAliasVisitor::AddInstruction(llvm::Instruction *inst) {
  curr_wl.insert(inst);
}

// Iterate through the current worklist, updating the offset_map and alias_map
// according to the instructions in the list. Any instruction that is not
// currently interpretable (some of its pointers are not yet in the offset_map)
// is withheld to the next analysis round in the next worklist.
// Analysis repeats until the current worklist is empty.
bool ForwardAliasVisitor::Analyze(void) {
  bool progress = true;
  // if any visit makes progress, continue the loop
  while (!curr_wl.empty() && progress) {
    LOG(INFO) << "FAV: " << curr_wl.size() << " instructions remaining";
    progress = false;
    for (auto inst : curr_wl) {
      switch (visit(inst)) {
        case VisitResult::Progress:
          progress = true;
          break;
        case VisitResult::NoProgress:
          next_wl.insert(inst);
          break;
        case VisitResult::Error:
          return false;
      }
    }
    // update curr_wl to the next set of insts
    curr_wl.swap(next_wl);
    // reset upcoming insts
    next_wl.clear();
  }
  //TODO(tim): check for possible errors?
  return true;
}

VisitResult ForwardAliasVisitor::visitInstruction(llvm::Instruction &I) {
  return VisitResult::Progress;
}

VisitResult ForwardAliasVisitor::visitAllocaInst(llvm::AllocaInst &I) {
  LOG(INFO) << "Entered alloca instruction";
  exclude.insert(&I);
  LOG(INFO) << "excluding: " << LLVMThingToString(&I);
  return VisitResult::Progress;
}

// Visit a load instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitLoadInst(llvm::LoadInst &I) {
  LOG(INFO) << "Entered load instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  // special case: loading the state ptr
  if (I.getType() == state_ptr->getType()) {
    alias_map.insert({&I, 0});
    return VisitResult::Progress;
  } else if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return VisitResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I);
      return VisitResult::Progress;
    }
  }
}

// Visit a store instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &I) {
  LOG(INFO) << "Entered store instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return VisitResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      alias_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I);
      return VisitResult::Progress;
    }
  }
}

// Visit a GEP instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitGetElementPtrInst(llvm::GetElementPtrInst &I) {
  LOG(INFO) << "Entered GEP instruction";
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      // no pointer found
      return VisitResult::NoProgress;
    } else {
      // get the offset
      llvm::APInt offset;
      if (I.accumulateConstantOffset(*dl, offset)) {
        // use offset (getRawData extracts the uint64_t)
        offset_map[&I] = ptr->second + offset.getZExtValue();
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return VisitResult::Progress;
      } else {
        // give up
        return VisitResult::Error;
      }
    }
  }
}

// Visit a cast instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitCastInst(llvm::CastInst &I) {
  LOG(INFO) << "Entered inttoptr instruction";
  auto val = I.getOperand(0);
  if (exclude.count(val)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = offset_map.find(val);
    if (ptr == offset_map.end()) {
      return VisitResult::NoProgress;
    } else {
      // update value
      offset_map[&I] = ptr->second;
      LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
      return VisitResult::Progress;
    }
  }
}

// Visit an add instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered add instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, true);
}

// Visit a sub instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitSub(llvm::BinaryOperator &I) {
  LOG(INFO) << "Entered sub instruction";
  return ForwardAliasVisitor::visitBinaryOp_(I, false);
}

// Visit an add or sub instruction.
VisitResult ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &I, bool plus) {
  auto val1 = I.getOperand(0);
  auto val2 = I.getOperand(1);
  if (exclude.count(val1) || exclude.count(val2)) {
    exclude.insert(&I);
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    return VisitResult::Progress;
  } else {
    // FIXME(tim): is there a way to make this code more succinct and avoid duplication?
    if (auto cint1 = llvm::dyn_cast<llvm::ConstantInt>(val1)) {
      auto ptr = offset_map.find(val2);
      if (ptr == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        auto offset = (plus ? ptr->second + cint1->getZExtValue() : ptr->second - cint1->getZExtValue());
        // check that we did not overflow
        CHECK(offset <= std::numeric_limits<uint64_t>::max());
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return VisitResult::Progress;
      }
    } else if (auto cint2 = llvm::dyn_cast<llvm::ConstantInt>(val2)) {
      auto ptr = offset_map.find(val1);
      if (ptr == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        auto offset = (plus ? ptr->second + cint2->getZExtValue() : ptr->second - cint2->getZExtValue());
        // check that we did not overflow
        CHECK(offset <= std::numeric_limits<uint64_t>::max());
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return VisitResult::Progress;
      }
    } else {
      // check if both are in the offset_map
      auto ptr1 = offset_map.find(val1);
      auto ptr2 = offset_map.find(val2);
      if (ptr1 == offset_map.end() || ptr2 == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        auto offset = (plus ? ptr1->second + ptr2->second : ptr1->second - ptr2->second);
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
        return VisitResult::Progress;
      }
    }
  }
}

// Visit a PHI node and update the offset map.
VisitResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &I) {
  LOG(INFO) << "Entered PHI node";
  // iterate over each operand
  auto in_offset_map = false;
  auto in_exclude_set = false;
  uint64_t offset;
  for (auto &operand : I.operands()) {
    if (exclude.count(operand)) {
      in_exclude_set = true;
    } else {
      auto ptr = offset_map.find(operand);
      if (ptr == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        if (!in_offset_map) {
          offset = ptr->second;
          in_offset_map = true;
        } else {
          if (ptr->second != offset) {
            // bail if the offsets don't match
            return VisitResult::Error;
          }
        }
      }
    }
  }
  if (in_offset_map && in_exclude_set) {
    // fail if some operands are excluded and others are state offsets
    return VisitResult::Error;
  } else if (in_offset_map) {
    LOG(INFO) << "offsetting: " << LLVMThingToString(&I);
    offset_map.insert({&I, offset});
  } else if (in_exclude_set) {
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    exclude.insert(&I);
  }
  return VisitResult::Progress;
}

// Return the scope of the given instruction.
llvm::MDNode *GetScopeFromInst(llvm::Instruction &I) {
  llvm::AAMDNodes N;
  I.getAAMetadata(N);
  return N.Scope;
}

// Remove all dead stores.
void LiveSetBlockVisitor::RemoveDeadStores(void) {
  for (auto *store : to_remove) {
    store->eraseFromParent();
  }
}

LiveSetBlockVisitor::LiveSetBlockVisitor(const ScopeMap &scope_to_offset_, const llvm::FunctionType *lft_)
  : scope_to_offset(scope_to_offset_),
    curr_wl(),
    next_wl(),
    block_map(),
    to_remove(),
    lft(lft_),
    on_remove_pass(false) {}

// Get every terminating basic block from the function `func`.
void LiveSetBlockVisitor::AddFunction(llvm::Function &func) {
  for (auto &block : func) {
    // The machines rose from the ashes of the nuclear fire....
    if (block.getTerminator()) {
      curr_wl.push_back(&block);
    }
  }
}

// Visit the basic blocks in the worklist and update the block_map.
void LiveSetBlockVisitor::Visit(void) {
  // if any visit makes progress, continue the loop
  while (!curr_wl.empty()) {
    LOG(INFO) << "LSBV: " << curr_wl.size() << " blocks in worklist";
    for (auto block : curr_wl) {
      if (VisitBlock(block)) {
        // Updates have been made; add predecessors to next rotation
        for (llvm::BasicBlock *pred : predecessors(block)) {
          next_wl.push_back(pred);
        }
      }
    }
    // update curr_wl to the next set of insts
    curr_wl.swap(next_wl);
    // reset upcoming insts
    next_wl.clear();
  }
}

bool LiveSetBlockVisitor::VisitBlock(llvm::BasicBlock *B) {
  LiveSet live;
  for (auto inst_it = B->rbegin(); inst_it != B->rend(); ++inst_it) {
    auto inst = &*inst_it;
    if (on_remove_pass) {
      if (llvm::isa<llvm::StoreInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          if (!live.test(scope_to_offset.at(scope))) {
            // Case 1: slot is marked dead by a previous store and we hit a store.
            // (i.e. testing the slot at this offset for liveness returns false)
            // This is a dead store, so we can add it to the chopping block.
            to_remove.insert(inst);
          }
        }
      }
    } else {
      if (llvm::isa<llvm::ReturnInst>(inst) || llvm::isa<llvm::UnreachableInst>(inst) ||
          llvm::isa<llvm::IndirectBrInst>(inst) || llvm::isa<llvm::ResumeInst>(inst) ||
          llvm::isa<llvm::CatchSwitchInst>(inst) || llvm::isa<llvm::CatchReturnInst>(inst) ||
          llvm::isa<llvm::CleanupReturnInst>(inst)) {
        // code that we return to or branch to could read out registers
        // so mark as all live
        live.set();
      } else if (llvm::isa<llvm::BranchInst>(inst) || llvm::isa<llvm::SwitchInst>(inst)) {
        // update live from successors
        for (llvm::BasicBlock *succ : successors(B)) {
          // all successors must be default have been visited first
          // b = U { s | for s in successors(b)}
          live |= block_map[succ];
        }
      } else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(inst)) {
        if (call_inst->getFunctionType() == lft) {
          // mark as all live if called function has the same type as lifted function
          // we're not able to see inside other paths, so we can't predict whether or
          // not the callee might not use any of our slots
          live.set();
        }
      } else if (llvm::isa<llvm::InvokeInst>(inst)) {
        if (call_inst->getFunctionType() == lft) {
          // mark as all live if invoked function has the same type as lifted function
          // we're not able to see inside other paths, so we can't predict whether or
          // not the callee might not use any of our slots
          live.set();
        }
      } else if (llvm::isa<llvm::StoreInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          // Case 2: slot is marked live and we hit a store.
          // We mark that the slot is dead before this store occurs.
          live.reset(scope_to_offset.at(scope));
        }
      } else if (llvm::isa<llvm::LoadInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          // Case 3: slot is loaded from.
          // We mark the slot live here as it was used.
          live.set(scope_to_offset.at(scope));
        }
      }
    }
  }
  if (block_map.count(B)) {
    auto &old_live_on_entry = block_map[B];
    if (old_live_on_entry != live) {
      old_live_on_entry = live;
      return true;
    } else {
      return false;
    }
  } else {
    block_map[B] = live;
    return true;
  }
}

void GenerateLiveSet(llvm::Module *module, const ScopeMap &scopes) {
  auto bb_func = BasicBlockFunction(module);
  //size_t slots = scopes.size();
  for (auto &func : *module) {
    if (&func != bb_func && !func.isDeclaration() &&
        func.getFunctionType() == bb_func->getFunctionType()) {
      LiveSetBlockVisitor LSBV(scopes, bb_func->getFunctionType());
      LSBV.AddFunction(func);
      LSBV.Visit();
      // repeat, but now ready to remove
      LSBV.on_remove_pass = true;
      LSBV.AddFunction(func);
      LSBV.Visit();
      LSBV.RemoveDeadStores();
    }
  }
  return;
}

}  // namespace remill
