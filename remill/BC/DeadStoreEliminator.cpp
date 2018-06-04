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

#include <cstdio>
#include <fstream>
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
  auto state_ptr_type = StatePointerType(module);
  auto type = state_ptr_type->getElementType();
  llvm::DataLayout dl = module->getDataLayout();
  StateVisitor vis(&dl);
  vis.Visit(type);
  CHECK(vis.slots.size() == dl.getTypeAllocSize(type));
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

enum class VisitResult {
  Progress,
  NoProgress,
  Error
};

ForwardAliasVisitor::ForwardAliasVisitor(const std::vector<StateSlot> &state_slots_,
    llvm::DataLayout *dl_,
    llvm::Value *sp_)
  : state_slots(state_slots_),
    offset_map({{sp_, 0}}),
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
  // clear any aametadata
  llvm::AAMDNodes aamd(nullptr, nullptr, nullptr);
  I.setAAMetadata(aamd);
  // get the initial ptr
  auto val = I.getPointerOperand();
  // special case: loading the state ptr
  if (I.getType() == state_ptr->getType()) {
    offset_map.insert({&I, 0});
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
      offset_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I) << " to " << ptr->second;
      return VisitResult::Progress;
    }
  }
}

// Visit a store instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &I) {
  // clear any aametadata
  llvm::AAMDNodes aamd(nullptr, nullptr, nullptr);
  I.setAAMetadata(aamd);
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
      offset_map.insert({&I, ptr->second});
      LOG(INFO) << "aliasing: " << LLVMThingToString(&I) << " to " << ptr->second;
      return VisitResult::Progress;
    }
  }
}

// Visit a GEP instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitGetElementPtrInst(llvm::GetElementPtrInst &I) {
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
        offset_map.emplace(&I, ptr->second + offset.getZExtValue());
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << offset_map[&I];
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
      offset_map.emplace(&I, ptr->second);
      LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << ptr->second;
      return VisitResult::Progress;
    }
  }
}

// Visit an add instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &I) {
  return ForwardAliasVisitor::visitBinaryOp_(I, OpType::Plus);
}

// Visit a sub instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitSub(llvm::BinaryOperator &I) {
  return ForwardAliasVisitor::visitBinaryOp_(I, OpType::Minus);
}

// Get the unsigned offset of two int64_t numbers with bounds checking
bool GetUnsignedOffset(int64_t v1, int64_t v2, OpType op, int64_t max, uint64_t *result) {
  auto signed_result = v1;
  switch (op) {
    case OpType::Plus:
      signed_result += v2;
      break;
    case OpType::Minus:
      signed_result -= v2;
      break;
    default:
      break;
  }
  if (signed_result >= 0 && signed_result < max) {
    *result = static_cast<uint64_t>(signed_result);
    return true;
  } else {
    return false;
  }
}

// Visit an add or sub instruction.
VisitResult ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &I, OpType op) {
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
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr->second), cint1->getSExtValue(), op, static_cast<int64_t>(state_slots.size()), &offset)) {
          return VisitResult::Error;
        }
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << offset;
        return VisitResult::Progress;
      }
    } else if (auto cint2 = llvm::dyn_cast<llvm::ConstantInt>(val2)) {
      auto ptr = offset_map.find(val1);
      if (ptr == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr->second), cint2->getSExtValue(), op, static_cast<int64_t>(state_slots.size()), &offset)) {
          return VisitResult::Error;
        }
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << offset;
        return VisitResult::Progress;
      }
    } else {
      // check if both are in the offset_map
      auto ptr1 = offset_map.find(val1);
      auto ptr2 = offset_map.find(val2);
      if (ptr1 == offset_map.end() || ptr2 == offset_map.end()) {
        return VisitResult::NoProgress;
      } else {
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr1->second), static_cast<int64_t>(ptr2->second), op, static_cast<int64_t>(state_slots.size()), &offset)) {
          return VisitResult::Error;
        }
        offset_map.insert({&I, offset});
        LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << offset;
        return VisitResult::Progress;
      }
    }
  }
}

// Visit a PHI node and update the offset map.
VisitResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &I) {
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
    LOG(INFO) << "offsetting: " << LLVMThingToString(&I) << " to " << offset;
    offset_map.insert({&I, offset});
  } else if (in_exclude_set) {
    LOG(INFO) << "excluding: " << LLVMThingToString(&I);
    exclude.insert(&I);
  }
  return VisitResult::Progress;
}

// For each instruction in the alias map, add an AAMDNodes struct 
// which specifies the aliasing stores and loads to the instruction's byte offset.
void AddAAMDNodes(const ValueToOffset &inst_to_offset, const std::vector<llvm::AAMDNodes> &offset_to_aamd) {
  for (const auto &map_pair : inst_to_offset) {
    auto val = map_pair.first;
    auto offset = map_pair.second;
    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(val)) {
      auto aamd = offset_to_aamd[offset];
      load_inst->setAAMetadata(aamd);
    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(val)) {
      auto aamd = offset_to_aamd[offset];
      store_inst->setAAMetadata(aamd);
    }
  }
}

// Return a map of MDNode scopes and a vector of AAMDNodes based on the given vector of StateSlots,
// where each byte offset (i.e. index) in the slots vector is mapped to a
// corresponding AAMDNodes struct.
AAMDInfo::AAMDInfo(const std::vector<StateSlot> &slots, llvm::LLVMContext &context) {
  // Create a vector of pairs of scopes to slot offsets
  // This will be made into a map at the end of the function
  // We need it as a vector for now so that it is ordered when creating the noalias
  std::vector<std::pair<llvm::MDNode *, uint64_t>> scope_offsets;
  scope_offsets.reserve(slots.size());
  for (const auto &slot : slots) {
    auto mdstr = llvm::MDString::get(context, "slot_" + std::to_string(slot.i));
    scope_offsets.emplace_back(llvm::MDNode::get(context, mdstr), slot.offset);
  }
  std::vector<llvm::AAMDNodes> aamds;
  // One AAMDNodes struct for each byte offset so that we can easily connect them
  aamds.reserve(slots.size());
  for (uint64_t i = 0; i < slots.size(); i++) {
    if (aamds.empty() || slots[i].i != slots[i - 1].i) {
    // noalias all slots != scope
    std::vector<llvm::Metadata *> noalias_vec;
    noalias_vec.reserve(slots.back().i + 1);
    for (uint64_t j = 0; j < slots.size(); j++) {
      if (i != j && (noalias_vec.empty() || scope_offsets[j].first != noalias_vec.back())) {
        noalias_vec.push_back(scope_offsets[j].first);
      }
    }
    llvm::MDNode *noalias = llvm::MDNode::get(context, llvm::MDTuple::get(context, noalias_vec));
    aamds.emplace_back(nullptr, scope_offsets[i].first, noalias);
    } else {
      // copy the last element
      aamds.push_back(aamds.back());
    }
  }
  std::unordered_map<llvm::MDNode *, uint64_t> scopes(scope_offsets.begin(), scope_offsets.end());
  slot_scopes = scopes;
  slot_aamds = aamds;
}

ScopeMap AnalyzeAliases(llvm::Module *module, const std::vector<StateSlot> &slots) {
  const AAMDInfo aamd_info(slots, module->getContext());
  llvm::DataLayout dl = module->getDataLayout();
  auto bb_func = BasicBlockFunction(module);
  for (auto &func : *module) {
    if (&func != bb_func && !func.isDeclaration() &&
        func.getFunctionType() == bb_func->getFunctionType()) {
      auto sp = LoadStatePointer(&func);
      ForwardAliasVisitor fav(slots, &dl, sp);
      for (auto &block : func) {
        for (auto &inst : block) {
          fav.AddInstruction(&inst);
        }
      }
      // if the analysis succeeds for this function, add the AAMDNodes
      if (fav.Analyze()) {
        LOG(INFO) << "Offsets: " << fav.offset_map.size();
        //LOG(INFO) << "Aliases: " << fav.alias_map.size();
        LOG(INFO) << "Excluded: " << fav.exclude.size();
        AddAAMDNodes(fav.offset_map, aamd_info.slot_aamds);
      }
    }
  }
  return aamd_info.slot_scopes;
}

// Return the scope of the given instruction.
llvm::MDNode *GetScopeFromInst(llvm::Instruction &I) {
  llvm::AAMDNodes N;
  I.getAAMetadata(N);
  return N.Scope;
}

LiveSetBlockVisitor::LiveSetBlockVisitor(llvm::Function &func_,
    const std::vector<StateSlot> &state_slots_,
    const ScopeMap &scope_to_offset_,
    const llvm::FunctionType *lifted_func_ty_)
  : func(func_),
    scope_to_offset(scope_to_offset_),
    state_slots(state_slots_),
    curr_wl(),
    next_wl(),
    block_map(),
    to_remove(),
    lifted_func_ty(lifted_func_ty_),
    func_used(),
    on_remove_pass(false) {
      for (auto &block_it : func) {
        auto block = &block_it;
        auto succ_block_it = successors(block);
        if (succ_block_it.begin() == succ_block_it.end()) {
          curr_wl.push_back(block);
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
        // Updates have been made
        // Add predecessors to next rotation
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
  bool removed_something = false;
  for (auto inst_it = B->rbegin(); inst_it != B->rend(); ++inst_it) {
    auto inst = &*inst_it;
    if (on_remove_pass) {
      if (llvm::isa<llvm::StoreInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          if (!live.test(state_slots[scope_to_offset.at(scope)].i)) {
            // Case 1: slot is marked dead by a previous store and we hit a store.
            // (i.e. testing the slot at this offset for liveness returns false)
            // This is a dead store, so we can add it to the chopping block.
            //TODO(tim): get size of stored to check if full/partial
            to_remove.insert(inst);
            removed_something = true;
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
        if (call_inst->getFunctionType() == lifted_func_ty) {
          // mark as all live if called function has the same type as lifted function
          // we're not able to see inside other paths, so we can't predict whether or
          // not the callee might not use any of our slots
          live.set();
        }
      } else if (llvm::isa<llvm::InvokeInst>(inst)) {
        if (call_inst->getFunctionType() == lifted_func_ty) {
          // mark as all live if invoked function has the same type as lifted function
          // we're not able to see inside other paths, so we can't predict whether or
          // not the callee might not use any of our slots
          live.set();
        }
      } else if (llvm::isa<llvm::StoreInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          // Case 2: slot is marked live and we hit a store.
          // We mark that the slot is dead before this store occurs.
          live.reset(state_slots[scope_to_offset.at(scope)].i);
          // Mark that we have accessed this slot
          func_used.set(state_slots[scope_to_offset.at(scope)].i);
        }
      } else if (llvm::isa<llvm::LoadInst>(inst)) {
        if (auto scope = GetScopeFromInst(*inst)) {
          // Case 3: slot is loaded from.
          // We mark the slot live here as it was used.
          live.set(state_slots[scope_to_offset.at(scope)].i);
          // Mark that we have accessed this slot
          func_used.set(state_slots[scope_to_offset.at(scope)].i);
        }
      }
    }
  }
  if (on_remove_pass) {
    // when removing, return that progress was made when we find something to remove
    return removed_something;
  } else {
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
}

// Remove all dead stores.
void LiveSetBlockVisitor::RemoveDeadStores(void) {
  for (auto *store : to_remove) {
    //auto bb = store->getParent();
    LOG(INFO) << "Deleting store " << LLVMThingToString(store);
    //for (auto inst_it = bb->begin(); inst_it != bb->end(); ++inst_it) {
      //auto inst = &*inst_it;
      //if (inst == store) {
        //LOG(INFO) << "**" << LLVMThingToString(inst) << "**";
      //} else {
        //LOG(INFO) << LLVMThingToString(inst);
      //}
    //}
    store->eraseFromParent();
  }
}

// Generate a DOT digraph file representing the dataflow of the LSBV.
void LiveSetBlockVisitor::CreateDOTDigraph(const llvm::DataLayout *dl) {
  DOT() << "digraph " << func.getName().str() << " {\n" << "node [shape=record]\n";
  for (auto &block_live : block_map) {
    auto block = block_live.first;
    auto blive = block_live.second;
    // top row: entry liveset
    DOT() << "b" << reinterpret_cast<uintptr_t>(block) << " [label=<<table>\n";
    DOT() << "<tr><td colspan=\"3\">";
    // print out live slots
    for (uint64_t i = 0; i < blive.size(); i++) {
      if (func_used.test(i) && blive.test(i)) {
        DOT() << i << " ";
      }
    }
    DOT() << "</td></tr>\n";
    for (auto &inst : *block) {
      DOT() << "<tr><td>";
      if (auto scope = GetScopeFromInst(inst)) {
        auto stateslot = state_slots[scope_to_offset.at(scope)];
        auto inst_size = 0;
        if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(load_inst->getType());
        } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(store_inst->getOperand(0)->getType());
        }
        // slot #
        DOT() << "slot " << stateslot.i
          // slot size minus load/store size
          << "</td><td>" << (stateslot.size - inst_size) << "</td><td>";
      } else {
        DOT() << "</td><td></td><td>";
      }
      // instruction text
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        // calls can be quite wide, so we don't present the whole instruction
        DOT() << "call " << call_inst->getFunction()->getName().str();
      } else {
        DOT() << LLVMThingToString(&inst);
      }
      DOT() << "</td></tr>\n";
    }
    // last row: exit liveset
    LiveSet exit_live = blive;
    for (auto succ_block_it : successors(block)) {
      auto succ = &*succ_block_it;
      exit_live |= block_map[succ];
    }
    DOT() << "<tr><td colspan=\"3\">";
    // print out live slots
    for (uint64_t i = 0; i < exit_live.size(); i++) {
      if (func_used.test(i) && exit_live.test(i)) {
        DOT() << i << " ";
      }
    }
    DOT() << "</td></tr>\n";
    DOT() << "</table>>];\n";
    for (auto succ_block_it : successors(block)) {
      auto succ = &*succ_block_it;
      DOT() << "b" << reinterpret_cast<uintptr_t>(block) << " -> b"
        << reinterpret_cast<uintptr_t>(succ) << "\n";
    }
  }
  DOT() << "}\n" << std::endl;
}

static std::ostream &DOT(void) {
  static std::ofstream out("/tmp/out.dot");
  return out;
}

void GenerateLiveSet(llvm::Module *module, const std::vector<StateSlot> &state_slots, const ScopeMap &scopes) {
  auto bb_func = BasicBlockFunction(module);
  auto dl = module->getDataLayout();
  for (auto &func : *module) {
    if (&func != bb_func && !func.isDeclaration() &&
        func.getFunctionType() == bb_func->getFunctionType()) {
      LiveSetBlockVisitor LSBV(func, state_slots, scopes, bb_func->getFunctionType());
      LSBV.Visit();
      // repeat, but now ready to remove
      // FIXME: readd function blocks
      //LSBV.on_remove_pass = true;
      //LSBV.Visit();
      //LSBV.RemoveDeadStores();
      LSBV.CreateDOTDigraph(&dl);
      break;
    }
  }
  return;
}

}  // namespace remill
