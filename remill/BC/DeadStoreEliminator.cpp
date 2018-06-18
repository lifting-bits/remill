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
#include "remill/BC/Compat/Local.h"

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
    : index(i_),
      offset(offset_),
      size(size_) {}

StateVisitor::StateVisitor(llvm::DataLayout *dl_)
    : slots(),
      index(0),
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
        slots.emplace_back(index, offset, len);
      }
      // update StateVisitor fields
      index++;
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
      slots.emplace_back(index, offset, len);
    }
    // update StateVisitor fields
    index++;
    offset += len;
  }
}

enum class VisitResult {
  Progress,
  NoProgress,
  Error
};

enum class OpType {
  Plus,
  Minus,
};

// Get the unsigned offset of two int64_t numbers with bounds checking
static bool GetUnsignedOffset(int64_t v1, int64_t v2, OpType op, int64_t max, uint64_t *result) {
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

ForwardAliasVisitor::ForwardAliasVisitor(
    const std::vector<StateSlot> &state_slots_, llvm::DataLayout *dl_, llvm::Value *sp_)
    : state_slots(state_slots_),
      state_offset({{sp_, 0}}),
      state_access_offset(),
      exclude(),
      curr_wl(),
      state_ptr(sp_),
      dl(dl_) {}

void ForwardAliasVisitor::AddInstruction(llvm::Instruction *inst) {
  curr_wl.insert(inst);
}

// Iterate through the current worklist, updating the state_offset and state_access_offset
// according to the instructions in the list. Any instruction that is not
// currently interpretable (some of its pointers are not yet in the state_offset)
// is withheld to the next analysis round in the next worklist.
// Analysis repeats until the current worklist is empty.
bool ForwardAliasVisitor::Analyze(void) {
  bool progress = true;
  std::unordered_set<llvm::Instruction *> next_wl;
  // if any visit makes progress, continue the loop
  while (!curr_wl.empty() && progress) {
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
  exclude.insert(&I);
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
    state_offset.emplace(&I, 0);
    return VisitResult::Progress;
  } else if (exclude.count(val)) {
    exclude.insert(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = state_offset.find(val);
    if (ptr == state_offset.end()) {
      return VisitResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      // we can also exclude the instruction
      exclude.insert(&I);
      state_access_offset.emplace(&I, ptr->second);
      return VisitResult::Progress;
    }
  }
}

// Visit a store instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &I) {
  // clear any aametadata
  llvm::AAMDNodes aamd(nullptr, nullptr, nullptr);
  I.setAAMetadata(aamd);
  // if the store is using a state pointer, fail immediately
  if (state_offset.count(I.getOperand(0))) {
    return VisitResult::Error;
  }
  // get the initial ptr
  auto val = I.getPointerOperand();
  if (exclude.count(val)) {
    exclude.insert(&I);
    return VisitResult::Progress;
  } else {
    auto ptr = state_offset.find(val);
    if (ptr == state_offset.end()) {
      return VisitResult::NoProgress;
    } else {
      // loads mean we now have an alias to the pointer
      state_access_offset.emplace(&I, ptr->second);
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
    return VisitResult::Progress;
  } else {
    auto ptr = state_offset.find(val);
    if (ptr == state_offset.end()) {
      // no pointer found
      return VisitResult::NoProgress;
    } else {
      // get the constant offset
      llvm::APInt const_offset(64, 0);
      if (I.accumulateConstantOffset(*dl, const_offset)) {
        // the final offset (adding the ptr->second value to the const_offset)
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr->second),
              const_offset.getSExtValue(), OpType::Plus, static_cast<int64_t>(state_slots.size()), &offset)) {
          LOG(WARNING) << "Out of bounds GEP operation: " << LLVMThingToString(&I);
          return VisitResult::Error;
        }
        state_offset.emplace(&I, offset);
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
    return VisitResult::Progress;
  } else {
    auto ptr = state_offset.find(val);
    if (ptr == state_offset.end()) {
      return VisitResult::NoProgress;
    } else {
      // update value
      state_offset.emplace(&I, ptr->second);
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

// Visit an add or sub instruction.
VisitResult ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &I, OpType op) {
  auto val1 = I.getOperand(0);
  auto val2 = I.getOperand(1);
  if (exclude.count(val1) || exclude.count(val2)) {
    exclude.insert(&I);
    return VisitResult::Progress;
  } else {
    // FIXME(tim): is there a way to make this code more succinct and avoid duplication?
    if (auto cint1 = llvm::dyn_cast<llvm::ConstantInt>(val1)) {
      auto ptr = state_offset.find(val2);
      if (ptr == state_offset.end()) {
        return VisitResult::NoProgress;
      } else {
        uint64_t offset = 0;
        if (!GetUnsignedOffset(cint1->getSExtValue(), static_cast<int64_t>(ptr->second),
              op, static_cast<int64_t>(state_slots.size()), &offset)) {
          LOG(WARNING) << "Out of bounds " << (op == OpType::Plus ? "add " : "sub ")
            << "operation: " << LLVMThingToString(&I);
          return VisitResult::Error;
        }
        state_offset.emplace(&I, offset);
        return VisitResult::Progress;
      }
    } else if (auto cint2 = llvm::dyn_cast<llvm::ConstantInt>(val2)) {
      auto ptr = state_offset.find(val1);
      if (ptr == state_offset.end()) {
        return VisitResult::NoProgress;
      } else {
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr->second), cint2->getSExtValue(),
              op, static_cast<int64_t>(state_slots.size()), &offset)) {
          LOG(WARNING) << "Out of bounds " << (op == OpType::Plus ? "add " : "sub ")
            << "operation: " << LLVMThingToString(&I);
          return VisitResult::Error;
        }
        state_offset.emplace(&I, offset);
        return VisitResult::Progress;
      }
    } else {
      // check if both are in the state_offset
      auto ptr1 = state_offset.find(val1);
      auto ptr2 = state_offset.find(val2);
      if (ptr1 == state_offset.end() || ptr2 == state_offset.end()) {
        return VisitResult::NoProgress;
      } else {
        uint64_t offset = 0;
        if (!GetUnsignedOffset(static_cast<int64_t>(ptr1->second),
              static_cast<int64_t>(ptr2->second), op, static_cast<int64_t>(state_slots.size()), &offset)) {
          LOG(WARNING) << "Out of bounds " << (op == OpType::Plus ? "add " : "sub ")
            << "operation: " << LLVMThingToString(&I);
          return VisitResult::Error;
        }
        state_offset.emplace(&I, offset);
        return VisitResult::Progress;
      }
    }
  }
}

// Visit a select instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitSelect(llvm::SelectInst &I) {
  auto true_val = I.getTrueValue();
  auto false_val = I.getFalseValue();
  auto true_ptr = state_offset.find(true_val);
  auto false_ptr = state_offset.find(false_val);
  auto in_exclude_set = exclude.count(true_val) || exclude.count(false_val);
  auto in_state_offset = true_ptr != state_offset.end() || false_ptr != state_offset.end();
  if (in_state_offset && in_exclude_set) {
    // fail if the two values are inconsistent
    return VisitResult::Error;
  } else if (in_state_offset) {
    if (true_ptr == state_offset.end()) {
      uint64_t offset = false_ptr->second;
      state_offset.emplace(&I, offset);
      return VisitResult::NoProgress;
    } else if (false_ptr == state_offset.end()) {
      uint64_t offset = true_ptr->second;
      state_offset.emplace(&I, offset);
      return VisitResult::NoProgress;
    } else {
      // both have values
      if (true_ptr->second == false_ptr->second) {
        uint64_t offset = true_ptr->second;
        state_offset.emplace(&I, offset);
      } else {
        return VisitResult::Error;
      }
    }
  } else if (in_exclude_set) {
    // if only one is found
    if (exclude.count(true_val) != exclude.count(false_val)) {
        exclude.insert(&I);
        return VisitResult::NoProgress;
    } else {
      exclude.insert(&I);
    }
  }
  return VisitResult::Progress;
}

// Visit a PHI node and update the offset map.
VisitResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &I) {
  // iterate over each operand
  auto complete = true;
  auto in_state_offset = false;
  auto in_exclude_set = false;
  uint64_t offset;
  for (auto &operand : I.operands()) {
    if (exclude.count(operand)) {
      in_exclude_set = true;
    } else {
      auto ptr = state_offset.find(operand);
      if (ptr == state_offset.end()) {
        complete = false;
      } else {
        if (!in_state_offset) {
          offset = ptr->second;
          in_state_offset = true;
        } else {
          if (ptr->second != offset) {
            // bail if the offsets don't match
            return VisitResult::Error;
          }
        }
      }
    }
  }
  if (in_state_offset && in_exclude_set) {
    // fail if some operands are excluded and others are state offsets
    return VisitResult::Error;
  } else if (in_state_offset) {
    state_offset.emplace(&I, offset);
  } else if (in_exclude_set) {
    exclude.insert(&I);
  }
  return (complete ? VisitResult::Progress : VisitResult::NoProgress);
}

// For each instruction in the alias map, add an AAMDNodes struct 
// which specifies the aliasing stores and loads to the instruction's byte offset.
void AddAAMDNodes(const InstToOffset &inst_to_offset, const std::vector<llvm::AAMDNodes> &offset_to_aamd) {
  for (const auto &map_pair : inst_to_offset) {
    auto inst = map_pair.first;
    auto offset = map_pair.second;
    if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
      auto aamd = offset_to_aamd[offset];
      load_inst->setAAMetadata(aamd);
    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
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
    auto mdstr = llvm::MDString::get(context, "slot_" + std::to_string(slot.index));
    scope_offsets.emplace_back(llvm::MDNode::get(context, mdstr), slot.offset);
  }
  std::vector<llvm::AAMDNodes> aamds;
  // One AAMDNodes struct for each byte offset so that we can easily connect them
  aamds.reserve(slots.size());
  for (uint64_t i = 0; i < slots.size(); i++) {
    if (aamds.empty() || slots[i].index != slots[i - 1].index) {
    // noalias all slots != scope
    std::vector<llvm::Metadata *> noalias_vec;
    noalias_vec.reserve(slots.back().index + 1);
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

void AnalyzeAliases(llvm::Module *module, const std::vector<StateSlot> &slots) {
  const AAMDInfo aamd_info(slots, module->getContext());
  llvm::DataLayout dl = module->getDataLayout();
  auto bb_func = BasicBlockFunction(module);
  for (auto &func : *module) {
    if (&func != bb_func && !func.isDeclaration() &&
        func.getFunctionType() == bb_func->getFunctionType()) {
      auto sp = LoadStatePointer(&func);
      ForwardAliasVisitor fav(slots, &dl, sp);
      DLOG(INFO) << "Analyzing aliases of func " << func.getName().str();
      for (auto &block : func) {
        for (auto &inst : block) {
          fav.AddInstruction(&inst);
        }
      }
      // if the analysis succeeds for this function, add the AAMDNodes
      if (fav.Analyze()) {
        DLOG(INFO) << "Offsets: " << fav.state_offset.size();
        DLOG(INFO) << "Aliases: " << fav.state_access_offset.size();
        DLOG(INFO) << "Excluded: " << fav.exclude.size();
        AddAAMDNodes(fav.state_access_offset, aamd_info.slot_aamds);
        ForwardingBlockVisitor FBV(func, fav.state_offset,
            aamd_info.slot_scopes, slots, &dl);
        FBV.Visit();
        // Perform live set analysis
        LiveSetBlockVisitor LSBV(func, slots, aamd_info.slot_scopes,
            fav.state_offset, bb_func->getFunctionType(), &dl);
        LSBV.Visit();
        LSBV.PerformRemovePass(true);
        LSBV.DeleteDeadInsts();
      }
    }
  }
}

// Return the scope of the given instruction.
llvm::MDNode *GetScopeFromInst(llvm::Instruction &I) {
  llvm::AAMDNodes N;
  I.getAAMetadata(N);
  return N.Scope;
}

LiveSetBlockVisitor::LiveSetBlockVisitor(
    llvm::Function &func_, const std::vector<StateSlot> &state_slots_,
    const ScopeToOffset &scope_to_offset_, const ValueToOffset &val_to_offset_,
    const llvm::FunctionType *lifted_func_ty_, const llvm::DataLayout *dl_)
    : func(func_),
      val_to_offset(val_to_offset_),
      scope_to_offset(scope_to_offset_),
      state_slots(state_slots_),
      curr_wl(),
      block_map(),
      to_remove(),
      lifted_func_ty(lifted_func_ty_),
      func_used(),
      on_remove_pass(false),
      dl(dl_) {
        for (auto &block : func) {
          auto succ_block_it = successors(&block);
          if (succ_block_it.begin() == succ_block_it.end()) {
            curr_wl.push_back(&block);
          }
        }
      }

// Visit the basic blocks in the worklist and update the block_map.
void LiveSetBlockVisitor::Visit(void) {
  // if any visit makes progress, continue the loop
  std::vector<llvm::BasicBlock *> next_wl;
  while (!curr_wl.empty()) {
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
  for (auto inst_it = B->rbegin(); inst_it != B->rend(); ++inst_it) {
    auto inst = &*inst_it;
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
      for (auto &arg_it : call_inst->arg_operands()) {
        auto arg = arg_it->stripPointerCasts();
        if (val_to_offset.count(arg)) {
          auto offset = val_to_offset.at(arg);
          if (offset != 0) {
            // if we access a single non-zero offset, mark just that offset
            live.set(state_slots[offset].index);
          } else {
            live.set();
          }
        }
      }
    } else if (auto invoke_inst = llvm::dyn_cast<llvm::InvokeInst>(inst)) {
      for (auto &arg_it : invoke_inst->arg_operands()) {
        auto arg = arg_it->stripPointerCasts();
        if (val_to_offset.count(arg)) {
          auto offset = val_to_offset.at(arg);
          if (offset != 0) {
            // if we access a single non-zero offset, mark just that offset
            live.set(state_slots[offset].index);
          } else {
            live.set();
          }
        }
      }
    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
      if (auto scope = GetScopeFromInst(*inst)) {
        auto inst_size = dl->getTypeAllocSize(store_inst->getOperand(0)->getType());
        auto &state_slot = state_slots[scope_to_offset.at(scope)];
        if (!live.test(state_slot.index)) {
          if (on_remove_pass) {
            to_remove.push_back(inst);
          }
        } else if (inst_size < state_slot.size) {
          // Partial stores revive the slot.
          live.set(state_slot.index);
        } else {
          // Full stores kill the slot.
          live.reset(state_slot.index);
        }
        // Mark that we have accessed this slot
        func_used.set(state_slot.index);
      }
    } else if (llvm::isa<llvm::LoadInst>(inst)) {
      if (auto scope = GetScopeFromInst(*inst)) {
        auto slot_num = state_slots[scope_to_offset.at(scope)].index;
        // Loads revive the slot.
        live.set(slot_num);
        // Mark that we have accessed this slot
        func_used.set(slot_num);
      }
    }
  }
  auto &old_live_on_entry = block_map[B];
  if (old_live_on_entry != live) {
    old_live_on_entry = live;
    return true;
  } else {
    return false;
  }
}

void LiveSetBlockVisitor::PerformRemovePass(bool create_dot = true) {
  on_remove_pass = true;
  for (auto &block_it : func) {
    auto block = &block_it;
    VisitBlock(block);
  }
  if (create_dot) {
    CreateDOTDigraph();
  }
  on_remove_pass = false;
}

// Remove all dead stores.
bool LiveSetBlockVisitor::DeleteDeadInsts(void) {
  bool changed = false;
  while (!to_remove.empty()) {
    auto inst = to_remove.back();
    to_remove.pop_back();

    //if (auto *alloc_inst = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
      //for (auto *dbg_info_intrinsic : llvm::FindDbgAddrUses(alloc_inst)) {
        //dbg_info_intrinsic->eraseFromParent();
      //}
    //}

    inst->replaceAllUsesWith(llvm::UndefValue::get(inst->getType()));

    for (auto &operand : inst->operands()) {
      if (auto op_inst = llvm::dyn_cast<llvm::Instruction>(operand)) {
        operand = nullptr;
        if (llvm::isInstructionTriviallyDead(op_inst)) {
          to_remove.push_back(op_inst);
        }
      }
    }
    inst->eraseFromParent();
    changed = true;
  }
  return changed;
}

// Generate a DOT digraph file representing the dataflow of the LSBV.
void LiveSetBlockVisitor::CreateDOTDigraph(void) {
  auto f = func.getName().str();
  std::ostringstream fname;
  fname << "/tmp/out_" << f << ".dot";
  std::ofstream dot(fname.str());
  dot << "digraph " << f << " {\n" << "node [shape=none margin=0 nojustify=false labeljust=l]\n";
  for (auto &block_live : block_map) {
    auto block = block_live.first;
    auto blive = block_live.second;
    // top row: entry liveset
    dot << "b" << reinterpret_cast<uintptr_t>(block) << " [label=<<table cellspacing=\"0\">\n";
    dot << "<tr><td align=\"left\" colspan=\"3\">";
    // print out live slots
    auto sep = "live: ";
    for (uint64_t i = 0; i < blive.size(); i++) {
      if (func_used.test(i) && blive.test(i)) {
        dot << sep << i;
        sep = ", ";
      }
    }
    dot << "</td></tr>\n";
    for (auto &inst : *block) {
      dot << "<tr><td align=\"left\">";
      if (auto scope = GetScopeFromInst(inst)) {
        auto stateslot = state_slots[scope_to_offset.at(scope)];
        auto inst_size = 0;
        if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(load_inst->getType());
        } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(store_inst->getOperand(0)->getType());
        }
        // slot #
        dot << "slot " << stateslot.index
          // slot size minus load/store size
          << "</td><td align=\"left\">" << (stateslot.size - inst_size)
          << "</td>";
      } else {
        dot << "</td><td></td>";
      }
      // instruction text
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        // calls can be quite wide, so we don't present the whole instruction
        dot << "<td align=\"left\">call " << call_inst->getCalledValue()->getName().str();
      } else if (llvm::isa<llvm::PHINode>(&inst)) {
        dot << "<td align=\"left\">phi";
      } else {
        llvm::AAMDNodes blank(nullptr, nullptr, nullptr);
        llvm::MDNode *tbaa = inst.getMetadata(llvm::LLVMContext::MD_tbaa);
        llvm::MDNode *scope = inst.getMetadata(llvm::LLVMContext::MD_alias_scope);
        llvm::MDNode *noalias = inst.getMetadata(llvm::LLVMContext::MD_noalias);
        llvm::AAMDNodes original(tbaa, scope, noalias);
        inst.setAAMetadata(blank);
        if (std::count(to_remove.begin(), to_remove.end(), &inst)) {
          // highlight
          dot << "<td align=\"left\" bgcolor=\"red\">" << LLVMThingToString(&inst);
        } else {
          dot << "<td align=\"left\">" << LLVMThingToString(&inst);
        }
        inst.setAAMetadata(original);
      }
      dot << "</td></tr>\n";
    }
    // last row: exit liveset
    LiveSet exit_live;
    for (auto succ_block_it : successors(block)) {
      auto succ = &*succ_block_it;
      exit_live |= block_map[succ];
    }
    dot << "<tr><td colspan=\"3\">";
    // print out live slots
    sep = "live: ";
    for (uint64_t i = 0; i < exit_live.size(); i++) {
      if (func_used.test(i) && exit_live.test(i)) {
        dot << sep << i;
        sep = ", ";
      }
    }
    dot << "</td></tr>\n";
    dot << "</table>>];\n";
    for (auto succ_block_it : successors(block)) {
      auto succ = &*succ_block_it;
      dot << "b" << reinterpret_cast<uintptr_t>(block) << " -> b"
        << reinterpret_cast<uintptr_t>(succ) << "\n";
    }
  }
  dot << "}\n" << std::endl;
}

ForwardingBlockVisitor::ForwardingBlockVisitor(
    llvm::Function &func_,
    const ValueToOffset &val_to_offset_,
    const ScopeToOffset &scope_to_offset_,
    const std::vector<StateSlot> &state_slots_,
    const llvm::DataLayout *dl_)
    : func(func_),
      val_to_offset(val_to_offset_),
      scope_to_offset(scope_to_offset_),
      state_slots(state_slots_),
      dl(dl_) {}

void ForwardingBlockVisitor::Visit(void) {
  // if any visit makes progress, continue the loop
  for (auto &block : func) {
    VisitBlock(&block);
  }
}

void ForwardingBlockVisitor::VisitBlock(llvm::BasicBlock *B) {
  std::unordered_map<StateSlot *, llvm::LoadInst *> slot_to_load;
  for (auto inst_it = B->rbegin(); inst_it != B->rend(); ++inst_it) {
    auto inst = &*inst_it;
    if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
      if (auto scope = GetScopeFromInst(*inst)) {
        auto inst_size = dl->getTypeAllocSize(store_inst->getOperand(0)->getType());
        auto state_slot = state_slots[scope_to_offset.at(scope)];
        if (slot_to_load.count(&state_slot)) {
          auto next = slot_to_load[&state_slot];
          auto next_size = dl->getTypeAllocSize(next->getType());
          if (val_to_offset.at(store_inst) == val_to_offset.at(next)) {
            if (next_size < inst_size) {
              auto trunc = new llvm::TruncInst(store_inst->getOperand(0), next->getType(), "", next);
              next->replaceAllUsesWith(trunc);
            } else if (next_size == inst_size) {
              next->replaceAllUsesWith(store_inst->getOperand(0));
            }
          }
        }
      }
    } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
      if (auto scope = GetScopeFromInst(*load_inst)) {
        auto inst_size = dl->getTypeAllocSize(load_inst->getType());
        auto state_slot = state_slots[scope_to_offset.at(scope)];
        if (slot_to_load.count(&state_slot)) {
          auto next = slot_to_load[&state_slot];
          auto next_size = dl->getTypeAllocSize(next->getType());
          if (val_to_offset.at(load_inst) == val_to_offset.at(next)) {
            if (next_size < inst_size) {
              auto trunc = new llvm::TruncInst(load_inst, next->getType(), "", next);
              next->replaceAllUsesWith(trunc);
            } else if (next_size == inst_size) {
              next->replaceAllUsesWith(load_inst);
            }
          }
        } else {
          slot_to_load.emplace(&state_slot, load_inst);
        }
      }
    }
  }
}

// Identify complete stores to slots that are subsequently accessed by loads
// and then used, and perform store-to-load forwarding to condense this series of
// statements from:
//  a complete store to %Y of %X
//  a load to %Z from %Y
//  a series of statements using %Z
// to:
//  a series of statements using %X
void ForwardStoresToLoads(void) {
}



}  // namespace remill
