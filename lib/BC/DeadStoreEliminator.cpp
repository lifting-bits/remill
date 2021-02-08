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

#include "remill/BC/DeadStoreEliminator.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Local.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/CallSite.h"
#include "remill/BC/Compat/VectorType.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

DEFINE_string(dot_output_dir, "",
              "The directory in which to log DOT digraphs of the alias "
              "analysis information derived during the process of "
              "eliminating dead stores.");

DEFINE_bool(disable_dead_store_elimination, false,
            "Whether or not to perform dead store elimination on stores into"
            "the State structure.");

DEFINE_bool(disable_register_forwarding, false,
            "Whether or not register forwarding should be enabled "
            "to perform load-to-load and load-to-store forwarding "
            "to eliminate dead instructions more aggressively.");

DEFINE_bool(log_dse_stats, false,
            "Log out statistics about how effective the DSE pass is.");

DEFINE_bool(name_register_variables, false,
            "Try to apply a register's name to its GEP variable.");

namespace remill {
namespace {

static constexpr size_t kMaxNumSlots = 256;

using ValueToOffset = std::unordered_map<llvm::Value *, uint64_t>;
using InstToOffset = std::unordered_map<llvm::Instruction *, uint64_t>;
using LiveSet = std::bitset<kMaxNumSlots>;

// TODO(pag): Map to `LiveSet` pointers. The common cases are:
//            - all set
//            - none set
//            - one set
using InstToLiveSet = std::unordered_map<llvm::Instruction *, LiveSet>;

// Struct to keep track of how murderous the dead store eliminator is.
struct KillCounter {
  uint64_t failed_funcs;
  uint64_t num_stores;
  uint64_t dead_stores;
  uint64_t removed_insts;
  uint64_t fwd_loads;
  uint64_t fwd_stores;
  uint64_t fwd_perfect;
  uint64_t fwd_truncated;
  uint64_t fwd_casted;
  uint64_t fwd_reordered;
  uint64_t fwd_failed;
};

// Return true if the given function is a lifted function
// (and not the `__remill_basic_block`).
static bool IsLiftedFunction(llvm::Function *func,
                             const llvm::Function *bb_func) {
  return !(func == bb_func || func->isDeclaration() ||
           func->getFunctionType() != bb_func->getFunctionType());
}

// Recursive visitor of the `State` structure that assigns slots of ranges of
// bytes.
class StateVisitor {
 public:
  StateVisitor(llvm::DataLayout *dl_, uint64_t num_bytes);

  // Visit a type and record it (and any children) in the slots vector
  void Visit(llvm::Type *ty);

  template <typename T>
  void VisitSequentialType(T *seq_ty);

  std::vector<StateSlot> offset_to_slot;

  // The current index in the state structure.
  uint64_t index;

  // The current offset in the state structure.
  uint64_t offset;

 private:
  // Used for calculating type allocation size.
  llvm::DataLayout *dl;
};

StateVisitor::StateVisitor(llvm::DataLayout *dl_, uint64_t num_bytes)
    : offset_to_slot(),
      index(0),
      offset(0),
      dl(dl_) {
  offset_to_slot.reserve(num_bytes);
}

// Update the `StateVisitor`s slots field to hold a StateSlot for every byte
// offset into the state. The `StateSlot` element is the same across each byte
// offset that is within the element's begin offset and end offset.
void StateVisitor::Visit(llvm::Type *ty) {
  if (!ty) {  // TODO(tim): Is this even possible?
    LOG(FATAL) << "NULL type in `State` structure.";
  }

  uint64_t num_bytes = dl->getTypeAllocSize(ty);
  CHECK_EQ(num_bytes, dl->getTypeStoreSize(ty))
      << "Alignment of type induces additional padding: "
      << LLVMThingToString(ty);

  const auto prev_offset = offset;

  // Structure, class, or union.
  if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(ty)) {
    auto layout = dl->getStructLayout(struct_ty);
    auto num_elems = struct_ty->getNumElements();
    for (auto i = 0U; i < num_elems; ++i) {
      const auto elem_offset = prev_offset + layout->getElementOffset(i);
      const auto elem_ty = struct_ty->getElementType(i);

      if (elem_offset != offset) {
        LOG(ERROR) << "Element " << i << " of type "
                   << LLVMThingToString(elem_ty) << " in "
                   << LLVMThingToString(ty) << " has padding";
        CHECK_LT(offset, elem_offset);
        for (auto j = offset; j < elem_offset; ++j) {
          offset_to_slot.emplace_back(~0u, ~0u, ~0u);
        }
        offset = elem_offset;
      }
      Visit(elem_ty);
      CHECK_EQ(offset, elem_offset + dl->getTypeAllocSize(elem_ty))
          << "Unexpected offset after visiting element " << i << " of type "
          << LLVMThingToString(elem_ty) << " in " << LLVMThingToString(ty);
    }

    //    LOG_IF(FATAL, layout->hasPadding())
    //        << "State structure type, or embedded type, has internal padding: "
    //        << LLVMThingToString(struct_ty);

  // Array or vector.
  } else if (auto fvt_ty = llvm::dyn_cast<llvm::FixedVectorType>(ty)) {
    VisitSequentialType(fvt_ty);

  } else if (auto arr_ty = llvm::dyn_cast<llvm::ArrayType>(ty)) {
    VisitSequentialType(arr_ty);

  // Primitive type.
  } else if (ty->isIntegerTy() || ty->isFloatingPointTy() ||
             ty->isPointerTy()) {
    for (uint64_t i = 0; i < num_bytes; i++) {
      offset_to_slot.emplace_back(index, offset, num_bytes);
    }
    index++;
    offset += num_bytes;

  } else {
    LOG(FATAL) << "Unexpected type `" << LLVMThingToString(ty)
               << "` in state structure";
  }

  CHECK_EQ(offset, prev_offset + num_bytes);
}

template <typename T>
void StateVisitor::VisitSequentialType(T *seq_ty) {
  uint64_t num_bytes = dl->getTypeAllocSize(seq_ty);
  auto first_ty = seq_ty->getElementType();
  uint64_t el_num_bytes = dl->getTypeAllocSize(first_ty);
  CHECK_EQ(el_num_bytes, dl->getTypeStoreSize(first_ty))
      << "Alignment of type induces additional padding: "
      << LLVMThingToString(first_ty);

  // Special case: sequences of primitive types (or vectors thereof) are
  // treated as one slot.
  if (first_ty->isIntegerTy() || first_ty->isFloatingPointTy()) {
    for (uint64_t i = 0; i < num_bytes; i++) {
      offset_to_slot.emplace_back(index, offset, num_bytes);
    }
    index++;
    offset += num_bytes;

  // This is an array of non-primitive types.
  } else {
    auto num_elems = num_bytes / el_num_bytes;
    for (uint64_t i = 0; i < num_elems; i++) {

      // NOTE(tim): Recalculates every time, rather than memoizing.
      Visit(first_ty);
    }
  }
}

// Try to get the offset associated with some value.
static bool TryGetOffset(llvm::Value *val, const ValueToOffset &state_offset,
                         uint64_t *offset_out) {
  auto ptr = state_offset.find(val);
  if (ptr != state_offset.end()) {
    *offset_out = ptr->second;
    return true;

  } else {
    return false;
  }
}

// Try to get the offset associated with some value, or if the value is
// a constant integer, get that instead.
static bool TryGetOffsetOrConst(llvm::Value *val,
                                const ValueToOffset &state_offset,
                                uint64_t *offset_out) {
  if (auto const_val = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    const auto &val_apint = const_val->getValue();
    if (val_apint.getMinSignedBits() <= 64) {
      *offset_out = static_cast<uint64_t>(const_val->getSExtValue());
      return true;
    } else {
      LOG(WARNING) << "Unable to fit offset from "
                   << remill::LLVMThingToString(val)
                   << " into a 64-bit signed integer";
      return false;
    }
  } else {
    return TryGetOffset(val, state_offset, offset_out);
  }
}

enum class VisitResult : int {
  Progress,
  NoProgress,
  Incomplete,
  Ignored,
  Error
};

enum class OpType : int {
  Plus,
  Minus,
};

// Add or subtract `lhs_offset` and `rhs_offset`, and do bounds checking.
static bool TryCombineOffsets(uint64_t lhs_offset, OpType op_type,
                              uint64_t rhs_offset, uint64_t max_offset,
                              uint64_t *out_offset) {
  int64_t signed_result = 0;
  switch (op_type) {
    case OpType::Plus:
      signed_result =
          static_cast<int64_t>(lhs_offset) + static_cast<int64_t>(rhs_offset);
      break;

    case OpType::Minus:
      signed_result =
          static_cast<int64_t>(lhs_offset) - static_cast<int64_t>(rhs_offset);
      break;
  }

  *out_offset = static_cast<uint64_t>(signed_result);
  return (*out_offset) < max_offset;
}

static LiveSet GetLiveSetFromArgs(llvm::iterator_range<llvm::Use *> args,
                                  const ValueToOffset &val_to_offset,
                                  const std::vector<StateSlot> &state_slots) {
  LiveSet live;
  live.reset();
  for (auto &arg_it : args) {
    auto arg = arg_it->stripPointerCasts();
    const auto offset_it = val_to_offset.find(arg);
    if (offset_it == val_to_offset.end()) {
      continue;
    }
    const auto offset = offset_it->second;

    // If we access a single non-zero offset, mark just that offset.
    if (offset != 0) {
      live.set(state_slots[offset].index);

    // If we access offset `0`, then maybe we're actually passing
    // a state pointer, in which anything can be changed, so we want
    // to treat everything as live, OR maybe we're passing a pointer
    // to the first thing in the `State` structure, which would be
    // rare and unusual.
    //
    // Typically this case is hit when we have a call to another lifted
    // function.
    } else {
      live.set();
      break;
    }
  }
  return live;
}

// Visits instructions and propagates information about where in the
// `State` structure a given instruction might reference.
struct ForwardAliasVisitor
    : public llvm::InstVisitor<ForwardAliasVisitor, VisitResult> {
 public:
  virtual ~ForwardAliasVisitor(void) = default;

  ForwardAliasVisitor(const llvm::DataLayout &dl_,
                      const std::vector<StateSlot> &offset_to_slot_,
                      InstToLiveSet &live_args_,
                      InstToOffset &state_access_offset_,
                      llvm::LLVMContext &context);

  bool Analyze(const remill::Arch *arch, KillCounter &stats,
               llvm::Function *func);

 protected:
  friend class llvm::InstVisitor<ForwardAliasVisitor, VisitResult>;

  virtual VisitResult visitInstruction(llvm::Instruction &I);
  virtual VisitResult visitAllocaInst(llvm::AllocaInst &I);
  virtual VisitResult visitLoadInst(llvm::LoadInst &inst);
  virtual VisitResult visitStoreInst(llvm::StoreInst &inst);
  virtual VisitResult visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  virtual VisitResult visitCastInst(llvm::CastInst &inst);
  virtual VisitResult visitAdd(llvm::BinaryOperator &inst);
  virtual VisitResult visitSub(llvm::BinaryOperator &I);
  virtual VisitResult visitSelect(llvm::SelectInst &inst);
  virtual VisitResult visitPHINode(llvm::PHINode &I);
  virtual VisitResult visitCallInst(llvm::CallInst &inst);
  virtual VisitResult visitInvokeInst(llvm::InvokeInst &inst);

 public:
  // Generate a DOT digraph file representing the offsets.
  void CreateDOTDigraph(const remill::Arch *arch, llvm::Function *func,
                        const char *extension);

 private:
  void AddInstruction(llvm::Instruction *inst);
  virtual VisitResult visitBinaryOp_(llvm::BinaryOperator &inst, OpType op);

 public:
  const llvm::DataLayout dl;
  const std::vector<StateSlot> &offset_to_slot;
  ValueToOffset state_offset;
  InstToOffset &state_access_offset;
  InstToLiveSet &live_args;
  std::unordered_set<llvm::Value *> exclude;
  std::unordered_set<llvm::Value *> missing;
  std::vector<llvm::Instruction *> curr_wl;
  std::vector<llvm::Instruction *> pending_wl;
  std::vector<llvm::Instruction *> calls;
  llvm::Value *state_ptr;
  unsigned reg_md_id;
};

// Stream a slot of the DOT digraph.
static void StreamSlot(const remill::Arch *arch, llvm::LLVMContext &context,
                       std::ostream &dot, const StateSlot &slot,
                       uint64_t access_size) {
  if (auto reg = arch->RegisterAtStateOffset(slot.offset)) {
    auto enc_reg = reg->EnclosingRegisterOfSize(access_size);
    if (!enc_reg) {
      enc_reg = reg->EnclosingRegister();
    }
    dot << enc_reg->name;
  } else {
    dot << slot.index;
  }
}

// Stream a `call` or `invoke` instruction to DOT.
static void StreamCallOrInvokeToDOT(std::ostream &dot,
                                    llvm::Instruction &inst) {
  if (!inst.getType()->isVoidTy()) {
    dot << "%" << inst.getName().str() << " = ";
  }

  if (auto cs = compat::llvm::CallSite(&inst)) {
    if (cs.isInvoke()) {
      dot << "invoke ";
    } else if (cs.isCall()) {
      dot << "call";
    } else {
      LOG(ERROR) << "Encountered callsite that is not call nor invoke!";
    }

    if (!cs.getCalledValue()->getName().empty()) {
      dot << cs.getCalledValue()->getName().str();
    } else {
      dot << cs.getCalledValue()->getValueID();
    }
  }
}

// Stream a PHI node to the DOT digraph.
static void StreamPHIToDOT(std::ostream &dot, llvm::PHINode &phi_node) {
  dot << "%" << phi_node.getName().str();
  auto sep = " = phi ";
  for (auto i = 0U; i < phi_node.getNumIncomingValues(); ++i) {
    auto val = phi_node.getIncomingValue(i);
    if (auto inst_val = llvm::dyn_cast<llvm::Instruction>(val)) {
      dot << sep << "%" << inst_val->getName().str();
    } else {
      dot << sep << "...";
    }
    sep = ", ";
  }
}

// Generate a DOT digraph file representing the offsets.
void ForwardAliasVisitor::CreateDOTDigraph(const remill::Arch *arch,
                                           llvm::Function *func,
                                           const char *extension) {
  auto &context = func->getContext();
  std::stringstream fname;
  fname << FLAGS_dot_output_dir << PathSeparator();
  if (!func->hasName()) {
    fname << "func_" << std::hex << reinterpret_cast<uintptr_t>(&func);
  } else {
    fname << func->getName().str();
  }
  fname << extension;

  std::ofstream dot(fname.str());
  dot << "digraph {" << std::endl
      << "node [shape=none margin=0 nojustify=false labeljust=l]" << std::endl;

  // Stream node information for each block.
  for (auto &block_ref : *func) {
    auto block = &block_ref;

    dot << "b" << reinterpret_cast<uintptr_t>(block)
        << " [label=<<table cellspacing=\"0\">" << std::endl;

    dot << "<tr><td>offset</td><td>slot</td><td>inst</td></tr>" << std::endl;

    // Then print out one row per instruction.
    for (auto &inst : *block) {

      dot << "<tr>";
      if (state_offset.count(&inst)) {
        auto offset = state_offset[&inst];
        dot << "<td>" << offset << "</td><td> </td>";

      } else if (state_access_offset.count(&inst)) {
        auto offset = state_access_offset[&inst];
        const auto &slot = offset_to_slot[offset];
        auto inst_size = 0;
        if (llvm::isa<llvm::LoadInst>(&inst)) {
          inst_size = dl.getTypeAllocSize(inst.getType());
        } else if (llvm::isa<llvm::StoreInst>(&inst)) {
          inst_size = dl.getTypeAllocSize(inst.getOperand(0)->getType());
        } else {
          LOG(FATAL) << "Instruction " << LLVMThingToString(&inst)
                     << " has scope meta-data";
        }
        dot << "<td>" << offset << "</td><td>";
        StreamSlot(arch, context, dot, slot, inst_size);
        dot << "</td>";

      } else if (exclude.count(&inst)) {
        dot << "<td>----</td><td> </td>";
      } else {
        dot << "<td> </td><td> </td>";
      }

      // Highlight nodes in yellow that remain in the pending work list.
      if (std::count(pending_wl.begin(), pending_wl.end(), &inst)) {
        if (missing.count(&inst)) {
          dot << "<td align=\"left\" bgcolor=\"red\">";
        } else {
          dot << "<td align=\"left\" bgcolor=\"yellow\">";
        }
      } else if (missing.count(&inst)) {
        dot << "<td align=\"left\" bgcolor=\"orange\">";

      } else {
        dot << "<td align=\"left\">";
      }

      // Calls can be quite wide, so we don't present the whole instruction.
      if (llvm::isa<llvm::CallInst>(&inst) ||
          llvm::isa<llvm::InvokeInst>(&inst)) {
        dot << "  ";

        StreamCallOrInvokeToDOT(dot, inst);

      // PHI nodes can also be quite wide (with the incoming block names)
      // so we compress those as well.
      } else if (auto phi_node = llvm::dyn_cast<llvm::PHINode>(&inst)) {
        dot << "  ";
        StreamPHIToDOT(dot, *phi_node);

      } else {
        dot << LLVMThingToString(&inst);
      }
      dot << "</td></tr>" << std::endl;
    }

    dot << "</table>>];" << std::endl;

    // Arrows to successor blocks.
    auto succ_begin_it = llvm::succ_begin(block);
    auto succ_end_it = llvm::succ_end(block);
    for (; succ_begin_it != succ_end_it; succ_begin_it++) {
      auto succ = *succ_begin_it;
      dot << "b" << reinterpret_cast<uintptr_t>(block) << " -> b"
          << reinterpret_cast<uintptr_t>(succ) << std::endl;
    }
  }
  dot << "}" << std::endl;
}

ForwardAliasVisitor::ForwardAliasVisitor(
    const llvm::DataLayout &dl_, const std::vector<StateSlot> &offset_to_slot_,
    InstToLiveSet &live_args_, InstToOffset &state_access_offset_,
    llvm::LLVMContext &context)
    : dl(dl_),
      offset_to_slot(offset_to_slot_),
      state_access_offset(state_access_offset_),
      live_args(live_args_),
      state_ptr(nullptr),
      reg_md_id(context.getMDKindID("remill_register")) {}

void ForwardAliasVisitor::AddInstruction(llvm::Instruction *inst) {

  if (!inst->getMetadata(reg_md_id)) {
    if (FLAGS_dot_output_dir.empty()) {
      inst->setName(llvm::Twine::createNull());
    } else {
      static int r = static_cast<int>(remill::kNumBlockArgs);
      if (!inst->getType()->isVoidTy()) {
        inst->setName("r" + std::to_string(r++));
      }
    }
  }

  if (llvm::isa<llvm::StoreInst>(inst)) {
    curr_wl.push_back(inst);

  } else if (llvm::isa<llvm::LoadInst>(inst)) {
    curr_wl.push_back(inst);

  // TODO(pag): What about `alloca`d `State` structures? Would need to adjust
  //            how the FAV handles code without the typical prototype.
  } else if (llvm::isa<llvm::AllocaInst>(inst)) {
    exclude.emplace(inst);

  } else if (llvm::isa<llvm::CallInst>(inst) ||
             llvm::isa<llvm::InvokeInst>(inst)) {
    exclude.emplace(inst);
    calls.push_back(inst);

  } else {
    curr_wl.push_back(inst);
  }
}

// Iterate through the current worklist, updating the `state_offset` and
// `state_access_offset` according to the instructions in the list. Any
// instruction that is not currently interpretable (some of its pointers
// are not yet in `state_offset`) is withheld to the next analysis round
// in the next worklist. Analysis repeats until the current worklist is
// empty or until an error condition is hit.
bool ForwardAliasVisitor::Analyze(const remill::Arch *arch, KillCounter &stats,
                                  llvm::Function *func) {
  curr_wl.clear();
  exclude.clear();
  calls.clear();
  state_offset.clear();
  pending_wl.clear();

  std::vector<llvm::Instruction *> order_of_progress;

  state_ptr = LoadStatePointer(func);
  auto memory_ptr = LoadMemoryPointerArg(func);
  auto pc = LoadProgramCounterArg(func);
  if (!state_ptr || !memory_ptr || !pc) {
    LOG(ERROR) << "Not analyzing " << func->getName().str()
               << " for dead loads or stores";
    return false;
  }

  state_offset.emplace(state_ptr, 0);
  exclude.emplace(memory_ptr);
  exclude.emplace(pc);

  for (auto &block : *func) {
    for (auto &inst : block) {
      AddInstruction(&inst);
    }
  }

  std::vector<llvm::Instruction *> next_wl;
  const auto num_insts = curr_wl.size();
  next_wl.reserve(num_insts);
  order_of_progress.reserve(num_insts);

  bool progress = true;

  while (!curr_wl.empty() && progress) {
    missing.clear();
    progress = false;

    const auto old_exclude_count = exclude.size();

    // Visit most instructions; this doesn't visit calls.
    for (auto inst : curr_wl) {
      switch (visit(inst)) {
        case VisitResult::Progress:
          order_of_progress.push_back(inst);
          progress = true;
          break;
        case VisitResult::Incomplete: pending_wl.push_back(inst); break;
        case VisitResult::NoProgress: next_wl.push_back(inst); break;
        case VisitResult::Ignored: break;
        case VisitResult::Error: return false;
      }
    }

    progress = progress || old_exclude_count < exclude.size();
    curr_wl.swap(pending_wl);
    curr_wl.insert(curr_wl.end(), next_wl.begin(), next_wl.end());
    next_wl.clear();
    pending_wl.clear();
  }

  order_of_progress.insert(order_of_progress.end(), curr_wl.begin(),
                           curr_wl.end());

  CHECK(num_insts == order_of_progress.size());

  pending_wl.clear();
  next_wl.clear();
  missing.clear();
  curr_wl.clear();

  // Do one final pass through, in the order in which progress was made.
  for (auto inst : order_of_progress) {
    switch (visit(inst)) {
      case VisitResult::Progress: break;
      case VisitResult::Incomplete: pending_wl.push_back(inst); break;
      case VisitResult::NoProgress: next_wl.push_back(inst); break;
      case VisitResult::Ignored: break;
      case VisitResult::Error: return false;
    }
  }

  // Calls are processed after everything else so that any pointer arguments
  // passed into the calls, e.g. for read-modify-write memory intrinsics that
  // update the state directly, can be mapped back to their state slots.
  for (auto inst : calls) {
    visit(inst);
  }

  // TODO(tim): This condition is triggered a lot.
  //
  // One place where this happens is when there is a `select` to choose
  // what index into an array to use.
  if (!pending_wl.empty()) {
    stats.failed_funcs++;

    DLOG(WARNING) << "Alias analysis failed to complete on function `"
                  << func->getName().str() << "` with " << next_wl.size()
                  << " instructions in the worklist and " << pending_wl.size()
                  << " incomplete but no progress made in the last"
                  << " iteration";
  }

  auto &context = func->getContext();
  for (auto [val, offset] : state_offset) {
    const auto inst = llvm::dyn_cast<llvm::Instruction>(val);
    if (!inst) {
      continue;
    }

    const auto val_type = inst->getType();
    if (!val_type->isPointerTy()) {
      continue;
    }
    auto reg = arch->RegisterAtStateOffset(offset);
    if (!reg) {
      continue;
    }

    const auto el_size = dl.getTypeAllocSize(val_type->getPointerElementType());
    if (auto parent_reg = reg->EnclosingRegisterOfSize(el_size)) {
      reg = parent_reg;
    }

    if (FLAGS_name_register_variables) {
      inst->setName(reg->name + "_ptr");
    }

    // Create the node for a `remill_register` annotation if it's missing.
    if (!inst->getMetadata(reg_md_id)) {
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
      auto reg_name_md = llvm::ValueAsMetadata::get(reg->constant_name);
      auto reg_name_node = llvm::MDNode::get(context, reg_name_md);
#else
      auto reg_name_node = llvm::MDNode::get(*context, reg.constant_name);
#endif
      inst->setMetadata(reg_md_id, reg_name_node);
    }
  }

  if (FLAGS_name_register_variables) {
    for (auto &block : *func) {
      for (auto &inst : block) {
        if (!llvm::isa<llvm::LoadInst>(&inst)) {
          continue;
        }

        auto offset_it = state_access_offset.find(&inst);
        if (offset_it == state_access_offset.end()) {
          continue;
        }

        const auto val_type = inst.getType();
        auto reg = arch->RegisterAtStateOffset(offset_it->second);
        if (!reg) {
          continue;
        }

        const auto el_size = dl.getTypeAllocSize(val_type);
        if (auto parent_reg = reg->EnclosingRegisterOfSize(el_size)) {
          reg = parent_reg;
        }

        inst.setName(reg->name + '_');
      }
    }
  }

  return true;
}

VisitResult ForwardAliasVisitor::visitInstruction(llvm::Instruction &I) {
  exclude.insert(&I);
  return VisitResult::Progress;
}

VisitResult ForwardAliasVisitor::visitAllocaInst(llvm::AllocaInst &I) {
  exclude.insert(&I);
  return VisitResult::Progress;
}

// Visit a load instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitLoadInst(llvm::LoadInst &inst) {
  auto val = inst.getPointerOperand();

  // Special case: loaded value is itself a `State` pointer. Not sure if
  // this ever comes up, but if it does then we want to treat all `State`
  // structures as aliasing.
  if (inst.getType() == state_ptr->getType()) {
    state_offset.emplace(&inst, 0);
    return VisitResult::Progress;

  } else if (exclude.count(val)) {
    exclude.emplace(&inst);
    return VisitResult::Progress;

  } else {
    auto ptr = state_offset.find(val);
    if (ptr == state_offset.end()) {
      return VisitResult::NoProgress;

    // The `State` structure doesn't contain pointers, so loaded values
    // should not be used to index elsewhere into `State`. Technically,
    // this could happen where an index into a vector register is stored
    // in another register. We don't handle that yet.
    } else {
      state_access_offset.emplace(&inst, ptr->second);
      exclude.emplace(&inst);
      return VisitResult::Progress;
    }
  }
}

// Visit a `store` instruction and update the alias map.
VisitResult ForwardAliasVisitor::visitStoreInst(llvm::StoreInst &inst) {

  // If we're storing a pointer into the `State` structure into the `State`
  // structure then just bail out because that shouldn't even be possible
  // and is not allowed by the Remill design.
  if (state_offset.count(inst.getOperand(0))) {
    return VisitResult::Error;
  }

  auto addr = inst.getPointerOperand();
  if (exclude.count(addr)) {
    exclude.insert(&inst);
    return VisitResult::Progress;
  }

  auto ptr = state_offset.find(addr);
  if (ptr == state_offset.end()) {
    return VisitResult::NoProgress;
  }

  // loads mean we now have an alias to the pointer
  state_access_offset.emplace(&inst, ptr->second);
  return VisitResult::Progress;
}

// Visit a `getelementptr` (GEP) instruction and update the offset map.
VisitResult
ForwardAliasVisitor::visitGetElementPtrInst(llvm::GetElementPtrInst &inst) {

  auto val = inst.getPointerOperand();

  if (exclude.count(val)) {
    exclude.insert(&inst);
    return VisitResult::Progress;
  }

  auto ptr = state_offset.find(val);
  if (ptr == state_offset.end()) {
    return VisitResult::NoProgress;
  }

  // Try to get the offset as a single constant. If we can't then
  llvm::APInt const_offset(dl.getPointerSizeInBits(0), 0, true);
  if (!inst.accumulateConstantOffset(dl, const_offset)) {
    return VisitResult::Error;
  }

  // the final offset (adding the ptr->second value to the const_offset)
  uint64_t offset = 0;
  if (!TryCombineOffsets(ptr->second, OpType::Plus,
                         static_cast<uint64_t>(const_offset.getSExtValue()),
                         offset_to_slot.size(), &offset)) {

    LOG(WARNING) << "Out of bounds GEP operation: " << LLVMThingToString(&inst)
                 << " on base " << LLVMThingToString(val)
                 << " with inferred offset " << static_cast<int64_t>(offset)
                 << " (" << ptr->second << " + " << const_offset.getSExtValue()
                 << ")"
                 << " and max allowed offset of " << offset_to_slot.size();
    return VisitResult::Error;
  }

  state_offset.emplace(&inst, offset);
  return VisitResult::Progress;
}

// Visit a cast instruction and update the offset map. This could be
// a `bitcast`, `inttoptr`, `ptrtoint`, etc.
VisitResult ForwardAliasVisitor::visitCastInst(llvm::CastInst &inst) {
  auto addr = inst.getOperand(0);
  if (exclude.count(addr)) {
    exclude.insert(&inst);
    return VisitResult::Progress;
  }

  auto ptr = state_offset.find(addr);
  if (ptr == state_offset.end()) {
    return VisitResult::NoProgress;

  } else {
    state_offset.emplace(&inst, ptr->second);
    return VisitResult::Progress;
  }
}

// Visit an `add` instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitAdd(llvm::BinaryOperator &inst) {
  return ForwardAliasVisitor::visitBinaryOp_(inst, OpType::Plus);
}

// Visit a `sub` instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitSub(llvm::BinaryOperator &inst) {
  return ForwardAliasVisitor::visitBinaryOp_(inst, OpType::Minus);
}

// Visit an `add` or `sub` instruction.
VisitResult ForwardAliasVisitor::visitBinaryOp_(llvm::BinaryOperator &inst,
                                                OpType op) {

  auto lhs_val = inst.getOperand(0);
  auto rhs_val = inst.getOperand(1);
  auto num_excluded = 0;
  auto num_offsets = 0;
  auto num_consts = 0;
  uint64_t lhs_offset = 0;
  uint64_t rhs_offset = 0;
  auto ret = VisitResult::NoProgress;

  if (exclude.count(lhs_val)) {
    num_excluded += 1;

  } else if (TryGetOffsetOrConst(lhs_val, state_offset, &lhs_offset)) {
    if (llvm::isa<llvm::Constant>(lhs_val)) {
      num_consts += 1;
    } else {
      num_offsets += 1;
    }

  // It's a constant that isn't an integer, e.g. a costant expression on a
  // global.
  } else if (llvm::isa<llvm::Constant>(lhs_val)) {
    exclude.emplace(lhs_val);
    num_excluded += 1;

  } else {
    if (!FLAGS_dot_output_dir.empty()) {
      missing.emplace(lhs_val);
    }
    ret = VisitResult::Incomplete;
  }

  if (exclude.count(rhs_val)) {
    num_excluded += 1;

  } else if (TryGetOffsetOrConst(rhs_val, state_offset, &rhs_offset)) {
    if (llvm::isa<llvm::Constant>(rhs_val)) {
      num_consts += 1;
    } else {
      num_offsets += 1;
    }

  // It's a constant that isn't an integer, e.g. a costant expression on a
  // global.
  } else if (llvm::isa<llvm::Constant>(rhs_val)) {
    exclude.emplace(lhs_val);
    num_excluded += 1;

  } else {
    if (!FLAGS_dot_output_dir.empty()) {
      missing.emplace(rhs_val);
    }
    ret = VisitResult::Incomplete;
  }

  if (num_excluded) {
    exclude.emplace(&inst);
    if (2 <= (num_offsets + num_excluded + num_consts)) {
      return VisitResult::Progress;
    } else {
      ret = VisitResult::Incomplete;
    }
  }

  if (2 == num_offsets) {
    LOG(WARNING) << "Adding or subtracting two state-pointer derived pointers";
    return VisitResult::Error;

  } else if (2 == (num_offsets + num_consts)) {
    uint64_t offset = 0;
    if (!TryCombineOffsets(lhs_offset, op, rhs_offset, offset_to_slot.size(),
                           &offset)) {
      LOG(WARNING) << "Out of bounds operation `" << LLVMThingToString(&inst)
                   << "` with LHS offset " << static_cast<int64_t>(lhs_offset)
                   << ", RHS offset " << static_cast<int64_t>(rhs_offset)
                   << ", combined offset " << static_cast<int64_t>(offset)
                   << ", and max allowed offset of " << offset_to_slot.size();
      return VisitResult::Error;
    }

    state_offset.emplace(&inst, offset);
    return VisitResult::Progress;

  } else if (2 == (num_offsets + num_excluded)) {
    return VisitResult::Progress;

  } else {
    return ret;
  }
}

// Visit a `select` instruction and update the offset map.
VisitResult ForwardAliasVisitor::visitSelect(llvm::SelectInst &inst) {
  auto true_val = inst.getTrueValue();
  auto false_val = inst.getFalseValue();
  auto true_ptr = state_offset.find(true_val);
  auto false_ptr = state_offset.find(false_val);
  auto in_exclude_set = exclude.count(true_val) || exclude.count(false_val);
  auto in_state_offset =
      true_ptr != state_offset.end() || false_ptr != state_offset.end();

  // Fail if the two values are inconsistent.
  if (in_state_offset && in_exclude_set) {
    return VisitResult::Error;

  // At least one of the selected values points into `State`.
  } else if (in_state_offset) {
    if (true_ptr == state_offset.end()) {
      if (!FLAGS_dot_output_dir.empty()) {
        missing.emplace(true_val);
      }
      state_offset.emplace(&inst, false_ptr->second);
      return VisitResult::Incomplete;  // Wait for the other to be found.

    } else if (false_ptr == state_offset.end()) {
      if (!FLAGS_dot_output_dir.empty()) {
        missing.emplace(false_val);
      }
      state_offset.emplace(&inst, true_ptr->second);
      return VisitResult::Incomplete;  // Wait for the other to be found.

    // Both point into `State`.
    } else {
      if (true_ptr->second == false_ptr->second) {
        state_offset.emplace(&inst, true_ptr->second);
        return VisitResult::Progress;

      } else {
        return VisitResult::Error;
      }
    }

  // At least one of the values being selected definitely does not point
  // into the `State` structure.
  } else if (in_exclude_set) {
    exclude.insert(&inst);
    if (exclude.count(true_val) != exclude.count(false_val)) {
      return VisitResult::Incomplete;  // Wait for the other to be found.

    } else {
      return VisitResult::Progress;
    }

  // One or both values are constant.
  } else if (llvm::isa<llvm::Constant>(true_val) ||
             llvm::isa<llvm::Constant>(false_val)) {
    exclude.emplace(&inst);
    return VisitResult::Progress;

  // The status of the values being selected are as-of-yet unknown.
  } else {
    return VisitResult::NoProgress;
  }
}

// Visit a PHI node and update the offset map. We unconditionally visit
// all incoming values in PHI nodes, and repeatedly do so until every
// such value is resolved, so that we can make sure that there are no
// inconsistencies.
VisitResult ForwardAliasVisitor::visitPHINode(llvm::PHINode &inst) {
  auto num_in_state_offset = 0U;
  auto num_in_exclude_set = 0U;
  auto num_consts = 0U;
  auto num_vals = inst.getNumIncomingValues();
  uint64_t offset = 0;

  for (unsigned i = 0; i < num_vals; ++i) {
    auto operand = inst.getIncomingValue(i);
    if (exclude.count(operand)) {
      num_in_exclude_set += 1;
      continue;

    } else if (llvm::isa<llvm::Constant>(operand)) {
      num_consts += 1;
      continue;
    }

    auto ptr = state_offset.find(operand);

    // The status of the incoming value is unknown, so we can't yet mark
    // handling this PHI as being complete.
    if (ptr == state_offset.end()) {
      if (!FLAGS_dot_output_dir.empty()) {
        missing.emplace(operand);
      }
      continue;
    }

    num_in_state_offset += 1;

    // This is the first incoming value that points into `State`.
    if (1 == num_in_state_offset) {
      offset = ptr->second;

    // This is the Nth incoming value that points into `State`, let's
    // make sure that it aggrees with the others.
    } else if (ptr->second != offset) {
      return VisitResult::Error;
    }
  }

  auto complete =
      (num_in_state_offset + num_in_exclude_set + num_consts) == num_vals;

  // Fail if some operands are excluded and others are state offsets.
  if (num_in_state_offset && num_in_exclude_set) {
    return VisitResult::Error;

  // At least one incoming value is a `State` offset, so opportunistically
  // assume that all will match. This lets us have the algorithm progress
  // in the presence of loops.
  } else if (num_in_state_offset) {
    state_offset.emplace(&inst, offset);
    return (complete ? VisitResult::Progress : VisitResult::Incomplete);

  // Similar case to above, but at least one thing is in the exclude set.
  } else if (num_in_exclude_set || num_consts) {
    exclude.insert(&inst);
    return (complete ? VisitResult::Progress : VisitResult::Incomplete);

  } else {
    return VisitResult::NoProgress;
  }
}

VisitResult ForwardAliasVisitor::visitCallInst(llvm::CallInst &inst) {

  //const auto val = inst.getCalledOperand()->stripPointerCasts();
  const auto val =
      compat::llvm::CallSite(&inst).getCalledValue()->stripPointerCasts();
  if (auto const_val = llvm::dyn_cast<llvm::Constant>(val); const_val) {

    // Don't let this affect anything.
    if (auto func = llvm::dyn_cast<llvm::Function>(const_val); func) {
      if (func->hasFnAttribute(llvm::Attribute::ReadNone) ||
          func->hasFnAttribute(llvm::Attribute::ReadOnly)) {
        live_args[&inst].reset();
        return VisitResult::Ignored;
      }
    }

    const auto name = const_val->getName();
    if (name.startswith("__remill_restore.") ||
        name.startswith("__remill_kill.") ||
        name.startswith("__remill_barrier_") ||
        name.startswith("__remill_atomic_") ||
        name.startswith("__remill_delay_slot_") ||
        name.startswith("__remill_read_memory_") ||
        name.startswith("__remill_write_memory_") ||
        name == "__remill_fpu_exception_test_and_clear" ||
        name == "__mcsema_pc_tracer" || name == "__mcsema_reg_tracer" ||
        name == "__mcsema_printf") {

      // Don't let this affect anything.
      live_args[&inst].reset();
      return VisitResult::Ignored;

    } else if (name.startswith("__mcsema")) {
      live_args[&inst].set();
      return VisitResult::Ignored;
    }

  // Don't let this affect anything.
  } else if (llvm::isa<llvm::InlineAsm>(val)) {
    live_args[&inst].reset();
    return VisitResult::Ignored;

  // It's an indirect call.
  } else {
    live_args[&inst].set();
    return VisitResult::Ignored;
  }

  // If we have not seen this instruction before, add it.
  auto args = inst.arg_operands();
  auto live = GetLiveSetFromArgs(args, state_offset, offset_to_slot);
  live_args.emplace(&inst, std::move(live));
  return VisitResult::Ignored;
}

VisitResult ForwardAliasVisitor::visitInvokeInst(llvm::InvokeInst &inst) {
  auto val =
      compat::llvm::CallSite(&inst).getCalledValue()->stripPointerCasts();
  if (llvm::isa<llvm::InlineAsm>(val)) {
    live_args[&inst].set();  // Weird to invoke inline assembly.

  } else if (auto func = llvm::dyn_cast<llvm::Constant>(val);
             func && func->getName().startswith("__mcsema")) {
    live_args[&inst].set();

  // If we have not seen this instruction before, add it.
  } else {
    auto args = inst.arg_operands();
    auto live = GetLiveSetFromArgs(args, state_offset, offset_to_slot);
    live_args.emplace(&inst, std::move(live));
  }
  return VisitResult::Ignored;
}

class LiveSetBlockVisitor {
 public:
  llvm::Module &module;
  InstToLiveSet debug_live_args_at_call;
  const InstToLiveSet &live_args;
  InstToOffset &state_access_offset;
  const std::vector<StateSlot> &offset_to_slot;
  std::vector<llvm::BasicBlock *> curr_wl;
  std::unordered_map<llvm::BasicBlock *, LiveSet> block_map;
  std::vector<llvm::Instruction *> to_remove;
  const llvm::Function *bb_func;

  LiveSetBlockVisitor(llvm::Module &module_, const InstToLiveSet &live_args_,
                      InstToOffset &state_access_offset_,
                      const std::vector<StateSlot> &state_slots_,
                      const llvm::Function *bb_func_,
                      const llvm::DataLayout *dl_);

  void FindLiveInsts(KillCounter &stats);
  void CollectDeadInsts(KillCounter &stats);
  bool VisitBlock(llvm::BasicBlock *block, KillCounter &stats);
  bool DeleteDeadInsts(KillCounter &stats);
  void CreateDOTDigraph(const remill::Arch *, llvm::Function *func,
                        const char *extensions);

 private:
  bool on_remove_pass;
  const llvm::DataLayout *dl;
};

LiveSetBlockVisitor::LiveSetBlockVisitor(
    llvm::Module &module_, const InstToLiveSet &live_args_,
    InstToOffset &state_access_offset_,
    const std::vector<StateSlot> &state_slots_, const llvm::Function *bb_func_,
    const llvm::DataLayout *dl_)
    : module(module_),
      live_args(live_args_),
      state_access_offset(state_access_offset_),
      offset_to_slot(state_slots_),
      curr_wl(),
      block_map(),
      to_remove(),
      bb_func(bb_func_),
      on_remove_pass(false),
      dl(dl_) {
  for (auto &func : module) {
    for (auto &block : func) {
      auto succ_begin_it = llvm::succ_begin(&block);
      auto succ_end_it = llvm::succ_end(&block);
      if (succ_begin_it == succ_end_it) {
        curr_wl.push_back(&block);
      }
    }
  }
}

// Visit the basic blocks in the worklist and update the block_map.
void LiveSetBlockVisitor::FindLiveInsts(KillCounter &stats) {
  std::vector<llvm::BasicBlock *> next_wl;
  while (!curr_wl.empty()) {
    for (auto block : curr_wl) {

      // If we change the live slots state of the block, then add the
      // block's predecessors to the next work list.
      if (VisitBlock(block, stats)) {
        int num_preds = 0;
        auto pred_it = llvm::pred_begin(block);
        auto pred_end = llvm::pred_end(block);
        for (; pred_it != pred_end; ++pred_it) {
          auto pred = *pred_it;
          next_wl.push_back(pred);
          num_preds++;
        }

        // If we've visited an entry block, add its callers to the
        // next work list.
        if (!num_preds) {
          auto func = block->getParent();
          for (auto user : func->users()) {
            if (auto inst = llvm::dyn_cast<llvm::Instruction>(user)) {
              if (llvm::isa<llvm::CallInst>(inst) ||
                  llvm::isa<llvm::InvokeInst>(inst)) {
                next_wl.push_back(inst->getParent());
              }
            }
          }
        }
      }
    }

    curr_wl.swap(next_wl);
    next_wl.clear();
  }
}

bool LiveSetBlockVisitor::VisitBlock(llvm::BasicBlock *block,
                                     KillCounter &stats) {
  LiveSet live;

  for (auto inst_it = block->rbegin(); inst_it != block->rend(); ++inst_it) {
    auto inst = &*inst_it;

    // Code that we return to or branch to could read out registers
    // so mark as all live.
    if (llvm::isa<llvm::ReturnInst>(inst) ||
        llvm::isa<llvm::UnreachableInst>(inst) ||
        llvm::isa<llvm::IndirectBrInst>(inst) ||
        llvm::isa<llvm::ResumeInst>(inst)) {
      live.set();

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 8)
    } else if (llvm::isa<llvm::CatchSwitchInst>(inst) ||
               llvm::isa<llvm::CatchReturnInst>(inst) ||
               llvm::isa<llvm::CatchPadInst>(inst) ||
               llvm::isa<llvm::CleanupPadInst>(inst) ||
               llvm::isa<llvm::CleanupReturnInst>(inst)) {
      live.set();
#endif

    // Update the live set from the successors. If a successors has not
    // been visited yet then we will inherit an empty live set. This is
    // fine because our algorithm converges towards bits being set.
    } else if (llvm::isa<llvm::BranchInst>(inst) ||
               llvm::isa<llvm::SwitchInst>(inst)) {
      auto succ_it = llvm::succ_begin(block);
      auto succ_end = llvm::succ_end(block);
      for (; succ_it != succ_end; succ_it++) {
        auto succ = *succ_it;
        live |= block_map[succ];
      }

    // This could be a call to another lifted function or control-flow
    // intrinsic, or to something that won't access the state like a simple
    // memory intrinsic or LLVM intrinsic (e.g. bswap).
    } else if (llvm::isa<llvm::CallInst>(inst) ||
               llvm::isa<llvm::InvokeInst>(inst)) {

      // Likely due to a more general failure to analyze this particular
      // function.
      auto arg_live_it = live_args.find(inst);
      if (arg_live_it == live_args.end()) {
        live.set();

      } else {
        live |= arg_live_it->second;
      }

    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
      auto offset_ptr = state_access_offset.find(inst);
      if (offset_ptr == state_access_offset.end()) {
        continue;
      }

      if (on_remove_pass) {
        stats.num_stores++;
      }

      auto val = store_inst->getOperand(0);
      auto val_size = dl->getTypeAllocSize(val->getType());
      const auto &state_slot = offset_to_slot[offset_ptr->second];
      auto slot_num = state_slot.index;

      if (!live.test(slot_num)) {
        if (on_remove_pass) {
          to_remove.push_back(inst);
        }

      // We're storing to all the bytes, so kill it. Ignore partial stores
      // (that would revive it) because it's already marked as live.
      } else if (val_size == state_slot.size) {
        live.reset(slot_num);
      }

    // Loads from slots revive the slots.
    } else if (llvm::isa<llvm::LoadInst>(inst)) {
      auto offset_ptr = state_access_offset.find(inst);
      if (offset_ptr != state_access_offset.end()) {
        auto slot_num = offset_to_slot[offset_ptr->second].index;
        live.set(slot_num);
      }
    }
  }

  auto &old_live_on_entry = block_map[block];
  if (old_live_on_entry != live) {
    old_live_on_entry = live;
    return true;
  } else {
    return false;
  }
}

void LiveSetBlockVisitor::CollectDeadInsts(KillCounter &stats) {
  on_remove_pass = true;
  for (auto &func : module) {
    for (auto &block : func) {
      VisitBlock(&block, stats);
    }
  }
  on_remove_pass = false;
}

// Remove all dead stores.
bool LiveSetBlockVisitor::DeleteDeadInsts(KillCounter &stats) {
  stats.dead_stores += to_remove.size();
  bool changed = false;
  while (!to_remove.empty()) {
    stats.removed_insts++;
    auto inst = to_remove.back();
    to_remove.pop_back();

    if (!inst->getType()->isVoidTy()) {
      inst->replaceAllUsesWith(llvm::UndefValue::get(inst->getType()));
    }

    for (auto &operand : inst->operands()) {
      if (auto op_inst = llvm::dyn_cast<llvm::Instruction>(operand)) {
        operand = nullptr;
        if (llvm::isInstructionTriviallyDead(op_inst)) {
          to_remove.push_back(op_inst);
        }
      }
    }

    inst->eraseFromParent();
    state_access_offset.erase(inst);
    changed = true;
  }
  return changed;
}

// Generate a DOT digraph file representing the dataflow of the LSBV.
void LiveSetBlockVisitor::CreateDOTDigraph(const remill::Arch *arch,
                                           llvm::Function *func,
                                           const char *extension) {
  auto &context = func->getContext();

  std::stringstream fname;
  fname << FLAGS_dot_output_dir << PathSeparator();
  if (!func->hasName()) {
    fname << "func_" << std::hex << reinterpret_cast<uintptr_t>(&func);
  } else {
    fname << func->getName().str();
  }
  fname << extension;

  std::ofstream dot(fname.str());
  dot << "digraph {" << std::endl
      << "node [shape=none margin=0 nojustify=false labeljust=l]" << std::endl;

  // Figure out relevant load/stores to print.
  LiveSet used;
  for (auto &block : *func) {
    for (auto &inst : block) {
      auto offset_ptr = state_access_offset.find(&inst);
      if (offset_ptr != state_access_offset.end()) {
        const auto &slot = offset_to_slot[offset_ptr->second];
        used.set(slot.index);
      }
    }
  }

  // Make a vector so that we can go from slot index to slot.
  std::vector<const StateSlot *> slots;
  slots.resize(offset_to_slot.back().index + 1);
  for (auto &slot : offset_to_slot) {
    if (slot.index < slots.size()) {
      slots[slot.index] = &slot;
    }
  }

  // Stream node information for each block.
  for (auto &block_ref : *func) {
    auto block_live_ptr = block_map.find(&block_ref);
    if (block_live_ptr == block_map.end()) {
      continue;
    }

    auto block = &block_ref;
    const auto &blive = block_live_ptr->second;

    // Figure out the live set on exit from the block.
    LiveSet exit_live;
    int num_succs = 0;
    auto succ_it = llvm::succ_begin(block);
    auto succ_end = llvm::succ_end(block);
    for (; succ_it != succ_end; succ_it++) {
      auto succ = *succ_it;
      exit_live |= block_map[succ];
      num_succs++;
      dot << "b" << reinterpret_cast<uintptr_t>(block) << " -> b"
          << reinterpret_cast<uintptr_t>(succ) << std::endl;
    }

    if (!num_succs) {
      exit_live.set();
    }

    dot << "b" << reinterpret_cast<uintptr_t>(block)
        << " [label=<<table cellspacing=\"0\">" << std::endl;

    // First row, print out the DEAD slots on entry.
    dot << "<tr><td align=\"left\" colspan=\"3\">";
    auto sep = "dead: ";
    for (uint64_t i = 0; i < slots.size(); i++) {
      if (used.test(i) && !blive.test(i) && slots[i]) {
        dot << sep;
        StreamSlot(arch, context, dot, *(slots[i]), slots[i]->size);
        sep = ", ";
      }
    }
    dot << "</td></tr>" << std::endl;

    // Then print out one row per instruction.
    for (auto &inst : *block) {

      // First row, print out the DEAD slots on entry.
      if (debug_live_args_at_call.count(&inst)) {
        const auto &clive = debug_live_args_at_call[&inst];
        dot << "<tr><td align=\"left\" colspan=\"3\">";
        sep = "dead: ";
        for (uint64_t i = 0; i < slots.size(); i++) {
          if (used.test(i) && !clive.test(i)) {
            dot << sep;
            StreamSlot(arch, context, dot, *(slots[i]), slots[i]->size);
            sep = ", ";
          }
        }
        dot << "</td></tr>" << std::endl;
      }

      dot << "<tr><td align=\"left\">";

      auto offset_ptr = state_access_offset.find(&inst);
      if (offset_ptr != state_access_offset.end()) {
        const auto &slot = offset_to_slot[offset_ptr->second];
        auto inst_size = 0;
        if (llvm::isa<llvm::LoadInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(inst.getType());
        } else if (llvm::isa<llvm::StoreInst>(&inst)) {
          inst_size = dl->getTypeAllocSize(inst.getOperand(0)->getType());
        } else {
          LOG(FATAL) << "Instruction " << LLVMThingToString(&inst)
                     << " has scope meta-data";
        }

        StreamSlot(arch, context, dot, slot, inst_size);

        // slot size minus load/store size
        dot << "</td><td align=\"left\">" << (slot.size - inst_size) << "</td>";
      } else {
        dot << "</td><td></td>";
      }

      // Calls can be quite wide, so we don't present the whole instruction.
      if (llvm::isa<llvm::CallInst>(&inst) ||
          llvm::isa<llvm::InvokeInst>(&inst)) {
        dot << "<td align=\"left\">  ";

        StreamCallOrInvokeToDOT(dot, inst);

      // PHI nodes can also be quite wide (with the incoming block names)
      // so we compress those as well.
      } else if (auto phi_node = llvm::dyn_cast<llvm::PHINode>(&inst)) {
        dot << "<td align=\"left\">  ";
        StreamPHIToDOT(dot, *phi_node);

      } else {

        // Highlight nodes in red that will be removed.
        if (std::count(to_remove.begin(), to_remove.end(), &inst)) {
          dot << "<td align=\"left\" bgcolor=\"red\">"
              << LLVMThingToString(&inst);
        } else {
          dot << "<td align=\"left\">" << LLVMThingToString(&inst);
        }
      }
      dot << "</td></tr>" << std::endl;
    }

    // Last row, print out the DEAD slots incoming from successors.
    dot << "<tr><td align=\"left\" colspan=\"3\">";
    sep = "dead: ";
    for (uint64_t i = 0; i < slots.size(); i++) {
      if (used.test(i) && !exit_live.test(i)) {
        dot << sep;
        StreamSlot(arch, context, dot, *(slots[i]), slots[i]->size);
        sep = ", ";
      }
    }
    dot << "</td></tr>" << std::endl;

    dot << "</table>>];" << std::endl;
  }
  dot << "}" << std::endl;
}

class ForwardingBlockVisitor {
 public:
  llvm::Function &func;
  llvm::DominatorTree &dominator_tree;
  InstToOffset &state_access_offset;
  const std::vector<StateSlot> &state_slots;
  const InstToLiveSet &live_args;
  const llvm::FunctionType *lifted_func_ty;

  ForwardingBlockVisitor(llvm::Function &func_,
                         llvm::DominatorTree &dominator_tree_,
                         InstToOffset &state_access_offset_,
                         const std::vector<StateSlot> &state_slots_,
                         const InstToLiveSet &live_args_,
                         const llvm::DataLayout *dl_);

  void Visit(const ValueToOffset &val_to_offset, KillCounter &stats);
  void VisitBlock(llvm::BasicBlock *block, const ValueToOffset &val_to_offset,
                  KillCounter &stats);

 private:
  const llvm::DataLayout *dl;
};

ForwardingBlockVisitor::ForwardingBlockVisitor(
    llvm::Function &func_, llvm::DominatorTree &dominator_tree_,
    InstToOffset &state_access_offset_,
    const std::vector<StateSlot> &state_slots_, const InstToLiveSet &live_args_,
    const llvm::DataLayout *dl_)
    : func(func_),
      dominator_tree(dominator_tree_),
      state_access_offset(state_access_offset_),
      state_slots(state_slots_),
      live_args(live_args_),
      lifted_func_ty(func.getFunctionType()),
      dl(dl_) {}

void ForwardingBlockVisitor::Visit(const ValueToOffset &val_to_offset,
                                   KillCounter &stats) {

  // If any visit makes progress, continue the loop.
  for (auto &block : func) {
    VisitBlock(&block, val_to_offset, stats);
  }
}

static llvm::Value *ConvertToSameSizedType(llvm::Value *val,
                                           llvm::Type *dest_type,
                                           llvm::Instruction *insert_loc) {
  auto empty_name = llvm::Twine::createNull();
  auto val_type = val->getType();
  if (val_type->isIntegerTy()) {
    if (dest_type->isPointerTy()) {
      return new llvm::IntToPtrInst(val, dest_type, empty_name, insert_loc);
    } else {
      return new llvm::BitCastInst(val, dest_type, empty_name, insert_loc);
    }

  } else if (val_type->isFloatingPointTy()) {
    if (dest_type->isPointerTy()) {
      LOG(ERROR) << "Likely nonsensical forwarding of float type "
                 << LLVMThingToString(val_type) << " to pointer type "
                 << LLVMThingToString(dest_type);

      return nullptr;
    } else {
      return new llvm::BitCastInst(val, dest_type, empty_name, insert_loc);
    }

  } else if (val_type->isPointerTy()) {
    if (dest_type->isIntegerTy()) {
      return new llvm::PtrToIntInst(val, dest_type, empty_name, insert_loc);

    } else if (dest_type->isPointerTy()) {
      return new llvm::BitCastInst(val, dest_type, empty_name, insert_loc);

    } else {
      LOG(ERROR) << "Likely nonsensical forwarding of pointer type "
                 << LLVMThingToString(val_type) << " to type "
                 << LLVMThingToString(dest_type);
      return nullptr;
    }
  } else {
    return new llvm::BitCastInst(val, dest_type, empty_name, insert_loc);
  }
}

void ForwardingBlockVisitor::VisitBlock(llvm::BasicBlock *block,
                                        const ValueToOffset &val_to_offset,
                                        KillCounter &stats) {
  auto empty_name = llvm::Twine::createNull();
  std::unordered_map<uint64_t, llvm::LoadInst *> slot_to_load;

  // Collect the instructions into a vector. We're going to be shuffling them
  // around and deleting some, so we don't want to invalidate any iterators.
  std::vector<llvm::Instruction *> insts;
  for (auto inst_it = block->rbegin(); inst_it != block->rend(); ++inst_it) {
    insts.push_back(&*inst_it);
  }

  for (auto inst : insts) {
    if (llvm::isa<llvm::CallInst>(inst) || llvm::isa<llvm::InvokeInst>(inst)) {

      auto live_args_it = live_args.find(inst);
      if (live_args_it == live_args.end()) {
        slot_to_load.clear();

      } else {
        const auto count = live_args_it->second.count();
        if (count == kMaxNumSlots) {
          slot_to_load.clear();

        } else if (count) {
          for (auto i = 0u; i < kMaxNumSlots; ++i) {
            if (live_args_it->second.test(i)) {
              slot_to_load.erase(i);
            }
          }
        }
      }

    // Try to do store-to-load forwarding.
    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
      auto offset_ptr = state_access_offset.find(inst);
      if (offset_ptr == state_access_offset.end()) {
        continue;
      }

      const auto val = store_inst->getOperand(0);
      const auto val_type = val->getType();
      const auto val_size = dl->getTypeAllocSize(val_type);
      const auto &state_slot = state_slots[offset_ptr->second];
      if (!slot_to_load.count(state_slot.index)) {
        continue;
      }

      const auto next_load = slot_to_load[state_slot.index];
      const auto next_type = next_load->getType();

      // We're visiting a store so erase the entry because we don't want to
      // accidentally forward around a store.
      slot_to_load.erase(state_slot.index);

      if (state_access_offset.at(store_inst) !=
          state_access_offset.at(next_load)) {
        stats.fwd_failed++;
        continue;
      }

      auto next_size = dl->getTypeAllocSize(next_type);

      // Perfect forwarding.
      if (val_type == next_type) {
        next_load->replaceAllUsesWith(val);
        next_load->eraseFromParent();
        state_access_offset.erase(next_load);
        stats.fwd_perfect++;
        stats.fwd_stores++;

      // Forwarding, but changing the type.
      } else if (next_size == val_size) {
        if (auto cast = ConvertToSameSizedType(val, next_type, next_load)) {
          next_load->replaceAllUsesWith(cast);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);
          stats.fwd_casted++;
          stats.fwd_stores++;
        } else {
          stats.fwd_failed++;
          continue;
        }

      // Forwarding, but changing the size.
      } else if (next_size < val_size) {
        if (val_type->isIntegerTy() && next_type->isIntegerTy()) {
          auto trunc =
              new llvm::TruncInst(val, next_type, empty_name, next_load);
          next_load->replaceAllUsesWith(trunc);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);

        } else if (val_type->isFloatingPointTy() &&
                   next_type->isFloatingPointTy()) {
          auto trunc =
              new llvm::FPTruncInst(val, next_type, empty_name, next_load);
          next_load->replaceAllUsesWith(trunc);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);

        } else {
          stats.fwd_failed++;
          continue;
        }

        stats.fwd_truncated++;
        stats.fwd_stores++;

      // This is like a store to `AX` followed by a load of `EAX`.
      } else {
        stats.fwd_failed++;
        continue;
      }

    // Try to do load-to-load forwarding.
    } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
      auto offset_ptr = state_access_offset.find(inst);
      if (offset_ptr == state_access_offset.end()) {
        continue;
      }

      const auto &state_slot = state_slots[offset_ptr->second];
      auto &load_ref = slot_to_load[state_slot.index];

      // If the slot is not dominating the load, update it.
      if (load_ref && !dominator_tree.dominates(load_inst, load_ref)) {
        load_ref = nullptr;
      }

      // Get the next load, and update the slot with the current load.
      auto next_load = load_ref;
      load_ref = load_inst;

      // There was no next load, but instead the map default-initialized to
      // `nullptr`, so move on with this load as a candidate for being the
      // target of forwarding.
      if (!next_load) {
        continue;
      }

      // E.g. One load of `AH`, one load of `AL`.
      if (state_access_offset.at(load_inst) !=
          state_access_offset.at(next_load)) {
        stats.fwd_failed++;
        continue;
      }

      auto val_type = load_inst->getType();
      auto val_size = dl->getTypeAllocSize(val_type);
      auto next_type = next_load->getType();
      auto next_size = dl->getTypeAllocSize(next_type);

      // Perfecting forwarding.
      if (val_type == next_type) {
        next_load->replaceAllUsesWith(load_inst);
        next_load->eraseFromParent();
        state_access_offset.erase(next_load);
        stats.fwd_perfect++;
        stats.fwd_loads++;

      // Forwarding, but changing the type.
      } else if (val_size == next_size) {
        if (auto cast =
                ConvertToSameSizedType(load_inst, next_type, next_load)) {
          next_load->replaceAllUsesWith(cast);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);
          stats.fwd_casted++;
          stats.fwd_loads++;
        } else {
          stats.fwd_failed++;
          slot_to_load.erase(state_slot.index);
          continue;
        }

      // Forwarding, but changing the size.
      } else if (next_size < val_size) {
      try_truncate:
        if (val_type->isIntegerTy() && next_type->isIntegerTy()) {
          auto trunc =
              new llvm::TruncInst(load_inst, next_type, empty_name, next_load);
          next_load->replaceAllUsesWith(trunc);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);

        } else if (val_type->isFloatingPointTy() &&
                   next_type->isFloatingPointTy()) {
          auto trunc = new llvm::FPTruncInst(load_inst, next_type, empty_name,
                                             next_load);
          next_load->replaceAllUsesWith(trunc);
          next_load->eraseFromParent();
          state_access_offset.erase(next_load);

        } else {
          stats.fwd_failed++;
          slot_to_load.erase(state_slot.index);
          continue;
        }

        stats.fwd_truncated++;
        stats.fwd_loads++;

      // Try to re-order the loads.
      } else {
        next_load->removeFromParent();
        next_load->insertBefore(load_inst);
        load_ref = next_load;
        std::swap(next_load, load_inst);
        std::swap(next_size, val_size);
        std::swap(val_type, next_type);
        stats.fwd_reordered++;
        goto try_truncate;
      }
    }
  }
}

}  // namespace

// Returns a covering vector of `StateSlots` for the module's `State` type.
// This vector contains one entry per byte of the `State` type.
std::vector<StateSlot> StateSlots(const remill::Arch *arch,
                                  llvm::Module *module) {

  if (!FLAGS_dot_output_dir.empty()) {
    if (!TryCreateDirectory(FLAGS_dot_output_dir)) {
      FLAGS_dot_output_dir.clear();
      LOG(ERROR) << "Invalid path specified to `--dot_output_dir`.";
    } else {
      FLAGS_dot_output_dir = CanonicalPath(FLAGS_dot_output_dir);
    }
  }

  const auto type = arch->StateStructType();
  llvm::DataLayout dl(module);
  const auto num_bytes = dl.getTypeAllocSize(type);
  StateVisitor vis(&dl, num_bytes);
  vis.Visit(type);
  CHECK_EQ(vis.offset_to_slot.size(), num_bytes);
  CHECK_LT(vis.index, kMaxNumSlots);

  std::vector<StateSlot> offset_to_slot;
  offset_to_slot = std::move(vis.offset_to_slot);
  return offset_to_slot;
}

// Analyze a module, discover aliasing loads and stores, and remove dead
// stores into the `State` structure.
void RemoveDeadStores(const remill::Arch *arch, llvm::Module *module,
                      llvm::Function *bb_func,
                      const std::vector<StateSlot> &slots,
                      llvm::Function *ds_func) {
  if (FLAGS_disable_dead_store_elimination) {
    return;
  }

  const auto print_dot = !FLAGS_dot_output_dir.empty();

  KillCounter stats = {};
  const llvm::DataLayout dl(module);

  InstToLiveSet live_args;
  InstToOffset state_access_offset;

  for (auto &func : *module) {
    if (!IsLiftedFunction(&func, bb_func)) {
      continue;
    }

    // If ds_func is set, only apply DSE on that function
    if (ds_func && ds_func != &func) {
      continue;
    }

    ForwardAliasVisitor fav(dl, slots, live_args, state_access_offset,
                            func.getContext());

    // If the analysis succeeds for this function, then do store-to-load
    // and load-to-load forwarding.
    if (fav.Analyze(arch, stats, &func)) {
      if (print_dot) {
        fav.CreateDOTDigraph(arch, &func, ".offsets.dot");
      }

      if (!FLAGS_disable_register_forwarding) {
        llvm::DominatorTree dominator_tree(func);
        ForwardingBlockVisitor fbv(func, dominator_tree, state_access_offset,
                                   slots, live_args, &dl);
        fbv.Visit(fav.state_offset, stats);
      }
    }
  }

  // Perform live set analysis
  LiveSetBlockVisitor visitor(*module, live_args, state_access_offset, slots,
                              bb_func, &dl);

  visitor.FindLiveInsts(stats);
  visitor.CollectDeadInsts(stats);

  if (print_dot) {
    for (auto &func : *module) {
      if (IsLiftedFunction(&func, bb_func)) {
        visitor.CreateDOTDigraph(arch, &func, ".dot");
      }
    }
  }

  visitor.DeleteDeadInsts(stats);

  LOG_IF(ERROR, FLAGS_log_dse_stats)
      << "Candidate stores: " << stats.num_stores << "; "
      << "Dead stores: " << stats.dead_stores << "; "
      << "Instructions removed from DSE: " << stats.removed_insts << "; "
      << "Forwarded loads: " << stats.fwd_loads << "; "
      << "Forwarded stores: " << stats.fwd_stores << "; "
      << "Perfectly forwarded: " << stats.fwd_perfect << "; "
      << "Forwarded by truncation: " << stats.fwd_truncated << "; "
      << "Forwarded by casting: " << stats.fwd_casted << "; "
      << "Forwarded by reordering: " << stats.fwd_reordered << "; "
      << "Could not forward: " << stats.fwd_failed << "; "
      << "Unanalyzed functions: " << stats.failed_funcs;
}

}  // namespace remill
