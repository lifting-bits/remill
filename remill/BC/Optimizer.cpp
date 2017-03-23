/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <bitset>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>

#include <llvm/Pass.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Optimizer.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

namespace remill {
namespace {
enum : size_t {
  kMaxNumRegs = 192UL,
  kNumFixPointIterations = 1000
};

#if 0

using RegBitMap = std::bitset<kMaxNumRegs>;

struct RegUses {
  inline RegUses(void) {
    local_dead.set();  // Bitmask.
  }

  // Registers that must be live on entry to an instruction or block because
  // the register will be used before is killed (if it is killed).
  RegBitMap local_live;

  // Registers that are definitely dead on entry. This is a bitmask.
  RegBitMap local_dead;

  RegBitMap incoming_live;
};
#endif

class Opt : public Optimizer {
 public:
  explicit Opt(llvm::Module *module_);
  virtual ~Opt(void) {}

  void Optimize(void) override;

#if 0
  // Assign register numbers to every load, store, GEP, pointer bitcast, and
  // alloca.
  void AssignRegisters(llvm::Function *func);

  // Initialize the flows within the function.
  void InitBlockTransferFunctions(llvm::Function *func);
  void InitDeoptBlockTransferFunctions(llvm::Function *func);

  // Re-associate registers. This does some basic deduplication of GEPs, and
  // moves things like GEPs and pointer bitcasts up into the entry block.
  //
  // Returns `false` if there are any GEPs with non-constant indices.
  bool ReassociateRegisters(llvm::Function *func);

  // Removes dead stores from within a functions.
  void EliminateDeadStores(llvm::Function *func) const;

  void InterProceduralDeadStoreElimination(void);

  llvm::StructType * const state_type;

  // Used to figure out the size of values/types within code in a module.
  llvm::DataLayout data_layout;

  // Used to create an ID for each register. A register with ID -1 is "invalid",
  // which means that the alias analysis won't track it. An ID of 0 means
  // unassigned. So, `num_regs` always starts at 1.
  int num_regs;

  // Maps a byte offset within the `State` structure to a register ID. If, for
  // example, a register is a 32-bit integer, then there will be four
  // consecutive entries in this vector with the same value (register ID).
  std::vector<int> offset_to_reg;

  // Maps a register to its size in bytes. We use this to figure out if a `load`
  // or `store` of a register covers the whole register or just part of it.
  std::vector<size_t> reg_to_size;

  // Maps a register to its LLVM type.
  std::vector<llvm::Type *> reg_to_type;

  // Maps instructions/values in a function to their associated register
  // number. In general, the only represented values are those relating to
  // memory operations, e.g. bit casts, loads, stores, and GEPs.
  std::unordered_map<const llvm::Value *, int> inst_to_reg;

  // Maps basic blocks to their live and killed sets.
  std::unordered_map<llvm::BasicBlock *, RegUses> block_transfer_functions;
  std::unordered_map<llvm::Function *, RegUses> func_transfer_functions;

  // This intrinsic represents asking the system for some information, but the
  // implementation of it is opaque and so it can modify any register state.
  // We need to treat calls to this intrinsic as making all registers live.
  llvm::Function *sync_hyper_call;

 private:
  void AssignReg(size_t offset, size_t size, int reg, llvm::Type *type);

  // Get the size of a type or value.
  size_t SizeOfType(llvm::Type *) const;
  size_t SizeOfValue(const llvm::Value *) const;

  // Recursively visit the architecture-specific `State` structure and assign
  // register IDs to each thing in there.
  size_t IndexType(llvm::Type *, size_t offset);
  size_t GetOffsetFromBasePtr(const llvm::GetElementPtrInst *gep_inst);
  size_t GetOffsetFromBasePtr(const llvm::GetElementPtrInst *gep_inst,
                              bool &failed);

  void ApplyInstructionTransferFunction(llvm::Instruction *inst,
                                        RegUses *transfer) const;

  void InitBlockTransferFunction(llvm::BasicBlock *block, RegUses *transfer);
#endif
};

#if 0
// Gets the state structure type from this module.
static llvm::StructType *GetStateType(llvm::Module *module) {
  llvm::Function *bb_func = module->getFunction("__remill_basic_block");
  CHECK(nullptr != bb_func)
      << "Unable to find `__remill_basic_block` function.";

  CHECK(nullptr != bb_func)
      << "Cannot find state structure type.";

  auto bb_func_type = bb_func->getFunctionType();
  auto state_ptr_type = llvm::dyn_cast<llvm::PointerType>(
      bb_func_type->getParamType(remill::kStatePointerArgNum));

  CHECK(nullptr != state_ptr_type)
      << "First argument to lifted block function must be a pointer to "
      << "a state structure type (1).";

  auto state_type = llvm::dyn_cast<llvm::StructType>(
      state_ptr_type->getElementType());

  CHECK(nullptr != state_type)
      << "First argument to lifted block function must be a pointer to "
      << "a state structure type (2).";

  return state_type;
}
#endif

Opt::Opt(llvm::Module *module_)
    : Optimizer(module_) {}

#if 0
Opt::Opt(llvm::Module *module_)
    : Optimizer(module_),
      state_type(GetStateType(module)),
      data_layout(module),
      num_regs(1),  // So that we can use `0` to mean unassigned.
      offset_to_reg(SizeOfType(state_type), -1),
      reg_to_size(kMaxNumRegs, 0),
      reg_to_type(kMaxNumRegs),
      inst_to_reg(),
      sync_hyper_call(module->getFunction("__remill_sync_hyper_call")) {

  IndexType(state_type, 0);

  CHECK(static_cast<int>(kMaxNumRegs) > num_regs)
      << "Too many registers for bitmap! Change kMaxNumRegs and recompile.";
}

// Gets the size of an llvm value.
size_t Opt::SizeOfValue(const llvm::Value *value) const {
  return SizeOfType(value->getType());
}

size_t Opt::SizeOfType(llvm::Type *type) const {
  return data_layout.getTypeStoreSize(type);
}

// Assign a register to a sequence of bytes within the offset map, and record
// the size of this register.
void Opt::AssignReg(size_t offset, size_t size, int reg,
                         llvm::Type *type) {

  CHECK(static_cast<int>(kMaxNumRegs) > reg)
      << "Too many registers for bitmap! Change kMaxNumRegs and recompile.";

  if (reg > 0) {
    DLOG(INFO)
        << "Register " << reg << " covers [" << offset
        << ", " << (offset + size) << ")";

    for (auto i = offset; i < (offset + size); ++i) {
      offset_to_reg[i] = reg;
    }

    reg_to_size[reg] = size;
    reg_to_type[reg] = type;
  }
}

// Recursively visit the architecture-specific `State` structure and assign
// register IDs to each thing in there.
size_t Opt::IndexType(llvm::Type *type, size_t offset) {

  auto size = SizeOfType(type);
  auto internal_size = 0UL;

  // Integers and floats are units.
  if (type->isIntegerTy() || type->isFloatingPointTy()) {
    AssignReg(offset, size, num_regs++, type);

  // Treat structures as bags of things that can be individually indexed.
  } else if (auto struct_type = llvm::dyn_cast<llvm::StructType>(type)) {
    auto internal_offset = offset;
    for (const auto field_type : struct_type->elements()) {
      internal_size += IndexType(field_type, internal_offset);
      internal_offset += SizeOfType(field_type);
    }

    CHECK(internal_size == size)
        << "Unable to allocate all elements of the structure type "
        << struct_type->getName().str();

  // Visit each element of the array.
  } else if (auto array_type = llvm::dyn_cast<llvm::ArrayType>(type)) {
    auto num_elems = array_type->getArrayNumElements();
    auto element_type = array_type->getArrayElementType();

    // Array of unit types; treat this as a vector.
    if (element_type->isIntegerTy() || element_type->isFloatTy()) {

      // Our dead store elimination works by injecting stores of the result
      // of calling an undefined value intrinsic, but those only go up to
      // 8 bytes of size, and so if we have an array of unit types, then it's
      // probably representing a vector, and we can't really handle vectors
      // with those intrinsics.
      if (size <= 8 || 1 != num_elems) {
        AssignReg(offset, size, num_regs++, element_type);
      }

    } else {
      auto internal_offset = offset;
      for (auto i = 0U; i < num_elems; ++i) {
        internal_size += IndexType(element_type, internal_offset);
        internal_offset += SizeOfType(element_type);
      }

      CHECK(internal_size == size)
          << "Unable to allocate all elements of the array type.";
    }
  }

  return size;
}

size_t Opt::GetOffsetFromBasePtr(const llvm::GetElementPtrInst *gep_inst) {
  bool failed = false;
  auto ret = GetOffsetFromBasePtr(gep_inst, failed);
  if (failed) {
    LOG(FATAL)
        << "Index operands to GEPs must be constant:"
        << remill::LLVMThingToString(gep_inst);
  }
  return ret;
}

// Get the index sequence of a GEP instruction. For GEPs that access the system
// register state, this allows us to index into the `system_regs` map in order
// to find the correct system register. In cases where we're operating on a
// bitcast system register, this lets us find the offset into that register.
size_t Opt::GetOffsetFromBasePtr(const llvm::GetElementPtrInst *gep_inst,
                                 bool &failed) {
  llvm::APInt offset(64, 0);
  const auto found_offset = gep_inst->accumulateConstantOffset(
      data_layout, offset);
  failed = !found_offset;
  return offset.getZExtValue();
}

void Opt::AssignRegisters(llvm::Function *func) {
  inst_to_reg.clear();

  auto state_ptr = NthArgument(func, remill::kStatePointerArgNum);
  auto mem_ptr = NthArgument(func, remill::kMemoryPointerArgNum);
  auto func_name = func->getName().str();
  std::queue<llvm::Value *> work_list;
  std::set<llvm::Value *> seen;
  std::unordered_map<llvm::Value *, int> inst_to_offset;

  inst_to_reg[state_ptr] = -2;
  inst_to_offset[state_ptr] = 0;

  inst_to_reg[mem_ptr] = -1;
  inst_to_offset[mem_ptr] = 0;

  seen.insert(state_ptr);
  seen.insert(mem_ptr);

  DLOG(INFO)
      << "Performing alias analysis of registers in " << func_name;

  // Auto-assign registers for GEPs and LOADs, and BITCASTs.
  for (auto &basic_block : *func) {
    for (auto &inst : basic_block) {

      // Clear alias-analysis meta-data. We don't want this affecting us down
      // the line in unpredictable ways.
      inst.setMetadata(llvm::LLVMContext::MD_tbaa, nullptr);

      // Ideally, loading the address of a register within the machine
      // state structure.
      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        if (state_ptr == gep_inst->getPointerOperand()) {
          auto offset = GetOffsetFromBasePtr(gep_inst);
          auto reg = offset_to_reg[offset];
          CHECK(0 != reg)
              << "Unable to locate system register associated with a "
              << "`getelementptr` instruction in function "
              << func_name << ".";

          inst_to_reg[gep_inst] = reg;
          inst_to_offset[gep_inst] = offset;
          seen.insert(&inst);
        } else {
          work_list.push(&inst);
        }

      // Pointer-to-pointer bitcasts, inttoptr, and ptrtoint.
      } else if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(&inst)) {
        auto dest_is_ptr = cast_inst->getType()->isPointerTy();
        auto src_is_ptr = cast_inst->getSrcTy()->isPointerTy();

        if (dest_is_ptr || src_is_ptr) {
          work_list.push(cast_inst->getOperand(0));
          work_list.push(&inst);
        }

      // Look at the source pointer.
      } else if (llvm::isa<llvm::LoadInst>(&inst)) {
        work_list.push(&inst);

      // Look at the destination pointer.
      } else if (llvm::isa<llvm::StoreInst>(&inst)) {
        work_list.push(&inst);

      // Pretend that an alloca is actually a register, but not one that is
      // named inside of the `State` struct. Those registers will have their
      // ID as > 0.
      } else if (llvm::isa<llvm::AllocaInst>(&inst)) {
        inst_to_reg[&inst] = -1;
        inst_to_offset[&inst] = 0;  // Dummy value.
        seen.insert(&inst);
      }
    }
  }

  // Resolve the instructions that create or load values from pointers into
  // registers. Ideally, every pointer should be formed from a register in
  // the machine state structure.
  while (!work_list.empty()) {
    auto inst = work_list.front();
    work_list.pop();

    if (seen.count(inst)) {
      continue;  // Already processed.
    }

    if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(inst)) {
      auto base_ptr = gep_inst->getPointerOperand();
      if (base_ptr == state_ptr) {
        LOG(FATAL)
            << "GEPs that directly access the State structure should already "
            << "have been handled in function " << func_name << ": "
            << remill::LLVMThingToString(inst);
      }

      if (auto reg = inst_to_reg[base_ptr]) {
        if (!inst_to_offset.count(base_ptr)) {
          LOG(FATAL)
              << "Don't have the offset for the source pointer of the GEP "
              << "in function " << func_name << ": "
              << remill::LLVMThingToString(inst);
        }

        auto offset = GetOffsetFromBasePtr(gep_inst);
        seen.insert(gep_inst);
        inst_to_reg[gep_inst] = reg;
        inst_to_offset[gep_inst] = offset + inst_to_offset[base_ptr];
      } else {
        work_list.push(base_ptr);
        work_list.push(gep_inst);
      }

    // Bitcasts, intotoptr, and ptrtoint all maintain the pointer value, so
    // are mostly identity transformations.
    } else if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(inst)) {
      auto src = cast_inst->getOperand(0);
      if (auto reg = inst_to_reg[src]) {
        if (!inst_to_offset.count(src)) {
          LOG(FATAL)
              << "Don't have the offset for the source pointer of the "
              << "cast instruction in function " << func_name << ": "
              << remill::LLVMThingToString(inst);
        }

        seen.insert(inst);
        inst_to_reg[inst] = reg;
        inst_to_offset[inst] = inst_to_offset[src];
      } else {
        work_list.push(src);
        work_list.push(inst);
      }

    // Try to handle binary arithmetic on inttoptr values.
    } else if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(inst)) {
      auto lhs = binop->getOperand(0);
      auto rhs = llvm::dyn_cast<llvm::ConstantInt>(binop->getOperand(1));

      if (auto reg = inst_to_reg[lhs]) {
        if (-1 == reg) {
          seen.insert(binop);
          inst_to_reg[binop] = reg;
          inst_to_offset[binop] = 0;
          // Weird stuff to the memory pointer, e.g. casting it and doing
          // a mask to "force" the pointer to be a 32-bit value??
          continue;
        }

        if (!rhs) {
          LOG(FATAL)
              << "Expected right-hand side of binary operator related to "
              << "memory accesses to be a constant integer in function "
              << func_name << ": " << remill::LLVMThingToString(inst);
        }
        if (!inst_to_offset.count(lhs)) {
          LOG(FATAL)
              << "Don't have the offset for the source pointer of the "
              << "binary operator in function " << func_name << ": "
              << remill::LLVMThingToString(inst);
        }

        if (llvm::BinaryOperator::Add == binop->getOpcode()) {
          auto offset = rhs->getSExtValue();
          auto total_offset = inst_to_offset[lhs] + offset;

          if (static_cast<size_t>(total_offset) >= offset_to_reg.size()) {
            LOG(FATAL)
                << "Cannot map offset " << total_offset
                << " to a register in function" << func_name << ": "
                << remill::LLVMThingToString(inst);
          }

          seen.insert(inst);
          inst_to_reg[binop] = offset_to_reg[total_offset];
          inst_to_offset[binop] = total_offset;
        } else {
          LOG(FATAL)
              << "Unsupported binary operator related to memory access in "
              << "function " << func_name << ": "
              << remill::LLVMThingToString(inst);
        }
      } else {
        work_list.push(lhs);
        if (rhs) {
          work_list.push(rhs);
        }
        work_list.push(binop);
      }

    } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
      auto source_ptr = load_inst->getPointerOperand();
      auto source_inst = llvm::dyn_cast<llvm::Instruction>(source_ptr);

      if (auto reg = inst_to_reg[source_ptr]) {
        inst_to_reg[inst] = reg;
        inst_to_offset[inst] = inst_to_offset[source_ptr];
        seen.insert(inst);

      } else if (source_inst) {
        work_list.push(source_ptr);
        work_list.push(inst);
      }

    } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
      auto dest_ptr = store_inst->getPointerOperand();
      if (auto reg = inst_to_reg[dest_ptr]) {
        inst_to_reg[inst] = reg;
        inst_to_offset[inst] = inst_to_offset[dest_ptr];
        seen.insert(inst);
      } else {
        auto dest_inst = llvm::dyn_cast<llvm::Instruction>(dest_ptr);
        if (!dest_inst) {
          LOG(FATAL)
              << "Storing to a non-instruction in function "
              << func_name << ": " << remill::LLVMThingToString(inst);
        }
        work_list.push(dest_ptr);
        work_list.push(inst);
      }

    // PHI node.
    } else if (auto phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
      auto &phi_reg = inst_to_reg[phi];
      auto need_more = false;

      for (auto &use : phi->incoming_values()) {
        auto val = use.get();
        if (auto reg = inst_to_reg[val]) {
          if (!phi_reg) {
            phi_reg = reg;
            inst_to_offset[phi] = inst_to_offset[val];

          } else if (phi_reg != reg) {
            LOG(FATAL)
                << "PHI node must join the same register in function "
                << func_name << ": " << remill::LLVMThingToString(inst);
          }
        } else {
          work_list.push(val);
          need_more = true;
        }
      }

      if (need_more) {
        work_list.push(phi);
      } else {
        seen.insert(phi);
      }

    } else if (llvm::isa<llvm::Constant>(inst) ||
               llvm::isa<llvm::Argument>(inst)) {
      seen.insert(inst);
      continue;

    // Likely call to an intrinsic for memory access.
    } else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(inst)) {
      auto called_func = call_inst->getCalledFunction();
      if (called_func && called_func->getName().startswith("__remill")) {
        inst_to_reg[inst] = -1;
        inst_to_offset[inst] = 0;  // Dummy value.
        seen.insert(inst);
      } else {
        LOG(FATAL)
            << "Got to an impossible state when assigning registers "
            << "in function " << func_name << ": "
            << remill::LLVMThingToString(inst);
      }

    // Shouldn't be possible.
    } else {
      LOG(FATAL)
          << "Got to an impossible state when assigning registers "
          << "in function " << func_name << ": "
          << remill::LLVMThingToString(inst);
    }
  }
}

bool Opt::ReassociateRegisters(llvm::Function *func) {
  auto state_ptr = NthArgument(func, remill::kStatePointerArgNum);
  bool failed = false;
  std::vector<llvm::GetElementPtrInst *> to_move;
  for (auto &block : *func) {
    for (auto &inst : block) {
      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        (void) GetOffsetFromBasePtr(gep_inst, failed);
        if (failed) {
          return false;
        }
        if (gep_inst->getPointerOperand() == state_ptr) {
          to_move.push_back(gep_inst);
        }
      }
    }
  }

  if (to_move.empty()) {
    return true;
  }

  // Sort the GEP instructions by the offset being accessed.
  std::sort(to_move.begin(), to_move.end(),
            [=] (llvm::GetElementPtrInst *a, llvm::GetElementPtrInst *b) {
                return GetOffsetFromBasePtr(a) < GetOffsetFromBasePtr(b);
            });

  // Move all GEPs into the beginning of the entry block.
  auto entry_block = &func->getEntryBlock();
  auto &inst_list = entry_block->getInstList();
  size_t last_offset = 0;
  llvm::GetElementPtrInst *last_gep_inst = nullptr;

  for (auto gep_inst : to_move) {
    auto offset = GetOffsetFromBasePtr(gep_inst);
    if (last_gep_inst && offset == last_offset &&
        last_gep_inst->getType() == gep_inst->getType()) {  // Deduplicate.
      gep_inst->replaceAllUsesWith(last_gep_inst);
      gep_inst->eraseFromParent();

    } else {  // Re-associate.
      gep_inst->removeFromParent();
      inst_list.insert(inst_list.begin(), gep_inst);
      last_gep_inst = gep_inst;
      last_offset = offset;
    }
  }
  return true;
}

void Opt::EliminateDeadStores(llvm::Function *func) const {
  std::vector<llvm::StoreInst *> to_remove;
  for (auto &block : *func) {
    auto it = block.rbegin();
    const auto end = block.rend();
    auto incoming = block_transfer_functions.at(&block);
    incoming.local_live = incoming.incoming_live;

    for (; it != end; ++it) {
      auto inst = &(*it);
      if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        auto dest_reg = inst_to_reg.at(store_inst->getPointerOperand());
        if (0 < dest_reg && !incoming.local_live.test(dest_reg)) {
          to_remove.push_back(store_inst);
        }
      }
      ApplyInstructionTransferFunction(inst, &incoming);
    }
  }

  for (auto store_inst : to_remove) {
    auto val = store_inst->getValueOperand();
    store_inst->eraseFromParent();
    llvm::RecursivelyDeleteTriviallyDeadInstructions(val);
  }
}

// Visit an instruction and track the changes to the dependencies.
void Opt::ApplyInstructionTransferFunction(llvm::Instruction *inst,
                                           RegUses *transfer) const {
  int reg = -1;
  bool is_load = true;
  size_t operand_size = 0;

  if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
    reg = inst_to_reg.at(load_inst->getPointerOperand());
    operand_size = SizeOfValue(load_inst);

  } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
    reg = inst_to_reg.at(store_inst->getPointerOperand());
    is_load = false;
    operand_size = SizeOfValue(store_inst->getValueOperand());

  // Find calls to the synchronous hyper call intrinsic and mark all
  // registers as used.
  } else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(inst)) {
    if (auto func = call_inst->getCalledFunction()) {
      if (sync_hyper_call == func) {
        transfer->local_live.set();
        transfer->local_dead.set();
      }
    }
    return;

  } else {
    return;  // Does not affect liveness of registers.
  }

  if (-1 == reg) {
    return;  // Load of something related to an `alloca`.
  }

  if (!reg) {
    LOG(FATAL)
        << "Missing register for instruction in "
        << inst->getFunction()->getName().str()
        << ":" << remill::LLVMThingToString(inst);
  }

  auto reg_bit = static_cast<size_t>(reg);

  // All or part of the register is read.
  if (is_load) {
    transfer->local_live.set(reg_bit);
    transfer->local_dead.set(reg_bit);

  // We store to the whole register.
  } else if (operand_size == reg_to_size[reg]) {
    transfer->local_live.reset(reg_bit);
    transfer->local_dead.reset(reg_bit);
  }
}

void Opt::InitBlockTransferFunction(llvm::BasicBlock *block,
                                         RegUses *transfer) {
  auto it = block->rbegin();
  auto end = block->rend();
  for (; it != end; ++it) {
    ApplyInstructionTransferFunction(&(*it), transfer);
  }
}

// Initialize the flows within the function.
void Opt::InitBlockTransferFunctions(llvm::Function *func) {
  for (auto &block : *func) {
    auto &transfer = block_transfer_functions[&block];
    InitBlockTransferFunction(&block, &transfer);
  }
}

void Opt::InitDeoptBlockTransferFunctions(llvm::Function *func) {
  for (auto &block : *func) {
    auto &transfer = block_transfer_functions[&block];
    transfer.incoming_live.set();
    transfer.local_dead.set();
    transfer.local_live.set();
  }
}

// Get all predecessors of a basic block. This will cross function boundaries.
static void GetBlockPredecessors(llvm::BasicBlock *block,
                                 std::vector<llvm::BasicBlock *> &preds) {
  preds.clear();
  preds.insert(preds.end(), llvm::pred_begin(block), llvm::pred_end(block));

  llvm::Function *func = block->getParent();
  if (&func->getEntryBlock() == block) {
    for (auto user : func->users()) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
        preds.push_back(call_inst->getParent());
      }
    }
  }
}

// Get all successors of a basic block. This will cross function boundaries.
static void GetBlockSuccessors(llvm::BasicBlock *block,
                               std::vector<llvm::BasicBlock *> &succs) {
  succs.clear();
  succs.insert(succs.end(), llvm::succ_begin(block), llvm::succ_end(block));

  if (auto call_inst = block->getTerminatingMustTailCall()) {
    if (auto func = call_inst->getCalledFunction()) {
      if (!func->isDeclaration() &&
          func->getName().startswith("__remill_sub")) {
        succs.push_back(&(func->getEntryBlock()));
      }
    }
  }
}

// Get a function's front or a null pointer if no front available.
static llvm::BasicBlock *GetFuncFrontOrNull(llvm::Function *func) {
  if (func->isDeclaration() || func->size() == 0) {
    return nullptr;
  }
  return &(func->front());
}

// Perform inter-procedural dead store elimination on accesses to the `State`
// structure.
void Opt::InterProceduralDeadStoreElimination(void) {
  size_t num_blocks = 0;
  std::set<llvm::BasicBlock *> work_list;
  std::set<llvm::BasicBlock *> avoid;
  std::vector<llvm::BasicBlock *> preds;
  std::vector<llvm::BasicBlock *> succs;

  for (llvm::Function &func : *module) {
    if (!func.isDeclaration() && !func_transfer_functions.count(&func)) {
      num_blocks += func.size();
    }
  }

  block_transfer_functions.clear();
  block_transfer_functions.reserve(num_blocks);

  // Initialize the block transfer functions for every basic block in every
  // lifted subroutine.
  ForEachBlock(module, [&] (uint64_t, uint64_t, llvm::Function *func) {
    auto func_name = func->getName();
    if (!func_transfer_functions.count(func)) {
      if (ReassociateRegisters(func)) {
        AssignRegisters(func);
        InitBlockTransferFunctions(func);

      // There exists a GEP with a non-constant index, and so we treat this
      // block as non-optimizable (in terms of DSE). We can add these blocks
      // to the avoid set, kind of like how incremental optimization happens.
      } else {
        DLOG(WARNING)
            << "Treating function " << func_name.str()
            << " as unoptimizable; it has a GEP with a non-constant index.";
        InitDeoptBlockTransferFunctions(func);
        func_transfer_functions[func] =
            block_transfer_functions[&(func->front())];
      }
    }
  });

  // Propagate dead register analysis results from a prior run to the
  // current run.
  for (const auto &trans_entry : func_transfer_functions) {
    auto func = trans_entry.first;
    CHECK(llvm::isa<llvm::Function>(trans_entry.first))
        << "Memory corruption; cached version of function has changed.";

    auto block = &(func->front());
    auto trans = trans_entry.second;
    block_transfer_functions[block] = trans;
    avoid.insert(block);
  }

  // Set the base case of the data flow computation.
  for (auto &trans_entry : block_transfer_functions) {
    auto block = trans_entry.first;

    // If we've already processed this block (in a prior run) then add its
    // predecessors in, as long as they are not part of already optimized
    // functions.
    if (avoid.count(block)) {
      GetBlockPredecessors(block, preds);
      for (auto pred : preds) {
        auto pred_func = pred->getParent();
        if (!func_transfer_functions.count(pred_func)) {
          work_list.insert(pred);
        }
      }
    } else {
      GetBlockSuccessors(block, succs);
      if (succs.empty()) {
        auto &transfer = trans_entry.second;
        transfer.incoming_live.set();  // Base case.
        GetBlockPredecessors(block, preds);
        work_list.insert(preds.begin(), preds.end());
      }
    }
  }

  // Iterate towards a fixed point until the work list empties or until we
  // reach the maximum number of iterations of the data flow algorithm.
  for (auto i = 0ULL; i < kNumFixPointIterations && !work_list.empty(); ++i) {
    DLOG(INFO)
        << "Work list size is " << work_list.size();

    std::set<llvm::BasicBlock *> next_work_list;
    for (auto block : work_list) {
      if (avoid.count(block)) {
        continue;
      }

      GetBlockSuccessors(block, succs);
      if (succs.empty()) {
        continue;
      }

      RegBitMap new_incoming;
      for (auto succ_block : succs) {
        const auto &succ_transfer = block_transfer_functions.at(succ_block);

        new_incoming |= (succ_transfer.incoming_live &
                         succ_transfer.local_dead);
        new_incoming |= succ_transfer.local_live;
      }

      auto &transfer = block_transfer_functions.at(block);
      if (new_incoming == transfer.incoming_live) {
        continue;  // No change.
      }

      transfer.incoming_live = new_incoming;

      GetBlockPredecessors(block, preds);

      // Add the predecessors to the work list, because our block has changed,
      // and its changes may introduce changes into its predecessors.
      for (auto pred_block : preds) {
        next_work_list.insert(pred_block);
      }
    }
    work_list.swap(next_work_list);
  }

  block_transfer_functions[nullptr].local_live.set();
  block_transfer_functions[nullptr].local_dead.set();

  // Eliminate dead stores.
  ForEachBlock(module, [&] (uint64_t, uint64_t, llvm::Function *func) {
    if (!func_transfer_functions.count(func)) {
      AssignRegisters(func);
      EliminateDeadStores(func);
      func_transfer_functions[func] =
          block_transfer_functions.at(GetFuncFrontOrNull(func));
    }
  });

  // Clear it out.
  decltype(block_transfer_functions) empty;
  block_transfer_functions.clear();
  block_transfer_functions.swap(empty);
  empty.clear();
}

#endif  // 0

static void DisableReoptimization(llvm::Module *module) {
  ForEachBlock(module, [&] (uint64_t, uint64_t, llvm::Function *func) {
    func->addFnAttr(llvm::Attribute::OptimizeNone);
  });
}

static void RunO3(llvm::Module *module) {
  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  auto TLI = new llvm::TargetLibraryInfoImpl(
      llvm::Triple(module->getTargetTriple()));
  TLI->disableAllFunctions();

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 0;  // -O0.
  builder.SizeLevel = 0;  // -Oz
  builder.Inliner = llvm::createFunctionInliningPass(999);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableTailCalls = false;  // Enable tail calls.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = false;  // Don't produce vector operations.
  builder.LoopVectorize = false;  // Don't produce vector operations.
  builder.LoadCombine = false;  // Don't coalesce loads.
  builder.MergeFunctions = false;  // Try to deduplicate functions.
  builder.VerifyInput = false;
  builder.VerifyOutput = false;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);

  func_manager.add(llvm::createCFGSimplificationPass());
  func_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_manager.add(llvm::createReassociatePass());
  func_manager.add(llvm::createInstructionCombiningPass());
  func_manager.add(llvm::createDeadStoreEliminationPass());
  func_manager.add(llvm::createDeadCodeEliminationPass());

  func_manager.doInitialization();
  ForEachBlock(module, [&] (uint64_t, uint64_t, llvm::Function *func) {
    if (!func->hasFnAttribute(llvm::Attribute::OptimizeNone)) {
      func_manager.run(*func);
    }
  });

  func_manager.doFinalization();
  module_manager.run(*module);
}

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  auto intrinsics = function->getParent()->getFunction("__remill_intrinsics");

  std::vector<llvm::CallInst *> call_insts;
  for (auto callers : function->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(callers)) {
      auto user_func = call_inst->getParent()->getParent();
      if (user_func != intrinsics) {
        call_insts.push_back(call_inst);
      }
    }
  }

  std::set<llvm::User *> work_list;
  auto undef_val = llvm::UndefValue::get(function->getReturnType());
  for (auto call_inst : call_insts) {
    work_list.insert(call_inst->user_begin(), call_inst->user_end());
    call_inst->replaceAllUsesWith(undef_val);
    call_inst->removeFromParent();
    delete call_inst;
  }

  // Try to propagate `undef` values produced from our intrinsics all the way
  // to store instructions, and treat them as dead stores to be eliminated.
  std::vector<llvm::StoreInst *> dead_stores;
  while (work_list.size()) {
    std::set<llvm::User *> next_work_list;
    for (auto inst : work_list) {
      if (llvm::isa<llvm::CmpInst>(inst) ||
          llvm::isa<llvm::CastInst>(inst)) {
        next_work_list.insert(inst->user_begin(), inst->user_end());
        auto undef_val = llvm::UndefValue::get(inst->getType());
        inst->replaceAllUsesWith(undef_val);
      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        dead_stores.push_back(store_inst);
      }
    }
    work_list.swap(next_work_list);
  }

  for (auto dead_store : dead_stores) {
    dead_store->eraseFromParent();
  }
}

static void RemoveUndefFuncCalls(llvm::Module *module) {
  llvm::Function *undef_funcs[] = {
      module->getFunction("__remill_undefined_8"),
      module->getFunction("__remill_undefined_16"),
      module->getFunction("__remill_undefined_32"),
      module->getFunction("__remill_undefined_64"),
      module->getFunction("__remill_undefined_f32"),
      module->getFunction("__remill_undefined_f64"),
  };

  for (auto undef_func : undef_funcs) {
    ReplaceUndefIntrinsic(undef_func);
  }
}

// Enable inlining of functions whose inlining has been deferred.
static bool EnableDeferredInlining(llvm::Module *module) {
  auto defer_inlining_func = module->getFunction("__remill_defer_inlining");
  if (!defer_inlining_func) {
    return false;
  }

  std::vector<llvm::CallInst *> call_insts;
  std::set<llvm::Function *> processed_funcs;

  // Find all calls to the inline defer intrinsic.
  for (auto caller : defer_inlining_func->users()) {
    if (auto call_inst = llvm::dyn_cast_or_null<llvm::CallInst>(caller)) {
      call_insts.push_back(call_inst);
    }
  }

  if (call_insts.empty()) {
    return false;
  }

  // Remove the calls to the inline defer intrinsic, and mark the functions
  // containing those calls as inlinable.
  for (auto call_inst : call_insts) {
    auto basic_block = call_inst->getParent();
    auto caller_func = basic_block->getParent();

    processed_funcs.insert(caller_func);

    caller_func->removeFnAttr(llvm::Attribute::NoInline);
    caller_func->addFnAttr(llvm::Attribute::AlwaysInline);
    caller_func->addFnAttr(llvm::Attribute::InlineHint);

    call_inst->replaceAllUsesWith(
        llvm::UndefValue::get(call_inst->getType()));
    call_inst->eraseFromParent();
  }

  // Emulate the `flatten` attribute by finding all calls to functions that
  // containing the inline defer intrinsic, and mark the call instructions
  // as requiring inlining.
  for (auto function : processed_funcs) {
    for (auto callers : function->users()) {
      if (auto call_inst = llvm::dyn_cast_or_null<llvm::CallInst>(callers)) {
        call_inst->addAttribute(llvm::AttributeSet::FunctionIndex,
                                llvm::Attribute::AlwaysInline);
      }
    }
  }

  return true;
}

void Opt::Optimize(void) {
  auto module_id = module->getModuleIdentifier();

  DLOG(INFO)
      << "Running -O3 on " << module_id;
  RunO3(module);

//  DLOG(INFO)
//      << "Doing inter-procedural dead store elimination on " << module_id;
//  InterProceduralDeadStoreElimination();

  DLOG(INFO)
      << "Removing undefined function calls.";
  RemoveUndefFuncCalls(module);

  DLOG(INFO)
      << "Enabling the deferring inlining optimization.";
  if (EnableDeferredInlining(module)) {
    DLOG(INFO)
        << "Rerunning -O3 on " << module_id;
    RunO3(module);

    DLOG(INFO)
        << "Finalizing optimizations of " << module_id;
  }

  DisableReoptimization(module);

  DLOG(INFO)
      << "Optimized bitcode.";
}

}  // namespace

Optimizer::~Optimizer(void) {}

Optimizer::Optimizer(llvm::Module *module_)
    : module(module_) {}

std::unique_ptr<Optimizer> Optimizer::Create(llvm::Module *module_) {
  return std::unique_ptr<Optimizer>(new Opt(module_));
}

}  // namespace remill
