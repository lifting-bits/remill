/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <bitset>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

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
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

DEFINE_uint64(aggressiveness, 1000, "How aggressive to be with the data flow "
                                    "analysis. Aggressiveness is expressed in "
                                    "terms of how many iterations of the "
                                    "analysis are performed. A bigger number "
                                    "means more aggressive.");

DEFINE_string(bc_in, "", "Input bitcode file to be optimized.");

DEFINE_string(bc_out, "", "Optimized bitcode.");

DEFINE_bool(server, false, "Run the optimizer as a server. This will allow "
                           "remill-opt to receive bitcode from remill-lift.");

DEFINE_bool(strip, false, "Strip out all debug information.");

DEFINE_bool(lower_memops, false, "Lower memory access intrinsics into "
                                 "LLVM load and store instructions. "
                                 "Note: the memory class pointer is replaced "
                                 "with a i8 pointer.");

namespace {
enum : size_t {
  kMaxNumRegs = 192UL
};

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


class StateMap {
 public:
  StateMap(llvm::Module *module, llvm::Type *state_type);

  // Assign register numbers to every load, store, GEP, pointer bitcast, and
  // alloca.
  void AssignRegisters(llvm::Function *func);

  // Initialize the flows within the function.
  void InitBlockTransferFunctions(llvm::Function *func);

  // Re-associate registers. This does some basic deduplication of GEPs, and
  // moves things like GEPs and pointer bitcasts up into the entry block.
  void ReassociateRegisters(llvm::Function *func);

  // Removes dead stores from within a functions.
  void EliminateDeadStores(llvm::Function *func) const;

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

  // Maps a register to a sequence of offsets that can be used in a GEP
  // instruction.
  std::vector<std::vector<llvm::Value *>> reg_to_index_seq;

  // Maps a register to its LLVM type.
  std::vector<llvm::Type *> reg_to_type;

  // Maps instructions/values in a function to their associated register
  // number. In general, the only represented values are those relating to
  // memory operations, e.g. bit casts, loads, stores, and GEPs.
  std::unordered_map<const llvm::Value *, int> inst_to_reg;

  // Maps basic blocks to their live and killed sets.
  std::unordered_map<llvm::BasicBlock *, RegUses> block_transfer_functions;

  // This intrinsic represents asking the system for some information, but the
  // implementation of it is opaque and so it can modify any register state.
  // We need to treat calls to this intrinsic as making all registers live.
  llvm::Function *sync_hyper_call;

 private:
  StateMap(void) = delete;

  void AssignReg(size_t offset, size_t size, int reg, llvm::Type *type);

  size_t SizeOfType(llvm::Type *) const;
  size_t SizeOfValue(const llvm::Value *) const;
  size_t IndexType(llvm::Type *, size_t offset);
  size_t GetGEPIndexSeq(const llvm::GetElementPtrInst *gep_inst);

  void ApplyInstructionTransferFunction(llvm::Instruction *inst,
                                        RegUses *transfer) const;

  void InitBlockTransferFunction(llvm::BasicBlock *block, RegUses *transfer);
};

StateMap::StateMap(llvm::Module *module, llvm::Type *state_type)
    : data_layout(module),
      num_regs(1),  // So that we can use `0` to mean unassigned.
      offset_to_reg(SizeOfType(state_type), -1),
      reg_to_size(kMaxNumRegs, 0),
      reg_to_type(kMaxNumRegs),
      inst_to_reg(),
      sync_hyper_call(module->getFunction("__remill_sync_hyper_call")) {

  IndexType(state_type, 0);

  CHECK(static_cast<int>(kMaxNumRegs) > num_regs)
      << "Too many registers for bitmap! Change kMaxNumRegs and recompile.";

  size_t num_blocks = 0;
  for (llvm::Function &func : *module) {
    if (!func.isDeclaration()) {
      num_blocks += func.size();
    }
  }

  block_transfer_functions.reserve(num_blocks);
}

// Gets the size of an llvm value.
size_t StateMap::SizeOfValue(const llvm::Value *value) const {
  return SizeOfType(value->getType());
}

size_t StateMap::SizeOfType(llvm::Type *type) const {
  return data_layout.getTypeStoreSize(type);
}

// Assign a register to a sequence of bytes within the offset map, and record
// the size of this register.
void StateMap::AssignReg(size_t offset, size_t size, int reg,
                         llvm::Type *type) {

  CHECK(static_cast<int>(kMaxNumRegs) > reg)
      << "Too many registers for bitmap! Change kMaxNumRegs and recompile.";

  if (reg > 0) {
    LOG(INFO)
        << "Register " << reg << " covers [" << offset
        << ", " << (offset + size) << ")";

    for (auto i = offset; i < (offset + size); ++i) {
      offset_to_reg[i] = reg;
    }

    reg_to_size[reg] = size;
    reg_to_type[reg] = type;
  }
}

// Recursively visit the values store within the system state structure, and
// assign a register to each value. The registers assigned are stored in the
// `system_regs` map according to their offset within the state structure.
size_t StateMap::IndexType(llvm::Type *type, size_t offset) {

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

// Get the index sequence of a GEP instuction. For GEPs that access the system
// register state, this allows us to index into the `system_regs` map in order
// to find the correct system register. In cases where we're operating on a
// bitcast system register, this lets us find the offset into that register.
size_t StateMap::GetGEPIndexSeq(const llvm::GetElementPtrInst *gep_inst) {
  llvm::APInt offset(64, 0);
  const auto found_offset = gep_inst->accumulateConstantOffset(
      data_layout, offset);

  CHECK(found_offset)
      << "Index operands to GEPs must be constant.";

  return offset.getZExtValue();
}

void StateMap::AssignRegisters(llvm::Function *func) {
  inst_to_reg.clear();

  auto state_ptr = &(*++func->arg_begin());
  auto func_name = func->getName().str();
  std::queue<llvm::Instruction *> work_list;
  std::set<llvm::Instruction *> seen;

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
          auto reg = offset_to_reg[GetGEPIndexSeq(gep_inst)];
          CHECK(0 != reg)
              << "Unable to locate system register associated with a "
              << "`getelementptr` instuction in function "
              << func_name << ".";

          inst_to_reg[gep_inst] = reg;
          seen.insert(&inst);
        } else {
          work_list.push(&inst);
        }

      // Wait until we have most pointers already resolved.
      } else if (auto cast_inst = llvm::dyn_cast<llvm::BitCastInst>(&inst)) {
        auto dest_is_ptr = cast_inst->getType()->isPointerTy();
        auto src_is_ptr = cast_inst->getSrcTy()->isPointerTy();
        if (dest_is_ptr) {
          if (!src_is_ptr) {
            LOG(FATAL)
                << "Found non pointer-to-pointer cast in function " << func_name
                << ": " << remill::LLVMThingToString(&inst);
          }
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
        seen.insert(&inst);
      }
    }
  }

  // Resolve the instructions that create or load values from pointers into
  // registers. Ideally, every pointer should be formed from a register in
  // the machine state structure.
  while (!work_list.empty()) {
    std::queue<llvm::Instruction *> next_work_list;

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
          seen.insert(gep_inst);
          inst_to_reg[gep_inst] = reg;
        } else {
          next_work_list.push(gep_inst);
        }

      // (Most) Bitcast instructions operate as aliases to things.
      } else if (auto cast_inst = llvm::dyn_cast<llvm::BitCastInst>(inst)) {
        if (auto reg = inst_to_reg[cast_inst->getOperand(0)]) {
          seen.insert(cast_inst);
          inst_to_reg[cast_inst] = reg;
        } else {
          next_work_list.push(cast_inst);
        }

      } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
        auto source_ptr = load_inst->getPointerOperand();
        auto source_inst = llvm::dyn_cast<llvm::Instruction>(source_ptr);

        if (auto reg = inst_to_reg[source_ptr]) {
          seen.insert(load_inst);

        } else if (source_inst) {
          next_work_list.push(source_inst);
        }

      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        auto dest_ptr = store_inst->getPointerOperand();
        if (!inst_to_reg[dest_ptr]) {
          auto dest_inst = llvm::dyn_cast<llvm::Instruction>(dest_ptr);
          if (!dest_inst) {
            LOG(FATAL)
                << "Storing to a non-instruction in function "
                << func_name << ": " << remill::LLVMThingToString(inst);
          }
          next_work_list.push(dest_inst);
        }

      // PHI node.
      } else if (auto phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
        auto &phi_reg = inst_to_reg[phi];
        auto need_more = false;
        for (auto &use : phi->incoming_values()) {
          auto val = llvm::dyn_cast<llvm::Instruction>(use.get());
          if (!val) {
            LOG(FATAL)
                << "Cannot allocate register for PHI node in function "
                << func_name << " whose incoming values are not instructions: "
                << remill::LLVMThingToString(phi);
          }

          if (auto reg = inst_to_reg[val]) {
            if (!phi_reg) {
              phi_reg = reg;

            } else if (phi_reg != reg) {
              LOG(FATAL)
                  << "PHI node must join the same register in function "
                  << func_name << ": " << remill::LLVMThingToString(inst);
            }
          } else {
            next_work_list.push(val);
            need_more = true;
          }
        }

        if (need_more) {
          next_work_list.push(phi);
        }

      // Shouldn't be possible.
      } else {
        LOG(FATAL)
            << "Got to an impossible state when assigning registers "
            << "in function " << func_name << ": "
            << remill::LLVMThingToString(inst);
      }
    }
    work_list.swap(next_work_list);
  }
}

void StateMap::ReassociateRegisters(llvm::Function *func) {
  auto state_ptr = &(*++func->arg_begin());

  std::vector<llvm::GetElementPtrInst *> to_move;
  for (auto &block : *func) {
    for (auto &inst : block) {
      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        if (gep_inst->getPointerOperand() == state_ptr) {
          to_move.push_back(gep_inst);
        }
      }
    }
  }

  if (to_move.empty()) {
    return;
  }

  // Sort the GEP instructions by the offset being accessed.
  std::sort(to_move.begin(), to_move.end(),
            [=] (llvm::GetElementPtrInst *a, llvm::GetElementPtrInst *b) {
                return GetGEPIndexSeq(a) < GetGEPIndexSeq(b);
            });

  // Move all GEPs into the beginning of the entry block.
  auto entry_block = &func->getEntryBlock();
  auto &inst_list = entry_block->getInstList();
  size_t last_offset = 0;
  llvm::GetElementPtrInst *last_gep_inst = nullptr;

  for (auto gep_inst : to_move) {
    auto offset = GetGEPIndexSeq(gep_inst);
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
}

void StateMap::EliminateDeadStores(llvm::Function *func) const {
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
void StateMap::ApplyInstructionTransferFunction(llvm::Instruction *inst,
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

void StateMap::InitBlockTransferFunction(llvm::BasicBlock *block,
                                         RegUses *transfer) {
  auto it = block->rbegin();
  auto end = block->rend();
  for (; it != end; ++it) {
    ApplyInstructionTransferFunction(&(*it), transfer);
  }
}

// Initialize the flows within the function.
void StateMap::InitBlockTransferFunctions(llvm::Function *func) {
  for (auto &block : *func) {
    auto &transfer = block_transfer_functions[&block];
    InitBlockTransferFunction(&block, &transfer);
  }
}

static void RemoveISelVars(llvm::Module *module) {
  std::vector<llvm::GlobalVariable *> isels;
  for (auto &var : module->globals()) {
    if (!var.getName().startswith("__remill")) {
      LOG(INFO)
          << "Removing ISEL definition " << var.getName().str();
      isels.push_back(&var);
    }
  }
  for (auto isel : isels) {
    isel->eraseFromParent();
  }
}

static void StripDebugInfo(llvm::Module *module) {
  if (FLAGS_strip) {
    llvm::legacy::PassManager module_manager;
    module_manager.add(llvm::createStripDebugDeclarePass());
    module_manager.add(llvm::createStripSymbolsPass(true /* OnlyDebugInfo */));
    module_manager.add(llvm::createStripDeadDebugInfoPass());
    module_manager.run(*module);
  }
}

static void RemoveFunction(llvm::Module *module, llvm::StringRef name) {
  if (auto func = module->getFunction(name)) {
    if (!func->hasNUsesOrMore(1)) {
      func->removeFromParent();
      delete func;
    }
  }
}

static void RemoveDeadIntrinsics(llvm::Module *module) {
  RemoveFunction(module, "__remill_intrinsics");
  RemoveFunction(module, "__remill_mark_as_used");
  RemoveFunction(module, "__remill_defer_inlining");
  RemoveFunction(module, "__remill_undefined_8");
  RemoveFunction(module, "__remill_undefined_16");
  RemoveFunction(module, "__remill_undefined_32");
  RemoveFunction(module, "__remill_undefined_64");
  RemoveFunction(module, "__remill_undefined_f32");
  RemoveFunction(module, "__remill_undefined_f64");
}

static void RemoveUnusedSemantics(llvm::Module *module) {
  std::vector<llvm::Function *> to_remove;
  for (auto &func : *module) {
    if (!func.getName().startswith("__remill")) {
      to_remove.push_back(&func);
    }
  }
  for (auto func : to_remove) {
    if (!func->hasNUsesOrMore(1)) {
      func->removeFromParent();
      delete func;
    }
  }
}

static void DisableBlockInlining(llvm::Module *module) {
  for (auto &func : *module) {
    if (!func.getName().startswith("__remill_sub")) {
      continue;
    }

    // Don't inline across calls to block functions.
    func.removeFnAttr(llvm::Attribute::AlwaysInline);
    func.removeFnAttr(llvm::Attribute::InlineHint);
    func.addFnAttr(llvm::Attribute::NoInline);
  }
}

static void Optimize(llvm::Module *module) {
  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;  // -O3.
  builder.SizeLevel = 2;  // -Oz
  builder.Inliner = llvm::createFunctionInliningPass(128);
  builder.DisableTailCalls = false;  // Enable tail calls.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = false;  // Don't produce vector operations.
  builder.LoopVectorize = false;  // Don't produce vector operations.
  builder.LoadCombine = false;  // Don't coalesce loads.
  builder.MergeFunctions = false;  // Try to deduplicate functions.
  builder.VerifyInput = true;  // Sanity checking.
  builder.VerifyOutput = true;  // Sanity checking.

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);

  func_manager.doInitialization();
  for (auto &func : *module) {
    if (!func.getName().startswith("__remill")) {
      continue;
    }
    func_manager.run(func);
  }

  func_manager.doFinalization();
  module_manager.run(*module);
}

// Gets the state structure type from this module.
static llvm::Type *GetStateType(llvm::Module *module) {
  llvm::Function *bb_func = nullptr;
  for (auto &func : *module) {
    if (func.getName().startswith("__remill_sub")) {
      bb_func = &func;
      break;
    }
  }

  CHECK(nullptr != bb_func)
      << "Module does not contain any lifted blocks!";

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

// Perform inter-procedural dead store elimination on accesses to the `State`
// structure.
static void InterProceduralDeadStoreElimination(llvm::Module *module) {
  StateMap map(module, GetStateType(module));
  for (auto &func : *module) {
    if (func.getName().startswith("__remill_sub")) {
      map.ReassociateRegisters(&func);
      map.AssignRegisters(&func);
      map.InitBlockTransferFunctions(&func);
    }
  }

  std::set<llvm::BasicBlock *> work_list;
  std::vector<llvm::BasicBlock *> preds;
  std::vector<llvm::BasicBlock *> succs;

  // Set the base case of the data flow computation.
  for (auto &trans_entry : map.block_transfer_functions) {
    auto block = trans_entry.first;
    GetBlockSuccessors(block, succs);
    if (succs.empty()) {
      auto &transfer = trans_entry.second;
      transfer.incoming_live.set();  // Base case.
      GetBlockPredecessors(block, preds);
      work_list.insert(preds.begin(), preds.end());
    }
  }

  // Iterate towards a fixed point until the work list empties or until we
  // reach the maximum number of iterations of the data flow algorithm.
  for (auto i = 0ULL; i < FLAGS_aggressiveness && !work_list.empty(); ++i) {
    std::set<llvm::BasicBlock *> next_work_list;

    LOG(INFO)
        << "Work list size is " << work_list.size();

    for (auto block : work_list) {

      GetBlockSuccessors(block, succs);
      if (succs.empty()) {
        continue;
      }

      RegBitMap new_incoming;
      for (auto succ_block : succs) {
        const auto &succ_transfer = map.block_transfer_functions.at(succ_block);
        new_incoming |= (succ_transfer.incoming_live & succ_transfer.local_dead);
        new_incoming |= succ_transfer.local_live;
      }

      auto &transfer = map.block_transfer_functions.at(block);
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

  // Eliminate dead stores.
  for (auto &func : *module) {
    if (func.getName().startswith("__remill_sub")) {
      map.AssignRegisters(&func);
      map.EliminateDeadStores(&func);
    }
  }
}

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  std::vector<llvm::CallInst *> call_insts;
  for (auto callers : function->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(callers)) {
      call_insts.push_back(call_inst);
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
static void EnableDeferredInlining(llvm::Module *module) {
  auto defer_inlining_func = module->getFunction("__remill_defer_inlining");
  if (!defer_inlining_func) {
    return;
  }

  std::vector<llvm::CallInst *> call_insts;
  std::set<llvm::Function *> processed_funcs;

  // Find all calls to the inline defer intrinsic.
  for (auto caller : defer_inlining_func->users()) {
    if (auto call_inst = llvm::dyn_cast_or_null<llvm::CallInst>(caller)) {
      call_insts.push_back(call_inst);
    }
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
}

void LowerMemOps(llvm::Module *module) {
  (void) module;
//  llvm::Function *accessors[] = {
//      module->getFunction("__remill_read_memory_8"),
//      module->getFunction("__remill_read_memory_16"),
//      module->getFunction("__remill_read_memory_32"),
//      module->getFunction("__remill_read_memory_64"),
//      module->getFunction("__remill_write_memory_8"),
//      module->getFunction("__remill_write_memory_16"),
//      module->getFunction("__remill_write_memory_32"),
//      module->getFunction("__remill_write_memory_64"),
//      module->getFunction("__remill_read_memory_f32"),
//      module->getFunction("__remill_read_memory_f64"),
//      module->getFunction("__remill_read_memory_f80"),
//      module->getFunction("__remill_write_memory_f32"),
//      module->getFunction("__remill_write_memory_f64"),
//      module->getFunction("__remill_write_memory_f80"),
//  };
//  auto &context = module->getContext();
//  auto new_mem_ptr_type = llvm::Type::getInt8PtrTy(context, 0);
//  for (auto &func : *module) {
//    llvm::Argument *mem_ptr = nullptr;
//    auto &func_name = func.getName();
//    if (func_name.startswith("__remill_")) {
//      if (func_name.startswith("__remill_barrier") ||
//          func_name.startswith("__remill_atomic")) {
//
//      } else {
//
//      }
//    }
//  }
//  auto mem_ptr = &(*++accessors[0]->arg_begin());
//  auto mem_ptr_type = memory_ptr->getType();
//  memory_ptr_type->
}

}  // namespace

int main(int argc, char *argv[]) {
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --bc_in INPUT_BC_FILE \\" << std::endl
     << "    --bc_out OUTPUT_BC_FILE \\" << std::endl
     << "    [--server]" << std::endl
     << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(!FLAGS_bc_in.empty())
      << "Please specify an input bitcode file with --bc_in.";

  CHECK(remill::FileExists(FLAGS_bc_in))
      << "Input bitcode file " << FLAGS_bc_in << " does not exist.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an output bitcode file with --bc_out.";

  do {
    auto context = new llvm::LLVMContext;
    auto module = remill::LoadModuleFromFile(context, FLAGS_bc_in);

    StripDebugInfo(module);
    RemoveISelVars(module);
    DisableBlockInlining(module);
    Optimize(module);
    InterProceduralDeadStoreElimination(module);
    RemoveUndefFuncCalls(module);
    EnableDeferredInlining(module);
    Optimize(module);
    RemoveDeadIntrinsics(module);
    RemoveUnusedSemantics(module);
    StripDebugInfo(module);
    if (FLAGS_lower_memops) {
      LowerMemOps(module);
    }
    remill::StoreModuleToFile(module, FLAGS_bc_out);
    delete module;
    delete context;
  } while (FLAGS_server);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}
