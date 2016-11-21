/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cstdio>
#include <cstring>

#include <algorithm>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IntrinsicInst.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

#include "tools/vmill/BC/Lifter.h"
#include "tools/vmill/Emulator/ByteCode/Cache.h"
#include "tools/vmill/Emulator/ByteCode/Compiler.h"

namespace remill {
namespace vmill {
namespace {

static constexpr VarId kUnresolvedVar = static_cast<uint8_t>(~0UL);

}  // namespace

struct CompiledFunction {
  explicit CompiledFunction(uint64_t pc_)
      : num_unresolved(0),
        pc(pc_),
        succ_ids{kUnresolvedVar, kUnresolvedVar},
        succ_funcs{nullptr, nullptr},
        ops(),
        inst_to_var(),
        const_to_var(),
        compiled_offset(0) {}

  unsigned num_unresolved;
  const uint64_t pc;
  VarId succ_ids[2];
  llvm::Function *succ_funcs[2];
  std::vector<Operation> ops;
  std::unordered_map<llvm::Value *, VarId> inst_to_var;
  std::unordered_map<uint64_t, VarId> const_to_var;
  size_t compiled_offset;
};

// Represents in-flight compiled bytecode.
struct TranslationUnit {
  explicit TranslationUnit(llvm::Module *module, size_t starting_offset_)
      : data_layout(module),
        arch_state_size(0),
        state_offset(),
        const_to_offset(),
        constant_table(),
        bitcode_func(nullptr),
        bytecode_func(nullptr),
        starting_offset(starting_offset_),
        read_mem_8(module->getFunction("__remill_read_memory_8")),
        read_mem_16(module->getFunction("__remill_read_memory_16")),
        read_mem_32(module->getFunction("__remill_read_memory_32")),
        read_mem_64(module->getFunction("__remill_read_memory_64")),
        read_mem_f32(module->getFunction("__remill_read_memory_f32")),
        read_mem_f64(module->getFunction("__remill_read_memory_f64")),
        read_mem_f80(module->getFunction("__remill_read_memory_f80")),
        write_mem_8(module->getFunction("__remill_write_memory_8")),
        write_mem_16(module->getFunction("__remill_write_memory_16")),
        write_mem_32(module->getFunction("__remill_write_memory_32")),
        write_mem_64(module->getFunction("__remill_write_memory_64")),
        write_mem_f32(module->getFunction("__remill_write_memory_f32")),
        write_mem_f64(module->getFunction("__remill_write_memory_f64")),
        write_mem_f80(module->getFunction("__remill_write_memory_f80")),
        barrier_load_load(module->getFunction("__remill_barrier_load_load")),
        barrier_load_store(module->getFunction("__remill_barrier_load_store")),
        barrier_store_load(module->getFunction("__remill_barrier_store_load")),
        barrier_store_store(
            module->getFunction("__remill_barrier_store_store")),
        atomic_begin(module->getFunction("__remill_atomic_begin")),
        atomic_end(module->getFunction("__remill_atomic_end")),
        sync_hypercall(module->getFunction("__remill_sync_hyper_call")),
        function_call(module->getFunction("__remill_function_call")),
        function_return(module->getFunction("__remill_function_return")),
        indirect_jump(module->getFunction("__remill_jump")),
        async_hypercall(module->getFunction("__remill_async_hyper_call")),
        error(module->getFunction("__remill_error")) {}

  void CompileFunction(const uint64_t pc, llvm::Function *lifed_func);

  // If this value is a constant in our constant pool,
  // then add an immediate operation into our operations list
  // and return the variable ID for that immediate operation,
  // otherwise return the unresolved variable ID.
  VarId TryResolve(llvm::Value *value);

  // Gets the offset from a base pointer.
  size_t GetOffsetFromBasePtr(llvm::GetElementPtrInst *gep_inst);

  // Find offsets into the state structure or adjacent "local storage"
  // for every related memory access instruction.
  uint64_t AssignLocalStoreOffsets(void);

  template <typename T>
  VarId AppendOperation(const T &op, llvm::Value *whence);

  Operation::State CreateStateRead(llvm::Value *val, size_t size);
  Operation::State CreateStateWrite(llvm::Value *val, size_t size,
                                    VarId src_var);

  template <typename T>
  void AppendConstant(const T &op, llvm::Value *whence, uint64_t val);

  void CompileGEP(llvm::GetElementPtrInst *inst);
  void CompileBitCast(llvm::BitCastInst *inst);
  void CompileBranch(llvm::BranchInst *inst);
  void CompileLoad(llvm::LoadInst *inst);
  void CompileStore(llvm::StoreInst *inst);
  void CompileBinary(llvm::BinaryOperator *inst);
  void CompileCast(llvm::CastInst *inst);
  void CompileCompare(llvm::CmpInst *inst);
  void AllocatePhi(llvm::PHINode *inst);
  void CompilePHI(llvm::PHINode *inst);
  void CompileSelect(llvm::SelectInst *inst);
  void CompileCall(llvm::CallInst *inst);
  void CompileMemSet(llvm::MemSetInst *inst);
  void CompileMemCopy(llvm::MemCpyInst *inst);
  void CompileIntrinsic(llvm::IntrinsicInst *inst);
  void Compile(llvm::Instruction *inst);

  void InternConstant(llvm::Constant *val);
  void InternConstants(void);
  void CompileConstants(void);

  llvm::DataLayout data_layout;

  std::unordered_map<uint64_t, CompiledFunction *> pc_to_bytecode;
  std::unordered_map<llvm::Function *, uint64_t> bitcode_to_pc;

  // Maps LLVM instructions (stores, loads) to the offset into the state
  // structure or adjacent local stores where local/state data is stored.
  size_t arch_state_size;
  std::unordered_map<llvm::Value *, size_t> state_offset;

  // Set of memory pointers or aliases thereof.
  std::set<llvm::Value *> mem_ptrs;

  // Maps actual constant values to where they are located in the pool.
  std::unordered_map<uint64_t, uint64_t> const_to_offset;

  // List of constants that we will place into the global constant pool.
  std::vector<uint64_t> constant_table;

  // Actively translated functions.
  llvm::Function *bitcode_func;
  CompiledFunction *bytecode_func;

  // First offset at which we will place constants into
  // the global constant pool.
  size_t starting_offset;

  // Intrinsics that we can match.
  llvm::Function * const read_mem_8;
  llvm::Function * const read_mem_16;
  llvm::Function * const read_mem_32;
  llvm::Function * const read_mem_64;
  llvm::Function * const read_mem_f32;
  llvm::Function * const read_mem_f64;
  llvm::Function * const read_mem_f80;
  llvm::Function * const write_mem_8;
  llvm::Function * const write_mem_16;
  llvm::Function * const write_mem_32;
  llvm::Function * const write_mem_64;
  llvm::Function * const write_mem_f32;
  llvm::Function * const write_mem_f64;
  llvm::Function * const write_mem_f80;
  llvm::Function * const barrier_load_load;
  llvm::Function * const barrier_load_store;
  llvm::Function * const barrier_store_load;
  llvm::Function * const barrier_store_store;
  llvm::Function * const atomic_begin;
  llvm::Function * const atomic_end;
  llvm::Function * const sync_hypercall;
  llvm::Function * const function_call;
  llvm::Function * const function_return;
  llvm::Function * const indirect_jump;
  llvm::Function * const async_hypercall;
  llvm::Function * const error;
};

class BCC final : public ByteCodeCompiler {
 public:
  virtual ~BCC(void);

  BCC(ByteCodeIndex *index_,
      ByteCodeCache *cache_,
      ConstantPool *constants_);

  // Return the bytecode for some program counter. If it doesn't exist,
  // then compile it on the spot.
  void Compile(llvm::Module *module) override;

 private:
  void Compile(TranslationUnit *tu);
};

ByteCodeCompiler::ByteCodeCompiler(ByteCodeIndex *index_,
                                   ByteCodeCache *cache_,
                                   ConstantPool *constants_)
    : index(index_),
      cache(cache_),
      constants(constants_) {}

ByteCodeCompiler::~ByteCodeCompiler(void) {}

// Create a new LLVM bitcode-to-bytecode compiler.
ByteCodeCompiler *ByteCodeCompiler::Create(ByteCodeIndex *index_,
                                           ByteCodeCache *cache_,
                                           ConstantPool *constants_) {
  DLOG(INFO)
      << "Creating LLVM bitcode to bytecode compiler.";

  return new BCC(index_, cache_, constants_);
}

BCC::BCC(ByteCodeIndex *index_,
         ByteCodeCache *cache_,
         ConstantPool *constants_)
    : ByteCodeCompiler(index_, cache_, constants_) {}

BCC::~BCC(void) {}

void BCC::Compile(llvm::Module *module) {
  auto tu = new TranslationUnit(module, constants->NumEntries());

  // Compile each function to a bytecode function.
  Lifter::ForEachLiftedFunctionInModule(module,
      [=] (uint64_t func_pc, llvm::Function *func) {
        tu->CompileFunction(func_pc, func);
      });

  Compile(tu);
  delete tu;
}

// Get the index sequence of a GEP instruction. For GEPs that access the system
// register state, this allows us to index into the `system_regs` map in order
// to find the correct system register. In cases where we're operating on a
// bitcast system register, this lets us find the offset into that register.
size_t TranslationUnit::GetOffsetFromBasePtr(
    llvm::GetElementPtrInst *gep_inst) {
  llvm::APInt offset(64, 0);
  const auto found_offset = gep_inst->accumulateConstantOffset(
      data_layout, offset);

  CHECK(found_offset)
      << "Index operands to GEPs must be constant.";

  return offset.getZExtValue();
}

// Find offsets into the state structure or adjacent "local storage" for every
// related memory access instruction.
uint64_t TranslationUnit::AssignLocalStoreOffsets(void) {
  std::queue<llvm::Value *> work_list;

  struct Local {
    llvm::Instruction *inst;
    size_t alloc_size;
  };

  std::vector<Local> locals;

  auto state_ptr = NthArgument(bitcode_func, remill::kStatePointerArgNum);
  auto state_ptr_type = llvm::dyn_cast<llvm::PointerType>(state_ptr->getType());
  auto state_size = data_layout.getTypeStoreSize(
      state_ptr_type->getElementType());

  arch_state_size = (state_size + 4095ULL) & ~4095ULL;  // Round it up.

  auto func_name = bitcode_func->getName().str();

  work_list.push(NthArgument(bitcode_func, remill::kMemoryPointerArgNum));

  mem_ptrs.clear();
  while (work_list.size()) {
    auto inst = work_list.front();
    work_list.pop();
    mem_ptrs.insert(inst);

    for (auto user : inst->users()) {
      if (!mem_ptrs.count(user)) {
        work_list.push(user);
      }
    }
  }

  CHECK(work_list.empty())
      << "Unable to identify all memory pointer related operations in "
      << func_name;

  // Fill in the work list with memory-related operations. First, assign
  // pseudo registers to the allocas, and enqueue all other memory-related
  // instructions.
  for (auto &basic_block : *bitcode_func) {
    for (auto &inst : basic_block) {
      if (auto alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(&inst)) {
        locals.push_back({
            alloca_inst,
            data_layout.getTypeStoreSize(alloca_inst->getAllocatedType())});

      } else if (llvm::isa<llvm::LoadInst>(&inst) ||
                 llvm::isa<llvm::StoreInst>(&inst) ||
                 llvm::isa<llvm::GetElementPtrInst>(&inst)) {
        work_list.push(&inst);

      } else if (llvm::isa<llvm::BitCastInst>(&inst)) {
        work_list.push(&inst);

      } else if (llvm::isa<llvm::PHINode>(&inst)) {
        if (inst.getType()->isPointerTy()) {
          work_list.push(&inst);
        } else {
          locals.push_back({
              &inst,
              data_layout.getTypeStoreSize(inst.getType())});
        }
      }
    }
  }

  // Sort the allocas from big to small in terms of allocated size.
  std::sort(
      locals.begin(), locals.end(),
      [] (const Local &a, const Local &b) -> bool {
        return b.alloc_size < a.alloc_size;
      });

  // Base case for GEPs into the state struct.
  auto offset = arch_state_size;
  state_offset.clear();
  state_offset[state_ptr] = 0;

  // Map the allocas to a byte offset within the local/register state
  // structure.
  for (auto local : locals) {
    state_offset[local.inst] = offset;
    offset += local.alloc_size;
  }

  // Auto-assign registers for GEPs and LOADs, and BITCASTs.
  for (bool made_progress = true; made_progress && !work_list.empty(); ) {
    made_progress = false;
    std::queue<llvm::Value *> new_work_list;
    while (work_list.size()) {
      auto inst = work_list.front();
      work_list.pop();
      if (mem_ptrs.count(inst)) {
        made_progress = true;
        continue;
      }

      // Ideally, loading the address of a register within the machine
      // state structure.
      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(inst)) {
        auto base_ptr = gep_inst->getPointerOperand();
        if (state_offset.count(base_ptr)) {
          auto offset_from_base = GetOffsetFromBasePtr(gep_inst);
          auto offset_from_state = state_offset[base_ptr];
          state_offset[gep_inst] = offset_from_state + offset_from_base;
          made_progress = true;
        } else {
          new_work_list.push(inst);
        }

      // Wait until we have most pointers already resolved.
      } else if (auto cast_inst = llvm::dyn_cast<llvm::BitCastInst>(inst)) {
        auto src_ptr = cast_inst->getOperand(0);
        if (state_offset.count(src_ptr)) {
          state_offset[cast_inst] = state_offset[src_ptr];
          made_progress = true;
        } else {
          new_work_list.push(inst);
        }

      // Look at the source pointer.
      } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(inst)) {
        auto src_ptr = load_inst->getPointerOperand();
        if (state_offset.count(src_ptr)) {
          state_offset[load_inst] = state_offset[src_ptr];
          made_progress = true;
        } else {
          new_work_list.push(inst);
        }

      // Look at the destination pointer.
      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        auto src_ptr = store_inst->getPointerOperand();
        if (state_offset.count(src_ptr)) {
          state_offset[store_inst] = state_offset[src_ptr];
          made_progress = true;
        } else {
          new_work_list.push(inst);
        }

      // PHI of two pointers.
      } else if (auto phi_node = llvm::dyn_cast<llvm::PHINode>(inst)) {
        auto first_op = phi_node->getIncomingValue(0);
        if (state_offset.count(first_op)) {
          state_offset[phi_node] = state_offset[first_op];
          made_progress = true;
        } else {
          new_work_list.push(inst);
        }
      }
    }
    work_list.swap(new_work_list);
  }

  // This shouldn't happen.
  if (!work_list.empty()) {
    std::stringstream ss;
    while (!work_list.empty()) {
      auto inst = work_list.front();
      work_list.pop();
      ss << std::endl << LLVMThingToString(inst);
    }

    LOG(FATAL)
        << "Unable to assign state offsets to all pointer-related operations "
        << "in " << func_name << ": " << ss.str();
  }

  return state_size;
}

namespace {

static OpCode::Name Choose8To128(
    size_t size, OpCode::Name op_8, OpCode::Name op_16,
    OpCode::Name op_32, OpCode::Name op_64, OpCode::Name op_128) {
  switch (size) {
    case 1: return op_8;
    case 2: return op_16;
    case 4: return op_32;
    case 8: return op_64;
    case 16: return op_128;
    default:
      LOG(FATAL)
          << "Unsupported OpCode for " << size << " bytes.";
  }
}

static OpCode::Name Choose32To64(
    size_t size, OpCode::Name op_32, OpCode::Name op_64) {
  switch (size) {
    case 4: return op_32;
    case 8: return op_64;
    default:
      LOG(FATAL)
          << "Unsupported OpCode for " << size << " bytes.";
  }
}

static OpCode::Name TableLookup32x64(size_t size_1, size_t size_2,
                                     OpCode::Name case_88,
                                     OpCode::Name case_84,
                                     OpCode::Name case_48,
                                     OpCode::Name case_44) {
  if (8 == size_1) {
    if (8 == size_2) {
      return case_88;
    } else if (4 == size_2) {
      return case_84;
    }
  } else if (4 == size_1) {
    if (8 == size_2) {
      return case_48;
    } else if (4 == size_2) {
      return case_44;
    }
  }

  LOG(FATAL)
      << "Lookup for a conversion from a " << size_1 << "-byte value "
      << "to a " << size_2 << "-byte value failed.";
}


static OpCode::Name GetOpCode(llvm::BinaryOperator *inst,
                              size_t inst_size,
                              size_t op_size) {
  const auto op_code = inst->getOpcode();
  switch (op_code) {
    case llvm::Instruction::Add:
      return Choose8To128(inst_size, OpCode::kAdd8, OpCode::kAdd16,
                          OpCode::kAdd32, OpCode::kAdd64, OpCode::kAdd128);
    case llvm::Instruction::FAdd:
      return Choose32To64(inst_size, OpCode::kFAdd32, OpCode::kFAdd64);
    case llvm::Instruction::Sub:
      return Choose8To128(inst_size, OpCode::kSub8, OpCode::kSub16,
                          OpCode::kSub32, OpCode::kSub64, OpCode::kSub128);
    case llvm::Instruction::FSub:
      return Choose32To64(inst_size, OpCode::kFSub32, OpCode::kFSub64);
    case llvm::Instruction::Mul:
      return Choose8To128(inst_size, OpCode::kMul8, OpCode::kMul16,
                          OpCode::kMul32, OpCode::kMul64, OpCode::kMul128);
    case llvm::Instruction::FMul:
      return Choose32To64(inst_size, OpCode::kFMul32, OpCode::kFMul64);
    case llvm::Instruction::UDiv:
      return Choose8To128(inst_size, OpCode::kUDiv8, OpCode::kUDiv16,
                          OpCode::kUDiv32, OpCode::kUDiv64, OpCode::kUDiv128);
    case llvm::Instruction::SDiv:
      return Choose8To128(inst_size, OpCode::kSDiv8, OpCode::kSDiv16,
                          OpCode::kSDiv32, OpCode::kSDiv64, OpCode::kSDiv128);
    case llvm::Instruction::FDiv:
      return Choose32To64(inst_size, OpCode::kFDiv32, OpCode::kFDiv64);
    case llvm::Instruction::URem:
      return Choose8To128(inst_size, OpCode::kURem8, OpCode::kURem16,
                          OpCode::kURem32, OpCode::kURem64, OpCode::kURem128);
    case llvm::Instruction::SRem:
      return Choose8To128(inst_size, OpCode::kSRem8, OpCode::kSRem16,
                          OpCode::kSRem32, OpCode::kSRem64, OpCode::kSRem128);
    case llvm::Instruction::FRem:
      return Choose32To64(inst_size, OpCode::kFRem32, OpCode::kFRem64);
    case llvm::Instruction::Shl:
      return Choose8To128(inst_size, OpCode::kShl8, OpCode::kShl16,
                          OpCode::kShl32, OpCode::kShl64, OpCode::kShl128);
    case llvm::Instruction::LShr:
      return Choose8To128(inst_size, OpCode::kLShr8, OpCode::kLShr16,
                          OpCode::kLShr32, OpCode::kLShr64, OpCode::kLShr128);
    case llvm::Instruction::AShr:
      return Choose8To128(inst_size, OpCode::kAShr8, OpCode::kAShr16,
                          OpCode::kAShr32, OpCode::kAShr64, OpCode::kAShr128);
    case llvm::Instruction::And:
      return Choose8To128(inst_size, OpCode::kAnd8, OpCode::kAnd16,
                          OpCode::kAnd32, OpCode::kAnd64, OpCode::kAnd128);
    case llvm::Instruction::Or:
      return Choose8To128(inst_size, OpCode::kOr8, OpCode::kOr16, OpCode::kOr32,
                          OpCode::kOr64, OpCode::kOr128);
    case llvm::Instruction::Xor:
      return Choose8To128(inst_size, OpCode::kXor8, OpCode::kXor16,
                          OpCode::kXor32, OpCode::kXor64, OpCode::kXor128);
    default:
      LOG(FATAL)
          << "Unsupported instruction: " << LLVMThingToString(inst) << ".";
    }
}

static OpCode::Name GetOpCode(llvm::CastInst *inst,
                              size_t inst_size,
                              size_t op_size) {
  const auto op_code = inst->getOpcode();
  switch (op_code) {
    case llvm::Instruction::ZExt:
      return Choose8To128(op_size, OpCode::kZExtFrom8, OpCode::kZExtFrom16,
                          OpCode::kZExtFrom32, OpCode::kZExtFrom64,
                          OpCode::kInvalid);
    case llvm::Instruction::SExt:
      return Choose8To128(op_size, OpCode::kSExtFrom8, OpCode::kSExtFrom16,
                          OpCode::kSExtFrom32, OpCode::kSExtFrom64,
                          OpCode::kInvalid);
    case llvm::Instruction::Trunc:
      return Choose8To128(inst_size, OpCode::kTruncTo8, OpCode::kTruncTo16,
                          OpCode::kTruncTo32, OpCode::kTruncTo64,
                          OpCode::kInvalid);
    case llvm::Instruction::FPToUI:
      return TableLookup32x64(op_size, inst_size, OpCode::kFP64ToUI64,
                              OpCode::kFP64ToUI32, OpCode::kFP32ToUI64,
                              OpCode::kFP32ToUI32);
    case llvm::Instruction::FPToSI:
      return TableLookup32x64(op_size, inst_size, OpCode::kFP64ToSI64,
                              OpCode::kFP64ToSI32, OpCode::kFP32ToSI64,
                              OpCode::kFP32ToSI32);
    case llvm::Instruction::UIToFP:
      return TableLookup32x64(op_size, inst_size, OpCode::kUI64ToFP64,
                              OpCode::kUI64ToFP32, OpCode::kUI32ToFP64,
                              OpCode::kUI32ToFP32);
    case llvm::Instruction::SIToFP:
      return TableLookup32x64(op_size, inst_size, OpCode::kSI64ToFP64,
                              OpCode::kSI64ToFP32, OpCode::kSI32ToFP64,
                              OpCode::kSI32ToFP32);
    case llvm::Instruction::FPTrunc:
      return OpCode::kFPTrunc64To32;
    case llvm::Instruction::FPExt:
      return OpCode::kFPExt32To64;
    default:
      LOG(FATAL)
          << "Unsupported instruction: " << LLVMThingToString(inst) << ".";
  }
}


static OpCode::Name GetOpCode(llvm::CmpInst *inst,
                              size_t inst_size,
                              size_t op_size) {
  const auto pred = inst->getPredicate();
  switch (pred) {
    case llvm::CmpInst::FCMP_OEQ:
    case llvm::CmpInst::FCMP_UEQ:
      return Choose32To64(op_size, OpCode::kFCmpEq32,
                          OpCode::kFCmpEq64);
    case llvm::CmpInst::FCMP_OGT:
    case llvm::CmpInst::FCMP_UGT:
      return Choose32To64(op_size, OpCode::kFCmpGt32,
                          OpCode::kFCmpGt64);
    case llvm::CmpInst::FCMP_OGE:
    case llvm::CmpInst::FCMP_UGE:
      return Choose32To64(op_size, OpCode::kFCmpGe32,
                          OpCode::kFCmpGe64);
    case llvm::CmpInst::FCMP_OLT:
    case llvm::CmpInst::FCMP_ULT:
      return Choose32To64(op_size, OpCode::kFCmpLt32,
                          OpCode::kFCmpLt64);
    case llvm::CmpInst::FCMP_OLE:
    case llvm::CmpInst::FCMP_ULE:
      return Choose32To64(op_size, OpCode::kFCmpLe32,
                          OpCode::kFCmpLe64);
    case llvm::CmpInst::FCMP_ONE:
    case llvm::CmpInst::FCMP_UNE:
      return Choose32To64(op_size, OpCode::kFCmpNe32,
                          OpCode::kFCmpNe64);
    case llvm::CmpInst::ICMP_EQ:
      return Choose8To128(op_size, OpCode::kICmpEq8,
                          OpCode::kICmpEq16,
                          OpCode::kICmpEq32,
                          OpCode::kICmpEq64,
                          OpCode::kICmpEq128);
    case llvm::CmpInst::ICMP_NE:
      return Choose8To128(op_size, OpCode::kICmpNe8,
                          OpCode::kICmpNe16,
                          OpCode::kICmpNe32,
                          OpCode::kICmpNe64,
                          OpCode::kICmpNe128);
    case llvm::CmpInst::ICMP_UGT:
      return Choose8To128(op_size, OpCode::kICmpUgt8,
                          OpCode::kICmpUgt16,
                          OpCode::kICmpUgt32,
                          OpCode::kICmpUgt64,
                          OpCode::kICmpUgt128);
    case llvm::CmpInst::ICMP_UGE:
      return Choose8To128(op_size, OpCode::kICmpUge8,
                          OpCode::kICmpUge16,
                          OpCode::kICmpUge32,
                          OpCode::kICmpUge64,
                          OpCode::kICmpUge128);
    case llvm::CmpInst::ICMP_ULT:
      return Choose8To128(op_size, OpCode::kICmpUlt8,
                          OpCode::kICmpUlt16,
                          OpCode::kICmpUlt32,
                          OpCode::kICmpUlt64,
                          OpCode::kICmpUlt128);
    case llvm::CmpInst::ICMP_ULE:
      return Choose8To128(op_size, OpCode::kICmpUle8,
                          OpCode::kICmpUle16,
                          OpCode::kICmpUle32,
                          OpCode::kICmpUle64,
                          OpCode::kICmpUle128);
    case llvm::CmpInst::ICMP_SGT:
      return Choose8To128(op_size, OpCode::kICmpSgt8,
                          OpCode::kICmpSgt16,
                          OpCode::kICmpSgt32,
                          OpCode::kICmpSgt64,
                          OpCode::kICmpSgt128);
    case llvm::CmpInst::ICMP_SGE:
      return Choose8To128(op_size, OpCode::kICmpSge8,
                          OpCode::kICmpSge16,
                          OpCode::kICmpSge32,
                          OpCode::kICmpSge64,
                          OpCode::kICmpSge128);
    case llvm::CmpInst::ICMP_SLT:
      return Choose8To128(op_size, OpCode::kICmpSlt8,
                          OpCode::kICmpSlt16,
                          OpCode::kICmpSlt32,
                          OpCode::kICmpSlt64,
                          OpCode::kICmpSlt128);
    case llvm::CmpInst::ICMP_SLE:
      return Choose8To128(op_size, OpCode::kICmpSle8,
                          OpCode::kICmpSle16,
                          OpCode::kICmpSle32,
                          OpCode::kICmpSle64,
                          OpCode::kICmpSle128);
    default:
      LOG(FATAL)
          << "Unsupported instruction: " << LLVMThingToString(inst) << ".";
  }
}

}  // namespace

// Append an opcode-specific instantiation of an operation into the list of
// operations. This *may* result in more than one operation being added to
// the list.
//
// This deals with things like inserting delay slots for allocating space
// after an operation (for things like 128-bit integer arithmetic).
template <typename T>
VarId TranslationUnit::AppendOperation(const T &op, llvm::Value *whence) {

  static_assert(sizeof(op) == 4 || sizeof(op) == 8 || sizeof(op) == 12,
                "Invalid sized pseudo-operation.");

  auto num_slots = OpCode::kNumOpSlots[op.op_code];

  CHECK(num_slots == (sizeof(T) / 4))
      << "Invalid specification for the number of slots occupied by "
      << OpCode::kName[op.op_code];

  auto num_bytes_written = OpCode::kNumBytesWritten[op.op_code];
  auto num_data_slots = ((num_bytes_written + 7UL) & ~7UL) / 8UL;
  auto max_slots = std::max(num_slots, num_data_slots);

  auto begin = reinterpret_cast<const Operation *>(&op);
  auto end = reinterpret_cast<const Operation *>(&op + 1);

  auto old_size = bytecode_func->ops.size();
  auto var_of_op = static_cast<VarId>(old_size);
  bytecode_func->ops.insert(bytecode_func->ops.end(), begin, end);

  Operation alloc_op = {OpCode::kAllocOverflowData, 0};
  bytecode_func->ops.resize(old_size + max_slots, alloc_op);

  if (!whence) {
    return var_of_op;
  }

  bytecode_func->inst_to_var[whence] = var_of_op;

  // We allocate PHI nodes to be just like allocas. So, when we write to a
  // value that reaches a PHI node, we will just write into the state backing
  // the PHI node.
  for (auto user : whence->users()) {
    if (auto phi = llvm::dyn_cast<llvm::PHINode>(user)) {
      if (!state_offset.count(phi)) {
        continue;
      }

      auto set_phi_op = CreateStateWrite(phi, num_bytes_written, var_of_op);
      bytecode_func->ops.push_back(
          *reinterpret_cast<Operation *>(&set_phi_op));
    }
  }

  return var_of_op;
}

Operation::State TranslationUnit::CreateStateRead(llvm::Value *val,
                                                  size_t size) {
  Operation::State op;
  op.offset = state_offset[val];
  if (op.offset >= arch_state_size) {
    op.op_code = Choose8To128(size, OpCode::kReadStack8,
                              OpCode::kReadStack16, OpCode::kReadStack32,
                              OpCode::kReadStack64, OpCode::kReadStack128);

  } else {
    op.op_code = Choose8To128(size, OpCode::kRead8,
                              OpCode::kRead16, OpCode::kRead32,
                              OpCode::kRead64, OpCode::kRead128);
  }
  return op;
}

Operation::State TranslationUnit::CreateStateWrite(
    llvm::Value *val, size_t size, VarId src_var) {
  Operation::State op;
  op.offset = state_offset[val];
  op.src_var = src_var;
  if (op.offset >= arch_state_size) {
    op.op_code = Choose8To128(size, OpCode::kWriteStack8,
                              OpCode::kWriteStack16, OpCode::kWriteStack32,
                              OpCode::kWriteStack64, OpCode::kWriteStack128);

  } else {
    op.op_code = Choose8To128(size, OpCode::kWrite8,
                              OpCode::kWrite16, OpCode::kWrite32,
                              OpCode::kWrite64, OpCode::kWrite128);
  }
  return op;
}

// Append an opcode-specific instantiation of an operation into the list of
// operations. This *may* result in more than one operation being added to
// the list.
//
// This deals with things like inserting delay slots for allocating space
// after an operation (for things like 128-bit integer arithmetic).
template <typename T>
void TranslationUnit::AppendConstant(
    const T &op, llvm::Value *whence, uint64_t val) {
  auto var = AppendOperation(op, whence);
  auto const_size = data_layout.getTypeStoreSize(whence->getType());
  if (8 >= const_size) {
    bytecode_func->const_to_var[val] = var;
    return;
  }

  if (16 != const_size) {
    LOG(FATAL)
        << "Expecting a 128-bit constant, but got "
        << LLVMThingToString(whence) << ", whose size is " << const_size;
  }

  Operation zero_op = {OpCode::kZero, 0};
  AppendOperation(zero_op, nullptr);
}

// Try to resolve a value to variable ID representing an existing operation
// in our ops list.
VarId TranslationUnit::TryResolve(llvm::Value *value) {
  if (value) {

    // We have already emitted an operation for the value.
    if (bytecode_func->inst_to_var.count(value)) {
      return bytecode_func->inst_to_var[value];
    }

    // This value isn't a constant, therefore no operation for it exists yet,
    // and we can't get its value from the constant pool.
    if (!llvm::isa<llvm::Constant>(value)) {
      bytecode_func->num_unresolved++;
      return kUnresolvedVar;
    }
  }

  LOG(FATAL)
      << "Cannot resolve constant " << LLVMThingToString(value)
      << " to a variable in our operations list in "
      << bitcode_func->getName().str() << " implementing code for PC "
      << std::hex << bytecode_func->pc;

  return kUnresolvedVar;
}

void TranslationUnit::CompileGEP(llvm::GetElementPtrInst *inst) {
  if (!state_offset.count(inst)) {  // Accessing memory.
    bytecode_func->inst_to_var[inst] = TryResolve(inst->getOperand(1));
  }
}

void TranslationUnit::CompileBitCast(llvm::BitCastInst *inst) {
  if (!state_offset.count(inst)) {  // Accessing memory.
    bytecode_func->inst_to_var[inst] = TryResolve(inst->getOperand(0));
  }
}

void TranslationUnit::CompileBranch(llvm::BranchInst *inst) {
  Operation::GoTo op;
  if (inst->isUnconditional()) {
    auto target = inst->getSuccessor(0);
    op.op_code = OpCode::kGoTo;
    op.true_var = TryResolve(target);
  } else {
    auto target_true = inst->getSuccessor(0);
    auto target_false = inst->getSuccessor(1);
    op.op_code = OpCode::kCondGoTo;
    op.true_var = TryResolve(target_true);
    op.false_var = TryResolve(target_false);
    op.cond_var = TryResolve(inst->getCondition());
  }
  AppendOperation(op, inst);
}


void TranslationUnit::CompileLoad(llvm::LoadInst *inst) {
  auto addr = inst->getPointerOperand();
  auto type = inst->getType();
  auto size = data_layout.getTypeStoreSize(type);

  CHECK(state_offset.count(addr))
      << "Logic flaw in assigning state offsets to pointer operations.";

  Operation::State op = CreateStateRead(addr, size);
  AppendOperation(op, inst);
}

void TranslationUnit::CompileStore(llvm::StoreInst *inst) {
  auto addr = inst->getPointerOperand();
  auto val = inst->getValueOperand();
  auto type = inst->getValueOperand()->getType();
  auto size = data_layout.getTypeStoreSize(type);

  CHECK(state_offset.count(addr))
      << "Logic flaw in assigning state offsets to pointer operations.";

  auto op = CreateStateWrite(addr, size, TryResolve(val));
  AppendOperation(op, inst);
}

void TranslationUnit::CompileBinary(llvm::BinaryOperator *inst) {
  Operation::Binary op = {};
  auto size = data_layout.getTypeStoreSize(inst->getType());
  op.op_code = GetOpCode(inst, size, size);
  op.src1_var = TryResolve(inst->getOperand(0));
  op.src2_var = TryResolve(inst->getOperand(1));
  AppendOperation(op, inst);
}

void TranslationUnit::CompileCast(llvm::CastInst *inst) {
  auto dst_type = inst->getType();
  auto dst_size = data_layout.getTypeStoreSize(dst_type);
  auto src = inst->getOperand(0);
  auto src_type = src->getType();
  auto src_size = data_layout.getTypeStoreSize(src_type);
  auto src_var = TryResolve(src);

  if (src_type->isIntegerTy(1)) {
    const auto cast_opcode = inst->getOpcode();
    if (llvm::Instruction::ZExt == cast_opcode) {
      bytecode_func->inst_to_var[inst] = src_var;

    // TODO(pag): This is so ugly. LLVM will do a `sext i1 to i8`, which will
    //            turn something like `1` into `0xFF`, so we need to handle
    //            this annoyance, as it's pretty important for things like
    //            `PCMPEQB`.
    //
    //            Our way of handling this will be to do: `~(src - 1)`.
    } else if (llvm::Instruction::SExt == cast_opcode) {
      auto var1_it = bytecode_func->const_to_var.find(1);
      auto var1 = kUnresolvedVar;

      if (var1_it != bytecode_func->const_to_var.end()) {
        var1 = var1_it->second;
      } else {
        Operation::Constant one = {OpCode::kOne, 1};
        var1 = AppendOperation(one, nullptr);
        bytecode_func->const_to_var[1] = var1;
      }

      Operation::Binary sub_op = {};
      sub_op.op_code = Choose8To128(
          dst_size, OpCode::kSub8, OpCode::kSub16,
          OpCode::kSub32, OpCode::kSub64, OpCode::kSub128);
      sub_op.src1_var = src_var;
      sub_op.src2_var = var1;

      auto sub_var = AppendOperation(sub_op, nullptr);

      Operation::Unary neg = {};
      neg.op_code = Choose8To128(
          dst_size, OpCode::kNot8, OpCode::kNot16,
          OpCode::kNot32, OpCode::kNot64, OpCode::kNot128);
      neg.src_var = sub_var;
      AppendOperation(neg, inst);

    } else {
      LOG(FATAL)
          << "Unsupported cast in block at PC " << std::hex
          << bytecode_func->pc << ": " << LLVMThingToString(inst);
    }

  } else if (src_size == dst_size &&
             src_type->isIntegerTy() &&
             dst_type->isIntegerTy()) {
    bytecode_func->inst_to_var[inst] = src_var;
  } else {
    Operation::Unary op = {};
    op.op_code = GetOpCode(inst, dst_size, src_size);
    op.src_var = src_var;
    AppendOperation(op, inst);
  }
}

void TranslationUnit::CompileCompare(llvm::CmpInst *inst) {
  Operation::Binary op = {};
  auto dst_size = data_layout.getTypeStoreSize(inst->getType());
  auto src_type = inst->getOperand(0)->getType();
  auto src_size = data_layout.getTypeStoreSize(src_type);
  op.op_code = GetOpCode(inst, dst_size, src_size);
  op.src1_var = TryResolve(inst->getOperand(0));
  op.src2_var = TryResolve(inst->getOperand(1));
  AppendOperation(op, inst);
}

void TranslationUnit::CompilePHI(llvm::PHINode *inst) {
  auto type = inst->getType();
  if (!type->isPointerTy()) {
    auto size = data_layout.getTypeStoreSize(type);
    auto op = CreateStateRead(inst, size);
    AppendOperation(op, inst);

  } else if (!state_offset.count(inst) && !mem_ptrs.count(inst)) {
    LOG(FATAL)
        << "Unsupported PHI node " << LLVMThingToString(inst)
        << " in " << bitcode_func->getName().str() << " emulating "
        << "the block at " << std::hex << bytecode_func->pc;
  }
}

void TranslationUnit::CompileSelect(llvm::SelectInst *inst) {
  auto size = data_layout.getTypeStoreSize(inst->getType());
  Operation::ITE op = {};
  op.op_code = Choose8To128(
      size, OpCode::kITE8,
      OpCode::kITE16, OpCode::kITE32,
      OpCode::kITE64, OpCode::kITE128);
  op.cond_var = TryResolve(inst->getOperand(0));
  op.true_var = TryResolve(inst->getOperand(1));
  op.false_var = TryResolve(inst->getOperand(2));
  AppendOperation(op, inst);
}

void TranslationUnit::CompileMemSet(llvm::MemSetInst *inst) {
  auto size_arg = llvm::dyn_cast<llvm::ConstantInt>(inst->getArgOperand(2));
  if (!size_arg) {
    LOG(FATAL)
        << "Only support memset intrinsics with constant sizes: "
        << LLVMThingToString(inst);
  }

  auto addr_arg = inst->getArgOperand(0);
  if (!state_offset.count(addr_arg)) {
    LOG(FATAL)
        << "Can only handle memset intrinsics that operate on the State "
        << "structure: " << LLVMThingToString(inst);
  }

  auto size = size_arg->getZExtValue();
  if (128 < size) {
    LOG(FATAL)
        << "Don't yet support memset intrinsics of " << size << "-bit writes "
        << "into the State structure. This is probably a translation of "
        << "an x86 AVX vector register: "
        << LLVMThingToString(inst);
  }

  auto op = CreateStateWrite(addr_arg, size,
                             TryResolve(inst->getArgOperand(1)));
  AppendOperation(op, inst);
}

void TranslationUnit::CompileMemCopy(llvm::MemCpyInst *inst) {
  auto size_arg = llvm::dyn_cast<llvm::ConstantInt>(inst->getArgOperand(2));
  if (!size_arg) {
    LOG(FATAL)
        << "Only support memcpy intrinsics with constant sizes: "
        << LLVMThingToString(inst);
  }

  auto dest_addr_arg = inst->getArgOperand(0);
  if (!state_offset.count(dest_addr_arg)) {
    LOG(FATAL)
        << "Can only handle memcpy intrinsics that write to the State "
        << "structure: " << LLVMThingToString(inst);
  }

  auto src_addr_arg = inst->getArgOperand(0);
  if (!state_offset.count(src_addr_arg)) {
    LOG(FATAL)
        << "Can only handle memcpy intrinsics that read from the State "
        << "structure: " << LLVMThingToString(inst);
  }

  auto size = size_arg->getZExtValue();
  if (128 < size) {
    LOG(FATAL)
        << "Don't yet support memcpy intrinsics of " << size << "-bit writes "
        << "into the State structure. This is probably a translation of "
        << "an x86 AVX vector register: "
        << LLVMThingToString(inst);
  }

  auto read_op = CreateStateRead(src_addr_arg, size);
  AppendOperation(read_op, inst);

  auto write_op = CreateStateWrite(
      dest_addr_arg, size, TryResolve(inst->getArgOperand(1)));
  AppendOperation(write_op, inst);
}

void TranslationUnit::CompileIntrinsic(llvm::IntrinsicInst *inst) {
  auto size = data_layout.getTypeStoreSize(inst->getType());
  auto arg1 = inst->getArgOperand(0);
  bool has_int_intrinsic = false;
  bool has_fp_intrinsic = false;

  Operation::IntrinsicCall op = {};
  Operation::FPIntrinsicCall fp_op = {};

  op.op_code = Choose8To128(
      size, OpCode::kIntrinsic8, OpCode::kIntrinsic16,
      OpCode::kIntrinsic32, OpCode::kIntrinsic64, OpCode::kIntrinsic128);

  fp_op.op_code = Choose8To128(
      size, OpCode::kInvalid, OpCode::kInvalid,
      OpCode::kFPIntrinsic32, OpCode::kFPIntrinsic64,
      OpCode::kInvalid);

  switch (inst->getIntrinsicID()) {
    case llvm::Intrinsic::ctpop:  // Count number of 1 bits. Used for parity.
      op.call = Intrinsic::kPopCount;
      op.src1_var = TryResolve(arg1);
      op.src2_var = kUnresolvedVar;
      has_int_intrinsic = true;
      break;
    case llvm::Intrinsic::ctlz:  // Count leading zeros.
      op.call = Intrinsic::kNumLeadingZeros;
      op.src1_var = TryResolve(arg1);
      op.src2_var = kUnresolvedVar;
      has_int_intrinsic = true;
      break;
    case llvm::Intrinsic::cttz:  // Count trailing zeros.
      op.call = Intrinsic::kNumTrailingZeros;
      op.src1_var = TryResolve(arg1);
      op.src2_var = kUnresolvedVar;
      has_int_intrinsic = true;
      break;
    case llvm::Intrinsic::bswap:  // Swap the bytes.
      op.call = Intrinsic::kByteSwap;
      op.src1_var = TryResolve(arg1);
      op.src2_var = kUnresolvedVar;
      has_int_intrinsic = true;
      break;

    // Round a float/double to nearest integer value. This is used extensively
    // in the x86 `CVT*` (type conversion) set of instructions.
    case llvm::Intrinsic::nearbyint:
      fp_op.call = FPIntrinsic::kRoundToNearestInt;
      fp_op.src1_var = TryResolve(arg1);
      fp_op.src2_var = kUnresolvedVar;
      has_fp_intrinsic = true;
      break;

    case llvm::Intrinsic::trunc:
      fp_op.call = FPIntrinsic::kTruncToNearestInt;
      fp_op.src1_var = TryResolve(arg1);
      fp_op.src2_var = kUnresolvedVar;
      has_fp_intrinsic = true;
      break;

    // Used in the implementation of the FPU.
//    case llvm::Intrinsic::cos:  // Cosine.
//    case llvm::Intrinsic::sin:  // Sin.
//    case llvm::Intrinsic::fabs:  // Absolute value of a floating-point number.
    default:
      LOG(FATAL)
          << "Unsupported intrinsic " << LLVMThingToString(inst);
  }

  if (has_int_intrinsic) {
    AppendOperation(op, inst);
  }
  if (has_fp_intrinsic) {
    AppendOperation(fp_op, inst);
  }
}

void TranslationUnit::CompileCall(llvm::CallInst *inst) {
  auto called_func = inst->getCalledFunction();

#define RESOLVE_MEM_READ(suffix, opcode) \
  if (called_func == read_mem_ ## suffix) { \
    Operation::Mem op = {}; \
    op.op_code = opcode; \
    op.addr_var = TryResolve(inst->getArgOperand(1)); \
    AppendOperation(op, inst); \
    return; \
  }

  RESOLVE_MEM_READ(8, OpCode::kReadMem8)
  RESOLVE_MEM_READ(16, OpCode::kReadMem16)
  RESOLVE_MEM_READ(32, OpCode::kReadMem32)
  RESOLVE_MEM_READ(64, OpCode::kReadMem64)
  RESOLVE_MEM_READ(f32, OpCode::kReadMem32)
  RESOLVE_MEM_READ(f64, OpCode::kReadMem64)
  RESOLVE_MEM_READ(f80, OpCode::kReadMemFP80)

#undef RESOLVE_MEM_READ

#define RESOLVE_MEM_WRITE(suffix, opcode) \
  if (called_func == write_mem_ ## suffix) { \
    Operation::Mem op = {}; \
    op.op_code = opcode; \
    op.addr_var = TryResolve(inst->getArgOperand(1)); \
    op.src_var = TryResolve(inst->getArgOperand(2)); \
    AppendOperation(op, inst); \
    return; \
  }

  RESOLVE_MEM_WRITE(8, OpCode::kWriteMem8)
  RESOLVE_MEM_WRITE(16, OpCode::kWriteMem16)
  RESOLVE_MEM_WRITE(32, OpCode::kWriteMem32)
  RESOLVE_MEM_WRITE(64, OpCode::kWriteMem64)
  RESOLVE_MEM_WRITE(f32, OpCode::kWriteMem32)
  RESOLVE_MEM_WRITE(f64, OpCode::kWriteMem64)
  RESOLVE_MEM_WRITE(f80, OpCode::kWriteMemFP80)

#undef RESOLVE_MEM_WRITE

  if (atomic_begin == called_func || atomic_end == called_func ||
      barrier_load_load == called_func || barrier_load_store == called_func ||
      barrier_store_load == called_func || barrier_store_store == called_func) {
    Operation op = {OpCode::kSafePoint, 0};
    AppendOperation(op, inst);
    return;
  }

  if (sync_hypercall == called_func) {
    auto hypercall_num = llvm::dyn_cast<llvm::ConstantInt>(
        inst->getArgOperand(2));

    if (!hypercall_num) {
      LOG(FATAL)
          << "SyncHyperCall number passed to __remill_sync_hyper_call "
          << "must be a constant; got " << LLVMThingToString(inst);
    }

    Operation::HyperCall op;
    op.op_code = OpCode::kSyncHyperCall;
    op.call = static_cast<SyncHyperCall::Name>(hypercall_num->getZExtValue());
    AppendOperation(op, inst);
    return;
  }

  // Handle a memset instruction.
  if (auto memset_inst = llvm::dyn_cast<llvm::MemSetInst>(inst)) {
    CompileMemSet(memset_inst);
    return;
  }

  // Handle a memcpy instruction.
  if (auto memcpy_inst = llvm::dyn_cast<llvm::MemCpyInst>(inst)) {
    CompileMemCopy(memcpy_inst);
    return;
  }

  if (auto intrinsic_inst = llvm::dyn_cast<llvm::IntrinsicInst>(inst)) {
    CompileIntrinsic(intrinsic_inst);
    return;
  }

  auto pc = inst->getArgOperand(2);
  Operation::Exit exit_op;
  if (error == called_func) {
    exit_op.op_code = OpCode::kExitError;
    exit_op.pc_var = TryResolve(pc);
    AppendOperation(exit_op, inst);
    return;
  }

  auto block = inst->getParent();
  auto terminator = block->getTerminatingMustTailCall();
  if (terminator != inst) {
    auto func_name = inst->getParent()->getParent()->getName().str();
    LOG(FATAL)
        << "Unsupported call in " << func_name
        << ": " << LLVMThingToString(inst);
  }

  if (function_call == called_func) {
    exit_op.op_code = OpCode::kExitCall;
    exit_op.pc_var = TryResolve(pc);
    AppendOperation(exit_op, inst);
    return;
  } else if (function_return == called_func) {
    exit_op.op_code = OpCode::kExitRet;
    exit_op.pc_var = TryResolve(pc);
    AppendOperation(exit_op, inst);
    return;
  } else if (indirect_jump == called_func) {
    exit_op.op_code = OpCode::kExitJump;
    exit_op.pc_var = TryResolve(pc);
    AppendOperation(exit_op, inst);
    return;
  } else if (async_hypercall == called_func) {
    exit_op.op_code = OpCode::kExitAsyncHyperCall;
    exit_op.pc_var = TryResolve(pc);
    AppendOperation(exit_op, inst);
    return;
  }

  bytecode_func->succ_funcs[1] = bytecode_func->succ_funcs[0];
  bytecode_func->succ_ids[1] = bytecode_func->succ_ids[0];

  Operation::Jump jmp_op;
  jmp_op.op_code = OpCode::kJump;
  jmp_op.rel_offset = 0;
  bytecode_func->succ_ids[0] = AppendOperation(jmp_op, inst);
  bytecode_func->succ_funcs[0] = called_func;
}

void TranslationUnit::Compile(llvm::Instruction *inst) {
  switch (auto op_code = inst->getOpcode()) {

    // Already mapped to registers.
    case llvm::Instruction::Alloca:
      break;
    case llvm::Instruction::GetElementPtr:
      CompileGEP(llvm::dyn_cast<llvm::GetElementPtrInst>(inst));
      break;
    case llvm::Instruction::BitCast:
      CompileBitCast(llvm::dyn_cast<llvm::BitCastInst>(inst));
      break;

    case llvm::Instruction::Ret:
      break;

    case llvm::Instruction::Br:
      CompileBranch(llvm::dyn_cast<llvm::BranchInst>(inst));
      break;

    case llvm::Instruction::Unreachable:
      // TODO(pag): Do this!!
      break;

    // Loads will either be treated the same as the address being loaded, or
    // instead, they will operate like an `extractelement`, e.g. accessing
    // the `AH` sub-register of `RAX`.
    case llvm::Instruction::Load:
      CompileLoad(llvm::dyn_cast<llvm::LoadInst>(inst));
      break;

    case llvm::Instruction::Store:
      CompileStore(llvm::dyn_cast<llvm::StoreInst>(inst));
      break;

    case llvm::Instruction::Add:
    case llvm::Instruction::FAdd:
    case llvm::Instruction::Sub:
    case llvm::Instruction::FSub:
    case llvm::Instruction::Mul:
    case llvm::Instruction::FMul:
    case llvm::Instruction::UDiv:
    case llvm::Instruction::SDiv:
    case llvm::Instruction::FDiv:
    case llvm::Instruction::URem:
    case llvm::Instruction::SRem:
    case llvm::Instruction::FRem:
    case llvm::Instruction::Shl:
    case llvm::Instruction::LShr:
    case llvm::Instruction::AShr:
    case llvm::Instruction::And:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
      CompileBinary(llvm::dyn_cast<llvm::BinaryOperator>(inst));
      break;

    case llvm::Instruction::Trunc:
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::FPToUI:
    case llvm::Instruction::FPToSI:
    case llvm::Instruction::UIToFP:
    case llvm::Instruction::SIToFP:
    case llvm::Instruction::FPTrunc:
    case llvm::Instruction::FPExt:
      CompileCast(llvm::dyn_cast<llvm::CastInst>(inst));
      break;

    case llvm::Instruction::ICmp:
    case llvm::Instruction::FCmp:
      CompileCompare(llvm::dyn_cast<llvm::CmpInst>(inst));
      break;

    case llvm::Instruction::PHI:
      CompilePHI(llvm::dyn_cast<llvm::PHINode>(inst));
      break;

    case llvm::Instruction::Select:
      CompileSelect(llvm::dyn_cast<llvm::SelectInst>(inst));
      break;

    case llvm::Instruction::Call:
      CompileCall(llvm::dyn_cast<llvm::CallInst>(inst));
      break;
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::IntToPtr:
      if (mem_ptrs.count(inst)) {
        break;
      }
      [[clang::fallthrough]];
    default:
      LOG(FATAL)
          << "Cannot compile unsupported instruction "
          << llvm::Instruction::getOpcodeName(op_code)
          << " in function " << bitcode_func->getName().str()
          << " implementing code at PC " << std::hex << bytecode_func->pc;
      break;
  }
}

inline static bool IsPowerOf2(const uint64_t v) {
  return !(v & (v - 1ULL));
}


// This goes through, finds constants, and does one of a few things:
//
// - If the constant is zero, one, or a power of two, then we emit Operations
//   for that specific constant.
// - If the constant is not in our constant pool, then we add it to the
//   constant pool.
// - If the constant is in our constant pool, then we emit an Operation
//   to load the constant from the pool.
void TranslationUnit::InternConstant(llvm::Constant *val) {

  if (!val || llvm::isa<llvm::UndefValue>(val) ||
      llvm::isa<llvm::Function>(val)) {
    return;
  }

  uint64_t uint_val = 0;
  if (auto int_val = llvm::dyn_cast<llvm::ConstantInt>(val)) {
    auto num_needed_bits = int_val->getValue().getActiveBits();
    if (64 < num_needed_bits) {
      LOG(FATAL)
          << "Cannot represent " << num_needed_bits << "-bit integer in the "
          << "constant pool: " << LLVMThingToString(val);
    }

    if (int_val->isNegative()) {
      uint_val = static_cast<uint64_t>(int_val->getSExtValue());
    } else {
      uint_val = int_val->getZExtValue();
    }

  // Floating point value; convert it into an integer.
  } else if (auto fp_val = llvm::dyn_cast<llvm::ConstantFP>(val)) {
    auto fp_type = fp_val->getType();
    CHECK(fp_type->isFloatTy() || fp_type->isDoubleTy())
        << "Can only put floats and doubles into the constant pool.";

    const auto &val = fp_val->getValueAPF();
    if (fp_type->isFloatTy()) {
      auto float_val = val.convertToFloat();
      uint_val = reinterpret_cast<uint32_t &>(float_val);
    } else {
      auto double_val = val.convertToDouble();
      uint_val = reinterpret_cast<uint64_t &>(double_val);
    }

  // We'll put these in, but we've got a special `Zero` operation just for
  // this.
  } else {
    LOG(FATAL)
        << "Cannot intern constant value " << LLVMThingToString(val);
  }

  // We have already emitted an operation for this constant value.
  if (bytecode_func->const_to_var.count(uint_val)) {
    bytecode_func->inst_to_var[val] = bytecode_func->const_to_var[uint_val];
    return;
  }

  // Load a zero into the data section.
  if (0 == uint_val) {
    Operation::PositiveInteger zero_op = {OpCode::kZero, 0, 1};
    AppendConstant(zero_op, val, uint_val);
    return;
  }

  // Load a 1 into the data section.
  if (1 == uint_val) {
    Operation::PositiveInteger one_op = {OpCode::kOne, 0, 1};
    AppendConstant(one_op, val, uint_val);
    return;
  }

  // Positive 16-bit integer.
  if (static_cast<uint16_t>(uint_val) == uint_val) {
    Operation::PositiveInteger pos_16 = {
        OpCode::kPositive16, 0, static_cast<uint16_t>(uint_val)};
    AppendConstant(pos_16, val, uint_val);
    return;
  }

  // Negative 16-bit integer.
  if (static_cast<int64_t>(static_cast<int16_t>(uint_val)) ==
      static_cast<int64_t>(uint_val)) {
    Operation::PositiveInteger neg_16 = {
        OpCode::kNegative16, 0, static_cast<uint16_t>(uint_val)};
    AppendConstant(neg_16, val, uint_val);
    return;
  }

  // Load a positive power of two into the data section.
  if (IsPowerOf2(uint_val)) {
    Operation::Pow2 pos_pow_2 = {
        OpCode::kPow2, 0, 0, static_cast<uint8_t>(__builtin_ctz(uint_val))};
    AppendConstant(pos_pow_2, val, uint_val);
  }

  // Load a negative power of two into the data section.
  auto neg_uint_val = static_cast<uint64_t>(-static_cast<int64_t>(uint_val));
  if (IsPowerOf2(neg_uint_val)) {
    Operation::Pow2 neg_pow_2 = {
        OpCode::kNegPow2, 0, 0,
        static_cast<uint8_t>(__builtin_ctz(neg_uint_val))};
    AppendConstant(neg_pow_2, val, uint_val);
    return;
  }

  // Put the constant into the constant pool, and emit an instruction to
  // load that constant into the data section.
  uint64_t offset = 0;
  if (!const_to_offset.count(uint_val)) {
    offset = starting_offset + constant_table.size();

    const_to_offset[uint_val] = offset;
    constant_table.push_back(uint_val);

    DLOG(INFO)
        << "Interning " << std::hex << uint_val
        << ", representing " << LLVMThingToString(val)
        << " into the constant pool at offset " << offset;
  } else {
    offset = const_to_offset[uint_val];  // Already in the pool.
  }

  Operation load_const = {
      OpCode::kConstant, static_cast<uint32_t>(offset)};
  AppendConstant(load_const, val, uint_val);
}

void TranslationUnit::InternConstants(void) {
  for (auto &block : *bitcode_func) {
    for (auto &inst : block) {

      // All accesses into the State structure are by constant integers, so
      // exclude those, while also allowing GEPs using hard-coded constant
      // addresses to Memory to pass through.
      if (llvm::isa<llvm::GetElementPtrInst>(inst)) {
        if (state_offset.count(&inst)) {
          continue;
        }
      }

      // The memcpy intrinsic takes a bunch of constants that we don't want.
      if (auto mem_copy_inst = llvm::dyn_cast<llvm::MemCpyInst>(&inst)) {
        InternConstant(llvm::dyn_cast<llvm::ConstantInt>(
            mem_copy_inst->getOperand(1)));
        continue;

      // Ignore the hypercall intrinsic because we encode the hyper call ID
      // directly into the Operation::HyperCall.
      } else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        if (call_inst->getCalledFunction()->getName() ==
            "__remill_sync_hyper_call") {
          continue;
        }
      }

      auto it = inst.op_begin();
      auto it_end = inst.op_end();
      for (; it != it_end; ++it) {
        InternConstant(llvm::dyn_cast<llvm::Constant>(it->get()));
      }
    }
  }
}

void TranslationUnit::CompileFunction(
    const uint64_t pc, llvm::Function *lifted_func) {

  auto func_name = lifted_func->getName().str();
  DLOG(INFO)
      << "Compiling " << func_name << " implementing code at "
      << std::hex << pc;

  bitcode_to_pc[lifted_func] = pc;

  if (lifted_func->isDeclaration()) {
    return;
  }

  auto compiled_func = new CompiledFunction(pc);
  pc_to_bytecode[pc] = compiled_func;
  bytecode_func = compiled_func;
  bitcode_func = lifted_func;

  auto state_size = AssignLocalStoreOffsets();

  // We can represent the PC as a 32-bit value.
  const auto pc_32 = static_cast<uint32_t>(pc);
  if (static_cast<uint64_t>(pc_32) == pc) {
    Operation::Enter32 enter_32 = {OpCode::kEnter32, 0,
                                   static_cast<uint16_t>(state_size), pc_32};
    AppendOperation(enter_32, nullptr);

  // Need 64 bits to represent the PC.
  } else {
    Operation::Enter64 enter_64 = {OpCode::kEnter64, 0,
                                   static_cast<uint16_t>(state_size), pc};
    AppendOperation(enter_64, nullptr);
  }

  // Generate instructions for each unique constant used in the function.
  // Some constants may be added to the constant pool.
  InternConstants();
  auto num_ops_before_compile = bytecode_func->ops.size();

  for (auto i = 0; i < 2; ++i) {
    if (bytecode_func->num_unresolved) {
      LOG(INFO)
          << "Recompiling block at PC " << std::hex << bytecode_func->pc
          << ", " << bytecode_func->num_unresolved
          << " variables were not resolved.";

//      std::stringstream ss;
//      for (auto i = 0UL; i < bytecode_func->ops.size(); ) {
//        const auto &op = bytecode_func->ops[i];
//        ss << "%" << i << " = " << op.Serialize() << std::endl;
//        i += OpCode::kNumOpSlots[op.op_code];
//      }
//
//      std::cout << ss.str() << std::endl << std::endl;
    }

    bytecode_func->num_unresolved = 0;
    bytecode_func->ops.resize(num_ops_before_compile);
    bytecode_func->succ_ids[0] = kUnresolvedVar;
    bytecode_func->succ_ids[1] = kUnresolvedVar;
    bytecode_func->succ_funcs[0] = nullptr;
    bytecode_func->succ_funcs[1] = nullptr;

    for (auto &block : *lifted_func) {
      bytecode_func->inst_to_var[&(block)] =
          static_cast<VarId>(bytecode_func->ops.size());
      for (auto &inst : block) {
        Compile(&inst);
      }
    }

    if (!bytecode_func->num_unresolved) {
      break;
    }
  }

  CHECK(!bytecode_func->num_unresolved)
      << "Unable to resolve all variables when compiling " << func_name;

}

void BCC::Compile(TranslationUnit *tu) {

  std::vector<CompiledFunction *> funcs;
  funcs.reserve(tu->pc_to_bytecode.size());

  // Count how many operations we'll add into the cache, and collect the
  // compiled functions.
  auto num_ops = 0UL;
  for (const auto &entry : tu->pc_to_bytecode) {
    num_ops += entry.second->ops.size();
    funcs.push_back(entry.second);
  }

  // Sort the compiled functions in increasing order of their PCs.
  std::sort(funcs.begin(), funcs.end(),
            [=] (CompiledFunction *a, CompiledFunction *b) {
              return a->pc < b->pc;
            });

  // Collect all operations.
  std::vector<Operation> ops;
  ops.reserve(num_ops);

  size_t compiled_offset = cache->NumEntries();
  auto first_op = cache->begin();
  for (auto func : funcs) {
    index->Insert(func->pc, &(first_op[compiled_offset]));
    func->compiled_offset = compiled_offset;
    compiled_offset += func->ops.size();
    ops.insert(ops.end(), func->ops.begin(), func->ops.end());
  }

  // Write the constants and operations to disk.
  constants->Extend(tu->constant_table);
  cache->Extend(ops);

  // Fixup the jump operands.
  for (auto func : funcs) {
    for (auto i = 0; i < 2; ++i) {
      if (auto target_bitcode = func->succ_funcs[i]) {
        auto op = &(first_op[func->compiled_offset + func->succ_ids[i]]);
        auto target_pc = tu->bitcode_to_pc[target_bitcode];
        auto target_func_name = target_bitcode->getName().str();
        CHECK(0 != target_pc)
            << "Unable to determine the program counter of the function "
            << target_func_name << " called by the block at PC "
            << std::hex << func->pc;

        auto target_op = index->TryFind(target_pc);
        CHECK(nullptr != target_op)
            << "Unable to resolve bitcode function "
            << target_bitcode->getName().str() << " to operation.";

        auto offset = static_cast<int32_t>(target_op - op);
        if (!offset) {
          LOG(FATAL)
              << "Problem with jump target of " << op->Serialize()
              << " in block starting at PC " << std::hex << func->pc
              << ". Targeted function " << target_bitcode->getName().str()
              << " is the jump instruction itself! Variable for the successor "
              << "is " << func->succ_ids[i];
        }

        if (static_cast<int16_t>(offset) == offset) {
          auto jump_op = reinterpret_cast<Operation::Jump *>(op);
          jump_op->op_code = OpCode::kJump;
          jump_op->rel_offset = static_cast<int16_t>(offset);
        } else if (0 <= offset) {
          auto jump_op = reinterpret_cast<Operation::JumpFar *>(op);
          jump_op->op_code = OpCode::kJumpFarForward;
          jump_op->rel_offset = static_cast<uint32_t>(offset);
        } else {
          auto jump_op = reinterpret_cast<Operation::JumpFar *>(op);
          jump_op->op_code = OpCode::kJumpFarBackward;
          jump_op->rel_offset = static_cast<uint32_t>(-offset);
        }
      }
    }
  }

  DLOG(INFO)
      << "Compiled " << num_ops << " operations, implementing "
      << funcs.size() << " basic blocks.";

  cache->Sync();
}

}  // namespace vmill
}  // namespace remill
