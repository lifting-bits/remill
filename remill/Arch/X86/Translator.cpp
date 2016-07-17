/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>

#include "remill/Arch/X86/Arch.h"
#include "remill/Arch/X86/RegisterAnalysis.h"
#include "remill/Arch/X86/Translator.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Translator.h"
#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"

namespace remill {
namespace x86 {

enum {
  kVectorRegAlign = 64
};

InstructionTranslator::InstructionTranslator(
    RegisterAnalysis &analysis_,
    const cfg::Block &block_,
    const cfg::Instr &instr_,
    const struct xed_decoded_inst_s &xedd_)
    : analysis(&analysis_),
      block(&block_),
      instr(&instr_),
      xedd(&xedd_),
      xedi(xed_decoded_inst_inst(xedd)),
      iclass(xed_decoded_inst_get_iclass(xedd)),
      addr_width(kArchAMD64 == analysis->arch_name ? 64 : 32),
      basic_block(nullptr),
      function(nullptr),
      module(nullptr),
      context(nullptr),
      intptr_type(nullptr),
      args(),
      prepend_instrs(),
      append_instrs() {}

namespace {

// Name of this instruction function.
static std::string InstructionFunctionName(const xed_decoded_inst_t *xedd) {
  std::stringstream ss;
  std::string iform_name = xed_iform_enum_t2str(
      xed_decoded_inst_get_iform_enum(xedd));

  // All `LOCK` versions of instructions have their own iform, but ideally
  // we want to express the (non-)atomic versions of instructions uniformly.
  // For locked instructions, we inject calls to atomic intrinsics before/after
  // the lifted instructions.
  if (xed_operand_values_has_lock_prefix(xedd)) {
    const std::string lock = "LOCK_";
    const auto idx = iform_name.find(lock);
    if (std::string::npos != idx) {
      iform_name.erase(idx, lock.size());
    }
  }

  ss << iform_name;

  // Some instructions are "scalable", i.e. there are variants of the
  // instruction for each effective operand size. We represent these in
  // the semantics files with `_<size>`, so we need to look up the correct
  // selection.
  if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_SCALABLE)) {
    ss << "_";
    ss << xed_decoded_inst_get_operand_width(xedd);
  }

  return ss.str();
}

// Returns the address space associated with a segment register. This is a
// GNU-specific extension.
static unsigned AddressSpace(xed_reg_enum_t seg, xed_operand_enum_t name) {
  if (XED_OPERAND_AGEN == name) {
    return 0U;
  } else if (XED_REG_GS == seg) {
    return 256U;
  } else if (XED_REG_FS == seg) {
    return 257U;
  } else {
    return 0U;
  }
}

}  // namespace

void InstructionTranslator::LiftIntoBlock(const Translator &lifter,
                                          llvm::BasicBlock *basic_block_) {
  basic_block = basic_block_;
  function = basic_block->getParent();
  module = function->getParent();
  context = &(function->getContext());
  intptr_type = llvm::Type::getIntNTy(*context, addr_width);

  LiftPC(instr->address());

  if (!IsNoOp() && !IsError()) {
    LiftGeneric(lifter);
  }

  // Kill whatever we can at the end of this instruction.
  //
  // Note:  Instructions are lifted in reverse order, i.e. end of the block to
  //        beginning of the block.
  if (auto block_regs = analysis->blocks[block->address()]) {
    AddTerminatingKills(lifter, block_regs);
    block_regs->UpdateEntryLive(xedd);
  }

  if (IsError()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->error,
                           ReadPC(basic_block));

  } else if (IsDirectJump()) {
    auto target_pc = TargetPC();
    LiftPC(target_pc);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(
        basic_block, lifter.GetLiftedBlockForPC(target_pc),
        llvm::ConstantInt::get(intptr_type, target_pc, false));

  } else if (IsIndirectJump()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->jump,
                           ReadPC(basic_block));

  } else if (IsDirectFunctionCall()) {
    auto target_pc = TargetPC();
    LiftPC(target_pc);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(
        basic_block, lifter.GetLiftedBlockForPC(target_pc),
        llvm::ConstantInt::get(intptr_type, target_pc, false));

  } else if (IsIndirectFunctionCall()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->function_call,
                           ReadPC(basic_block));

  } else if (IsFunctionReturn()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->function_return,
                           ReadPC(basic_block));

  } else if (IsBranch()) {
    LiftConditionalBranch(lifter);

  // Instruction implementation handles syscall emulation.
  } else if (IsSystemCall()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->system_call,
                           ReadPC(basic_block));

  } else if (IsSystemReturn()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->system_return,
                           ReadPC(basic_block));
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();

  // Instruction implementation handles syscall (x86, x32) emulation.
  } else if (IsInterruptCall()) {
    if (!IsConditionalInterruptCall()) {
      AddTerminatingTailCall(basic_block, lifter.intrinsics->interrupt_call,
                             ReadPC(basic_block));
    } else {
      LOG(INFO)
          << "Lifted program performs a conditional interrupt.";
    }

  } else if (IsInterruptReturn()) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->interrupt_return,
                           ReadPC(basic_block));
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();

  // CPUID. Lets a runtime or static analyzer decide what this means.
  } else if (XED_ICLASS_CPUID == iclass) {
    AddTerminatingTailCall(basic_block, lifter.intrinsics->read_cpu_features,
                           NextPC());
    LOG(INFO)
        << "Lifted program requires access to CPU feature set.";
  }
}

// Store the program counter into the associated state register. This
// lets us access this information from within instruction implementations.
void InstructionTranslator::LiftPC(uintptr_t next_pc) {
  auto rip_name = kArchAMD64 == analysis->arch_name ? "RIP_write" : "EIP_write";
  llvm::IRBuilder<> ir(basic_block);
  ir.CreateStore(
      llvm::ConstantInt::get(intptr_type, next_pc, false),
      ir.CreateLoad(FindVarInFunction(function, rip_name)));
}

// Read the program counter. The program counter is updated before each
// lifted instruction, and needs to be passed along to all basic block
// and control-flow functions.
llvm::Value *InstructionTranslator::ReadPC(llvm::BasicBlock *block) {
  auto rip_name = kArchAMD64 == analysis->arch_name ? "RIP_read" : "EIP_read";
  llvm::IRBuilder<> ir(basic_block);
  return ir.CreateLoad(ir.CreateLoad(FindVarInFunction(function, rip_name)));
}

namespace {

// Debugging aid that describes certain type mismatch failures.
static void DescribeArgTypeMismatch(const llvm::Argument &func_arg,
                                    const llvm::Value *our_arg,
                                    const llvm::Function *F,
                                    const std::string &func_name) {
  std::string arg_types_str;
  llvm::raw_string_ostream arg_types_stream(arg_types_str);
  arg_types_stream << "\n";
  func_arg.print(arg_types_stream);
  arg_types_stream << " in ";
  F->getFunctionType()->print(arg_types_stream);
  arg_types_stream << "\n";
  our_arg->print(arg_types_stream);
  LOG(ERROR)
    << "Argument types don't match to " << func_name << ":" << arg_types_str;
}

}  // namespace

// Check the types of a function's argument.
bool InstructionTranslator::CheckArgumentTypes(
    const llvm::Function *instr_func, const std::string &func_name) {

  CHECK(instr_func->arg_size() == args.size())
      << "Number of arguments don't match to " << func_name << ": "
      << "got " << args.size() << ", wanted " << instr_func->arg_size();

  auto i = 0;
  for (const llvm::Argument &arg : instr_func->args()) {
    if (arg.getType() != args[i]->getType()) {
      DescribeArgTypeMismatch(arg, args[i], instr_func, func_name);
      return false;
    }
    ++i;
  }
  return true;
}

// Finds the function that implements this particular decoded instruction,
// using the XED iform name as the main way of finding the function, and if
// the instruction is scalable, then appending on the operand size of the
// function (e.g. `_32`).
llvm::Function *InstructionTranslator::GetInstructionFunction(void) {
  auto func_name = InstructionFunctionName(xedd);
  llvm::Function *instr_func = FindFunction(module, func_name);
  llvm::GlobalVariable *instr_func_alt = FindGlobaVariable(module, func_name);

  if (!instr_func && instr_func_alt) {
    CHECK(instr_func_alt->isConstant() && instr_func_alt->hasInitializer())
        << "Expected a `constexpr` variable as the function pointer.";
    instr_func = llvm::dyn_cast<llvm::Function>(
        instr_func_alt->getInitializer()->stripPointerCasts());
  }

  // TODO(pag): Memory leak of `args`, `prepend_instrs`, and `append_instrs`.
  if (!instr_func || !CheckArgumentTypes(instr_func, func_name)) {
    LOG(WARNING) << "Missing instruction semantics for " << func_name;
  }

  return instr_func;
}

// Lift a generic instruction.
void InstructionTranslator::LiftGeneric(const Translator &lifter) {
  // First argument is the state pointer.
  args.push_back(FindStatePointer(function));

  // Second argument is the memory pointer. This is actually a pointer to
  // the memory pointer, so that instruction implementations can "update" to
  // the new memory pointer (a la small step semantics).
  args.push_back(FindMemoryPointer(function));

  // Third argument is the next program counter.
  args.push_back(llvm::ConstantInt::get(intptr_type, NextPC(), false));

  // Lift the operands. This creates the arguments for us to call the
  // instruction implementation.
  auto num_operands = xed_decoded_inst_noperands(xedd);
  for (auto i = 0U; i < num_operands; ++i) {
    LiftOperand(lifter, i);
  }

  if (auto IF = GetInstructionFunction()) {
    auto &IList = basic_block->getInstList();
    IList.insert(IList.end(), prepend_instrs.rbegin(), prepend_instrs.rend());
    IList.push_back(llvm::CallInst::Create(IF, args));
    IList.insert(IList.end(), append_instrs.begin(), append_instrs.end());
  }
}

namespace {

static std::string BlockName(uintptr_t pc) {
  std::stringstream ss;
  ss << "0x" << std::hex << pc;
  return ss.str();
}

}  // namespace

// Lift a conditional branch instruction.
void InstructionTranslator::LiftConditionalBranch(const Translator &lifter) {
  auto dynamic_dest_pc_val = ReadPC(basic_block);

  auto target_pc = TargetPC();
  auto taken_block = llvm::BasicBlock::Create(
      *context, BlockName(target_pc), function);

  auto fall_through_pc = NextPC();
  auto fall_through_block = llvm::BasicBlock::Create(
      *context, BlockName(fall_through_pc), function);

  auto target_pc_val = llvm::ConstantInt::get(intptr_type, target_pc, false);
  AddTerminatingTailCall(
      taken_block, lifter.GetLiftedBlockForPC(target_pc), target_pc_val);

  AddTerminatingTailCall(
      fall_through_block, lifter.GetLiftedBlockForPC(fall_through_pc),
      llvm::ConstantInt::get(intptr_type, fall_through_pc, false));

  llvm::IRBuilder<> ir(basic_block);
  ir.CreateCondBr(ir.CreateICmpEQ(target_pc_val, dynamic_dest_pc_val),
                  taken_block, fall_through_block);
}

// Lift an operand. The goal is to be able to pass all explicit and implicit
// operands as arguments into a function that implements this instruction.
void InstructionTranslator::LiftOperand(const Translator &lifter,
                                        unsigned op_num) {
  auto xedo = xed_inst_operand(xedi, op_num);
  if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
      case XED_OPERAND_MEM1:
        LiftMemory(lifter, xedo, op_num);
        break;

      case XED_OPERAND_IMM0SIGNED:
      case XED_OPERAND_IMM0:
      case XED_OPERAND_IMM1_BYTES:
      case XED_OPERAND_IMM1:
        LiftImmediate(op_name);
        break;

      case XED_OPERAND_PTR:
        LOG(FATAL) << "Unsupported operand type: XED_OPERAND_PTR";
        break;

      case XED_OPERAND_REG:
      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
      case XED_OPERAND_REG4:
      case XED_OPERAND_REG5:
      case XED_OPERAND_REG6:
      case XED_OPERAND_REG7:
      case XED_OPERAND_REG8:
        LiftRegister(xedo);
        break;

      case XED_OPERAND_RELBR:
        LiftBranchDisplacement();
        break;

      default:
        LOG(FATAL) << "Unexpected operand type: " << op_name;
        return;
    }
  }
}

// Lift a base/displacement memory operand. This can manifest as a few things:
//
//    1)  It could be a PC-relative memory operand (64-bit).
//    2)  It could be an absolute memory operand (fixed address encoded in the
//        displacement.
//    3)  It could be a regular base + index*scale + displacement form.
//
// A minor challenge is handling the segment register. To handle this we use
// a GNU-specific extension by specifying an address space of the pointer type.
// The challenge is that we don't want to have
void InstructionTranslator::LiftMemory(const Translator &lifter,
                                       const xed_operand_t *xedo,
                                       unsigned op_num) {
  auto op_name = xed_operand_name(xedo);
  auto mem_index = (XED_OPERAND_MEM1 == op_name) ? 1 : 0;  // Handles AGEN.
  auto seg = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto addr_space = AddressSpace(seg, op_name);

  llvm::Value *addr_val = nullptr;  // Address (as an integer).
  llvm::IRBuilder<> ir(basic_block);
  auto int32_type = llvm::Type::getInt32Ty(*context);

  // Address is in the displacement.
  if (XED_REG_INVALID == base && XED_REG_INVALID == index) {
    addr_val = llvm::ConstantInt::get(
        intptr_type, static_cast<uint64_t>(disp), false);

  // PC-relative address.
  } else if (XED_REG_RIP == base) {
    auto next_pc = static_cast<intptr_t>(NextPC());
    addr_val = llvm::ConstantInt::get(
        intptr_type, static_cast<uint64_t>(next_pc + disp), false);

  // Need to to compute the address as `B + (I * S) + D`.
  } else {

    // Convert a given register reference into an integer of the correct
    // size and type. We sometimes need to zero extend the
    auto RegToValue = [=, &ir] (xed_reg_enum_t reg) -> llvm::Value * {
      if (XED_REG_INVALID == reg) {
        return llvm::ConstantInt::get(intptr_type, 0, false);
      } else {
        auto reg_name = std::string(xed_reg_enum_t2str(reg)) + "_read";
        llvm::Value *reg_val = ir.CreateLoad(ir.CreateLoad(
            FindVarInFunction(function, reg_name)));
        if (xed_get_register_width_bits64(reg) < addr_width) {
          reg_val = ir.CreateZExt(reg_val, intptr_type);
        }
        return reg_val;
      }
    };

    auto base_reg_val = RegToValue(base);
    auto index_reg_val = RegToValue(index);

    // Special case: `POP [xSP + ...] uses the value of `xSP` after incrementing
    // it by the stack width.
    if (XED_ICLASS_POP == iclass &&
        XED_REG_RSP == xed_get_largest_enclosing_register(base)) {
      auto shift_size = xed_decoded_inst_get_operand_width(xedd);
      base_reg_val = ir.CreateAdd(
          base_reg_val,
          llvm::ConstantInt::get(intptr_type, (shift_size / 8), false));
    }

    llvm::Value *scale_val = llvm::ConstantInt::get(intptr_type, scale, true);
    llvm::Value *disp_val = llvm::ConstantInt::get(int32_type, disp, true);
    if (32 < addr_width) {
      disp_val = ir.CreateSExt(disp_val, intptr_type);
    }

    addr_val = ir.CreateAdd(
        ir.CreateAdd(base_reg_val, ir.CreateMul(index_reg_val, scale_val)),
        disp_val);
  }

  // Mask the address down to size if a addr16/addr32 prefix is being used.
  const auto memop_addr_width = xed_decoded_inst_get_memop_address_width(
      xedd, mem_index);
  if (memop_addr_width < addr_width) {
    addr_val = ir.CreateTrunc(
        addr_val, llvm::Type::getIntNTy(*context, memop_addr_width));
    addr_val = ir.CreateZExt(addr_val, intptr_type);
  }

  if (addr_space) {
    std::vector<llvm::Value *> args = {
        FindStatePointer(function),  // Machine state.
        addr_val,  // Address.
        llvm::ConstantInt::get(int32_type, addr_space, true)};
    addr_val = ir.CreateCall(lifter.intrinsics->compute_address, args);
  }

  // We always pass destination operands first, then sources. Memory operands
  // are represented by their addresses, and in the instruction implementations,
  // accessed via intrinsics.
  if (xed_operand_written(xedo)) {
    args.push_back(addr_val);
  }

  if (xed_operand_read(xedo)) {
    args.push_back(addr_val);
  }

  // Wrap an instruction in atomic begin/end if it accesses memory with RMW
  // semantics or with a LOCK prefix.
  if (xed_operand_values_get_atomic(xedd) ||
      xed_operand_values_has_lock_prefix(xedd)) {
    auto memory = FindMemoryPointer(function);

    auto load_mem1 = new llvm::LoadInst(memory);
    auto new_mem1 = llvm::CallInst::Create(lifter.intrinsics->atomic_begin,
                                             {load_mem1});
    auto store_mem1 = new llvm::StoreInst(new_mem1, memory);

    auto load_mem2 = new llvm::LoadInst(memory);
    auto new_mem2 = llvm::CallInst::Create(lifter.intrinsics->atomic_begin,
                                             {load_mem2});
    auto store_mem2 = new llvm::StoreInst(new_mem2, memory);

    prepend_instrs.push_back(load_mem1);
    prepend_instrs.push_back(new_mem1);
    prepend_instrs.push_back(store_mem1);

    append_instrs.push_back(store_mem2);
    append_instrs.push_back(new_mem2);
    append_instrs.push_back(load_mem2);
  }
}

// Convert an immediate constant into an LLVM `Value` for passing into the
// instruction implementation.
void InstructionTranslator::LiftImmediate(xed_operand_enum_t op_name) {
  auto val = 0ULL;
  auto is_signed = false;
  auto op_size = xed_decoded_inst_get_operand_width(xedd);
  auto imm_size = xed_decoded_inst_get_immediate_width_bits(xedd);

  CHECK(imm_size <= op_size)
      << "Immediate size is greater than effective operand size at PC "
      << instr->address();

  if (XED_OPERAND_IMM0SIGNED == op_name ||
      xed_operand_values_get_immediate_is_signed(xedd)) {
    val = static_cast<uint64_t>(
        static_cast<int64_t>(xed_decoded_inst_get_signed_immediate(xedd)));
    is_signed = true;

  } else if (XED_OPERAND_IMM0 == op_name) {
    val = static_cast<uint64_t>(xed_decoded_inst_get_unsigned_immediate(xedd));

  } else if (XED_OPERAND_IMM1_BYTES == op_name || XED_OPERAND_IMM1 == op_name) {
    val = static_cast<uint64_t>(xed_decoded_inst_get_second_immediate(xedd));

  } else {
    LOG(FATAL) << "Unexpected immediate type " << op_name;
  }

  // Note: We use `addr_width` instead of `op_size` because `In<T>` internally
  //       stores an `addr_t` to avoid `byval` arguments.
  args.push_back(llvm::ConstantInt::get(
      llvm::Type::getIntNTy(*context, addr_width), val, is_signed));
}

namespace {

static bool IsVectorReg(xed_reg_enum_t reg) {
  switch (xed_reg_class(reg)) {
    case XED_REG_CLASS_MMX:
    case XED_REG_CLASS_XMM:
    case XED_REG_CLASS_YMM:
    case XED_REG_CLASS_ZMM:
      return true;
    default:
      return false;
  }
}

static bool IsSSE(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_extension(xedd)) {
    case XED_EXTENSION_SSE:
    case XED_EXTENSION_SSE2:
    case XED_EXTENSION_SSE3:
    case XED_EXTENSION_SSE4:
    case XED_EXTENSION_SSE4A:
    case XED_EXTENSION_SSSE3:
      return true;
    default:
      return false;
  }
}

}  // namespace

// Lift a register operand. We need to handle both reads and writes. We place
// writes first as they are the output operands.
void InstructionTranslator::LiftRegister(const xed_operand_t *xedo) {
  auto op_name = xed_operand_name(xedo);
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  std::string reg_name = xed_reg_enum_t2str(reg);
  llvm::IRBuilder<> ir(basic_block);

  // Pass the register by reference.
  if (xed_operand_written(xedo)) {

    // XMM registers have different behavior when using SSE vs. using AVX. SSE
    // instructions operating on XMM registers on a machine with AVX will not
    // cause zeroing of the high bits of the YMM/ZMM registers. If AVX-specific
    // versions of the same instructions (usually prefixed with a `V`) are used
    // then writing to an XMM register will kill the high bits of a YMM/ZMM
    // register, thus breaking data dependencies (sort of like how writing to
    // a 32-bit register on a 64-bit system zeroes the high bits).
    std::string legacy_suffix;
    if (XED_REG_CLASS_XMM == xed_reg_class(reg) && IsSSE(xedd)) {
      legacy_suffix = "_legacy";
    }
    llvm::LoadInst *RegAddr = ir.CreateLoad(
        FindVarInFunction(function, reg_name + "_write" + legacy_suffix));
    args.push_back(RegAddr);
  }

  if (xed_operand_read(xedo)) {
    llvm::LoadInst *reg_addr_val = ir.CreateLoad(
        FindVarInFunction(function, reg_name + "_read"));

    llvm::LoadInst *reg_val = ir.CreateLoad(reg_addr_val);

    // This is an annoying hack. Clang will always use ABI-specific argument
    // type coercion, which means that important type information isn't always
    // correctly communicated via argument types. In these cases, we really
    // want to be passing the structure types associated with the vectors, but
    // Clang's code generator would have us pass vectors of integral/floating
    // point values instead. To avoid this issue, we pass vector registers by
    // constant references (i.e. by address).
    if (IsVectorReg(reg)) {
      reg_val->setAlignment(kVectorRegAlign);

      // We go through the indirection of a load then a store to a local so
      // that we never have the issue where a register is both a source and
      // destination operand and the destination is written before the
      // source is read.
      llvm::AllocaInst *ind_val_addr = ir.CreateAlloca(reg_val->getType());
      ir.CreateStore(reg_val, ind_val_addr);

      args.push_back(ind_val_addr);

    // Okay so we're only passing a normal value, but then we need to watch
    // out! We represent all register and immediate types as structures
    // containing our machine `addr_t` type so that scalarization of the
    // arguments always happens (as opposed to passing `byval` structure
    // pointers). So in many cases we'll need to zero-extend the value into
    // and `addr_t`.
    } else {
      if (xed_get_register_width_bits64(reg) < addr_width) {
        args.push_back(ir.CreateZExt(reg_val, intptr_type));
      } else {
        args.push_back(reg_val);
      }
    }
  }
}

// Lift a relative branch operand.
void InstructionTranslator::LiftBranchDisplacement(void) {
  args.push_back(llvm::ConstantInt::get(intptr_type, TargetPC(), true));
}

namespace {

llvm::Value *KillReg(llvm::BasicBlock *basic_block, const char *name,
                     llvm::Function *undef, llvm::Value *undef_val) {
  auto function = basic_block->getParent();
  llvm::IRBuilder<> ir(basic_block);
  if (!undef_val) {
    undef_val = ir.CreateCall(undef);
  }
  auto reg_addr_val = ir.CreateLoad(FindVarInFunction(function, name));
  ir.CreateStore(undef_val, reg_addr_val);
  return undef_val;
}

}  // namespace

void InstructionTranslator::AddTerminatingKills(
    const Translator &lifter, const BasicBlockRegs *regs) {
  llvm::IRBuilder<> ir(basic_block);

  auto create_undef_bool = lifter.intrinsics->undefined_8;
  llvm::Value *undef_bool = nullptr;

  if (!regs->flags.kill.s.af) {
    undef_bool = KillReg(basic_block, "AF_write",
                         create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.cf) {
    undef_bool = KillReg(basic_block, "CF_write",
                         create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.df) {
    undef_bool = KillReg(basic_block, "DF_write",
                         create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.of) {
    undef_bool = KillReg(basic_block, "OF_write",
                         create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.pf) {
    undef_bool = KillReg(basic_block, "PF_write",
                         create_undef_bool, undef_bool);
  } else {
    asm("nop;");
  }
  if (!regs->flags.kill.s.sf) {
    undef_bool = KillReg(basic_block, "SF_write",
                         create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.zf) {
    undef_bool = KillReg(basic_block, "ZF_write",
                         create_undef_bool, undef_bool);
  }

  llvm::Value *undef_reg = nullptr;
  llvm::Function *create_undef_reg = kArchAMD64 == analysis->arch_name ?
                                     lifter.intrinsics->undefined_64 :
                                     lifter.intrinsics->undefined_32;

  if (!regs->regs.kill.s.rax) {
    undef_reg = KillReg(basic_block, "EAX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rcx) {
    undef_reg = KillReg(basic_block, "ECX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rdx) {
    undef_reg = KillReg(basic_block, "EDX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rbx) {
    undef_reg = KillReg(basic_block, "EBX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rbp) {
    undef_reg = KillReg(basic_block, "EBP_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rsi) {
    undef_reg = KillReg(basic_block, "ESI_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rdi) {
    undef_reg = KillReg(basic_block, "EDI_write", create_undef_reg, undef_reg);
  }
  if (kArchAMD64 == analysis->arch_name) {
    if (!regs->regs.kill.s.r8) {
      undef_reg = KillReg(basic_block, "R8_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r9) {
      undef_reg = KillReg(basic_block, "R9_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r10) {
      undef_reg = KillReg(basic_block, "R10_write",
                          create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r11) {
      undef_reg = KillReg(basic_block, "R11_write",
                          create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r12) {
      undef_reg = KillReg(basic_block, "R12_write",
                          create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r13) {
      undef_reg = KillReg(basic_block, "R13_write",
                          create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r14) {
      undef_reg = KillReg(basic_block, "R14_write",
                          create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r15) {
      undef_reg = KillReg(basic_block, "R15_write",
                          create_undef_reg, undef_reg);
    }
  }
}

bool InstructionTranslator::IsFunctionCall(void) const {
  return XED_CATEGORY_CALL == xed_decoded_inst_get_category(xedd);
}

bool InstructionTranslator::IsFunctionReturn(void) const {
  return XED_ICLASS_RET_NEAR == iclass || XED_ICLASS_RET_FAR == iclass;
}

// TODO(pag): Should far calls be treated as syscalls or indirect calls?
bool InstructionTranslator::IsSystemCall(void) const {
  return XED_ICLASS_SYSCALL == iclass || XED_ICLASS_SYSCALL_AMD == iclass ||
         XED_ICLASS_SYSENTER == iclass;
}

bool InstructionTranslator::IsSystemReturn(void) const {
  return XED_ICLASS_SYSRET == iclass || XED_ICLASS_SYSRET_AMD == iclass ||
         XED_ICLASS_SYSEXIT == iclass;
}

bool InstructionTranslator::IsInterruptCall(void) const {
  return (XED_ICLASS_INT <= iclass && XED_ICLASS_INTO >= iclass) ||
         XED_ICLASS_BOUND == iclass;
}

bool InstructionTranslator::IsConditionalInterruptCall(void) const {
  return XED_ICLASS_INTO == iclass || XED_ICLASS_BOUND == iclass;
}

bool InstructionTranslator::IsInterruptReturn(void) const {
  return XED_ICLASS_IRET <= iclass && XED_ICLASS_IRETQ >= iclass;
}

// This includes `JRCXZ`.
bool InstructionTranslator::IsBranch(void) const {
  return XED_CATEGORY_COND_BR == xed_decoded_inst_get_category(xedd);
}

bool InstructionTranslator::IsJump(void) const {
  return XED_CATEGORY_UNCOND_BR == xed_decoded_inst_get_category(xedd);
}

bool InstructionTranslator::IsDirectFunctionCall(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR == op_name;
}

bool InstructionTranslator::IsIndirectFunctionCall(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return (XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_CALL_FAR == iclass;
}

bool InstructionTranslator::IsDirectJump(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR == op_name;
}

bool InstructionTranslator::IsIndirectJump(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return (XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_JMP_FAR == iclass ||
         XED_ICLASS_XEND == iclass || XED_ICLASS_XABORT == iclass;
}

bool InstructionTranslator::IsNoOp(void) const {
  switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_NOP:
    case XED_CATEGORY_WIDENOP:
      return true;
    default:
      return false;
  }
}

bool InstructionTranslator::IsError(void) const {
  return XED_ICLASS_HLT == iclass || XED_ICLASS_UD2 == iclass ||
         XED_ICLASS_INVALID == iclass;
}

uintptr_t InstructionTranslator::TargetPC(void) const {
  CHECK(IsDirectJump() || IsDirectFunctionCall() || IsBranch())
      << "Can only get target PC of a direct jump, branch, or function call.";
  auto disp = xed_decoded_inst_get_branch_displacement(xedd);
  auto next_pc = static_cast<intptr_t>(NextPC());
  return static_cast<uintptr_t>(next_pc + disp);
}

uintptr_t InstructionTranslator::NextPC(void) const {
  return instr->address() + instr->size();
}

}  // namespace x86
}  // namespace remill
