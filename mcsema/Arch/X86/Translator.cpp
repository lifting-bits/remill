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

#include "mcsema/Arch/X86/Arch.h"
#include "mcsema/Arch/X86/RegisterAnalysis.h"
#include "mcsema/Arch/X86/Translator.h"
#include "mcsema/BC/IntrinsicTable.h"
#include "mcsema/BC/Translator.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace x86 {

enum {
  kVectorRegAlign = 64
};

InstructionTranslator::InstructionTranslator(
    RegisterAnalysis &analysis_,
    const cfg::Block &block_, const cfg::Instr &instr_,
    const struct xed_decoded_inst_s &xedd_)
    : analysis(&analysis_),
      block(&block_),
      instr(&instr_),
      xedd(&xedd_),
      xedi(xed_decoded_inst_inst(xedd)),
      iclass(xed_decoded_inst_get_iclass(xedd)),
      addr_width(kArchAMD64 == analysis->arch_name ? 64 : 32),
      B(nullptr),
      F(nullptr),
      M(nullptr),
      C(nullptr),
      IntPtrTy(nullptr),
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
                                          llvm::BasicBlock *B_) {
  B = B_;
  F = B->getParent();
  M = F->getParent();
  C = &(F->getContext());
  IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);

  LiftPC(instr->address());

  if (!IsNoOp() && !IsError()) {
    LiftGeneric(lifter);
  }

  // Kill whatever we can at the end of this instruction.
  //
  // Note:  Instructions are lifted in reverse order, i.e. end of the block to
  //        beginning of the block.
  if (auto block_regs = analysis->blocks[block->address()]) {
    AddTerminatingKills(lifter, block_regs, B);
    block_regs->UpdateEntryLive(xedd);
  }

  if (IsError()) {
    AddTerminatingTailCall(B, lifter.intrinsics->error, ReadPC(B));

  } else if (IsDirectJump()) {
    auto target_pc = TargetPC();
    LiftPC(target_pc);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.GetLiftedBlockForPC(target_pc),
                           llvm::ConstantInt::get(IntPtrTy, target_pc, false));

  } else if (IsIndirectJump()) {
    AddTerminatingTailCall(B, lifter.intrinsics->jump, ReadPC(B));

  } else if (IsDirectFunctionCall()) {
    auto target_pc = TargetPC();
    LiftPC(target_pc);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.GetLiftedBlockForPC(target_pc),
                           llvm::ConstantInt::get(IntPtrTy, target_pc, false));

  } else if (IsIndirectFunctionCall()) {
    AddTerminatingTailCall(B, lifter.intrinsics->function_call, ReadPC(B));

  } else if (IsFunctionReturn()) {
    AddTerminatingTailCall(B, lifter.intrinsics->function_return, ReadPC(B));

  } else if (IsBranch()) {
    LiftConditionalBranch(lifter);

  // Instruction implementation handles syscall emulation.
  } else if (IsSystemCall()) {
    AddTerminatingTailCall(B, lifter.intrinsics->system_call, ReadPC(B));

  } else if (IsSystemReturn()) {
    AddTerminatingTailCall(B, lifter.intrinsics->system_return, ReadPC(B));
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();

  // Instruction implementation handles syscall (x86, x32) emulation.
  } else if (IsInterruptCall()) {
    AddTerminatingTailCall(B, lifter.intrinsics->interrupt_call, ReadPC(B));

  } else if (IsInterruptReturn()) {
    AddTerminatingTailCall(B, lifter.intrinsics->interrupt_return, ReadPC(B));
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();
  }
}

// Store the program counter into the associated state register. This
// lets us access this information from within instruction implementations.
void InstructionTranslator::LiftPC(uintptr_t next_pc) {
  auto rip_name = kArchAMD64 == analysis->arch_name ? "RIP_write" : "EIP_write";
  llvm::IRBuilder<> ir(B);
  ir.CreateStore(
      llvm::ConstantInt::get(IntPtrTy, next_pc, false),
      ir.CreateLoad(FindVarInFunction(F, rip_name)));
}

// Read the program counter.
llvm::Value *InstructionTranslator::ReadPC(llvm::BasicBlock *block) {
  auto rip_name = kArchAMD64 == analysis->arch_name ? "RIP_read" : "EIP_read";
  llvm::IRBuilder<> ir(B);
  return ir.CreateLoad(ir.CreateLoad(FindVarInFunction(F, rip_name)));
}

namespace {

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
    << "Argument types don't match to " << func_name << ":"
    << arg_types_str;
}

}  // namespace

// Check the types of a function's argument.
bool InstructionTranslator::CheckArgumentTypes(
    const llvm::Function *F, const std::string &func_name) {
  if (F->arg_size() != args.size()) {
    LOG(ERROR)
            << "Number of arguments don't match to " << func_name << ": "
            << "got " << args.size() << ", wanted " << F->arg_size();
    return false;
  }
  auto i = 0;
  for (const auto &arg : F->args()) {
    if (arg.getType() != args[i]->getType()) {
      DescribeArgTypeMismatch(arg, args[i], F, func_name);
      return false;
    }
    ++i;
  }
  return true;
}

llvm::Function *InstructionTranslator::GetInstructionFunction(void) {
  auto func_name = InstructionFunctionName(xedd);
  llvm::Function *IF = FindFunction(M, func_name);
  llvm::GlobalVariable *FP = FindGlobaVariable(M, func_name);

  if (!IF && FP) {
    CHECK(FP->isConstant() && FP->hasInitializer())
        << "Expected a `constexpr` variable as the function pointer.";
    llvm::Constant *FC = FP->getInitializer()->stripPointerCasts();
    IF = llvm::dyn_cast<llvm::Function>(FC);
  }

  // TODO(pag): Memory leak of `args`, `prepend_instrs`, and `append_instrs`.
  if (!IF || !CheckArgumentTypes(IF, func_name)) {
    LOG(WARNING) << "Missing instruction semantics for " << func_name;
  }

  return IF;
}

// Lift a generic instruction.
void InstructionTranslator::LiftGeneric(const Translator &lifter) {
  // First argument is the state pointer.
  args.push_back(FindStatePointer(F));

  // Second argument is the next program counter.
  args.push_back(llvm::ConstantInt::get(IntPtrTy, NextPC(), false));

  // Lift the operands. This creates the arguments for us to call the
  // instruction implementation.
  auto num_operands = xed_decoded_inst_noperands(xedd);
  for (auto i = 0U; i < num_operands; ++i) {
    LiftOperand(lifter, i);
  }

  if (auto IF = GetInstructionFunction()) {
    auto &IList = B->getInstList();
    IList.insert(IList.end(), prepend_instrs.rbegin(), prepend_instrs.rend());
    IList.push_back(llvm::CallInst::Create(IF, args));
    IList.insert(IList.end(), append_instrs.begin(), append_instrs.end());
  }
}

// Lift a conditional branch instruction.
void InstructionTranslator::LiftConditionalBranch(const Translator &lifter) {
  auto rip_name = kArchAMD64 == analysis->arch_name ? "RIP_read" : "EIP_read";
  auto target_pc = TargetPC();
  auto fall_through_pc = NextPC();

  llvm::IRBuilder<> ir(B);
  llvm::Value *DestPC = ir.CreateLoad(ir.CreateLoad(
      FindVarInFunction(F, rip_name)));
  llvm::Value *BranchPC = llvm::ConstantInt::get(IntPtrTy, target_pc, false);

  llvm::BasicBlock *Taken = llvm::BasicBlock::Create(
      *C, "branch_taken", F);

  llvm::BasicBlock *FallThrough = llvm::BasicBlock::Create(
      *C, "fall_through", F);

  AddTerminatingTailCall(
      Taken, lifter.GetLiftedBlockForPC(target_pc),
      llvm::ConstantInt::get(IntPtrTy, target_pc, false));
  AddTerminatingTailCall(
      FallThrough, lifter.GetLiftedBlockForPC(fall_through_pc),
      llvm::ConstantInt::get(IntPtrTy, fall_through_pc, false));

  ir.CreateCondBr(ir.CreateICmpEQ(BranchPC, DestPC), Taken, FallThrough);
}

// Lift an operand. The goal is to be able to pass all explicit and implicit
// operands as arguments into a function that implements this instruction.
void InstructionTranslator::LiftOperand(const Translator &lifter, unsigned op_num) {
  auto xedo = xed_inst_operand(xedi, op_num);
  if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
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

  llvm::IRBuilder<> ir(B);
  llvm::Type *Int32Ty = llvm::Type::getInt32Ty(*C);
  llvm::Value *A = nullptr;  // Address (as an integer).

  // Address is in the displacement.
  if (XED_REG_INVALID == base && XED_REG_INVALID == index) {
    A = llvm::ConstantInt::get(IntPtrTy, static_cast<uint64_t>(disp), false);

  // PC-relative address.
  } else if (XED_REG_RIP == base) {
    auto next_pc = static_cast<intptr_t>(NextPC());
    A = llvm::ConstantInt::get(IntPtrTy, static_cast<uint64_t>(next_pc + disp),
                               false);

  // Need to to compute the address as `B + (I * S) + D`.
  } else {

    // Convert a given register reference into an integer of the correct
    // size and type. We sometimes need to zero extend the
    auto RegToValue = [&] (xed_reg_enum_t reg) -> llvm::Value * {
      if (XED_REG_INVALID == reg) {
        return llvm::ConstantInt::get(IntPtrTy, 0, false);
      } else {
        auto var_name = std::string(xed_reg_enum_t2str(reg)) + "_read";
        llvm::Value *V = ir.CreateLoad(ir.CreateLoad(
            FindVarInFunction(F, var_name)));
        if (xed_get_register_width_bits64(reg) < addr_width) {
          V = ir.CreateZExt(V, IntPtrTy);
        }
        return V;
      }
    };

    auto B = RegToValue(base);
    auto I = RegToValue(index);

    // Special case: `POP [xSP + ...] uses the value of `xSP` after incrementing
    // it by the stack width.
    if (XED_ICLASS_POP == iclass &&
        XED_REG_RSP == xed_get_largest_enclosing_register(base)) {
      B = ir.CreateAdd(
          B, llvm::ConstantInt::get(IntPtrTy, (addr_width / 8), false));
    }

    llvm::Value *S = llvm::ConstantInt::get(IntPtrTy, scale, true);
    llvm::Value *D = llvm::ConstantInt::get(Int32Ty, disp, true);
    if (32 < addr_width) {
      D = ir.CreateSExt(D, IntPtrTy);
    }
    A = ir.CreateAdd(ir.CreateAdd(B, ir.CreateMul(I, S)), D);
  }

  if (addr_space) {
    std::vector<llvm::Value *> args = {
        FindStatePointer(F),  // Machine state.
        A,  // Address.
        llvm::ConstantInt::get(Int32Ty, addr_space, true)};
    A = ir.CreateCall(lifter.intrinsics->compute_address, args);
  }

  if (xed_operand_written(xedo)) {
    args.push_back(A);
  }
  if (xed_operand_read(xedo)) {
    args.push_back(A);
  }

  // Wrap an instruction in atomic begin/end if it accesses memory with RMW
  // semantics or with a LOCK prefix.
  if (xed_operand_values_get_atomic(xedd) ||
      xed_operand_values_has_lock_prefix(xedd)) {
    auto load_order1 = new llvm::LoadInst(lifter.intrinsics->memory_order);
    auto new_order1 = llvm::CallInst::Create(lifter.intrinsics->atomic_begin,
                                              {load_order1});
    auto store_order1 = new llvm::StoreInst(new_order1,
                                            lifter.intrinsics->memory_order);

    auto load_order2 = new llvm::LoadInst(lifter.intrinsics->memory_order);
    auto new_order2 = llvm::CallInst::Create(lifter.intrinsics->atomic_begin,
                                              {load_order2});
    auto store_order2 = new llvm::StoreInst(new_order2,
                                            lifter.intrinsics->memory_order);

    prepend_instrs.push_back(load_order1);
    prepend_instrs.push_back(new_order1);
    prepend_instrs.push_back(store_order1);

    append_instrs.push_back(store_order2);
    append_instrs.push_back(new_order2);
    append_instrs.push_back(load_order2);
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
      llvm::Type::getIntNTy(*C, addr_width), val, is_signed));
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

}  // namespace

// Lift a register operand. We need to handle both reads and writes. We place
// writes first as they are the output operands.
void InstructionTranslator::LiftRegister(const xed_operand_t *xedo) {
  auto op_name = xed_operand_name(xedo);
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  std::string reg_name = xed_reg_enum_t2str(reg);
  llvm::IRBuilder<> ir(B);

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
    if (XED_CATEGORY_SSE == xed_decoded_inst_get_category(xedd) &&
        XED_REG_CLASS_XMM == xed_gpr_reg_class(reg)) {
      legacy_suffix = "_legacy";
    }
    llvm::LoadInst *RegAddr = ir.CreateLoad(
        FindVarInFunction(F, reg_name + "_write" + legacy_suffix));
    args.push_back(RegAddr);
  }

  if (xed_operand_read(xedo)) {
    llvm::LoadInst *RegAddr = ir.CreateLoad(
        FindVarInFunction(F, reg_name + "_read"));

    llvm::LoadInst *Reg = ir.CreateLoad(RegAddr);

    // This is an annoying hack. Clang will always use ABI-specific argument
    // type coercion, which means that important type information isn't always
    // correctly communicated via argument types. In these cases, we really
    // want to be passing the structure types associated with the vectors, but
    // Clang's code generator would have us pass vectors of integral/floating
    // point values instead. To avoid this issue, we pass vector registers by
    // constant references (i.e. by address).
    if (IsVectorReg(reg)) {
      Reg->setAlignment(kVectorRegAlign);

      // We go through the indirection of a load then a store to a local so
      // that we never have the issue where a register is both a source and
      // destination operand and the destination is written before the
      // source is read.
      llvm::AllocaInst *ValAddr = ir.CreateAlloca(Reg->getType());
      ir.CreateStore(Reg, ValAddr);

      args.push_back(ValAddr);

    // Okay so we're only passing a normal value, but then we need to watch
    // out! We represent all register and immediate types as structures
    // containing our machine `addr_t` type so that scalarization of the
    // arguments always happens (as opposed to passing `byval` structure
    // pointers). So in many cases we'll need to zero-extend the value into
    // and `addr_t`.
    } else {
      if (xed_get_register_width_bits64(reg) < addr_width) {
        args.push_back(ir.CreateZExt(Reg, IntPtrTy));
      } else {
        args.push_back(Reg);
      }
    }
  }
}

// Lift a relative branch operand.
void InstructionTranslator::LiftBranchDisplacement(void) {
  args.push_back(llvm::ConstantInt::get(IntPtrTy, TargetPC(), true));
}

namespace {

llvm::Value *KillReg(llvm::BasicBlock *B, const char *name,
                     llvm::Function *undef, llvm::Value *undef_val) {
  auto F = B->getParent();
  llvm::IRBuilder<> ir(B);
  if (!undef_val) {
    undef_val = ir.CreateCall(undef);
  }
  llvm::LoadInst *RegAddr = ir.CreateLoad(FindVarInFunction(F, name));
  ir.CreateStore(undef_val, RegAddr);
  return undef_val;
}

}  // namespace

void InstructionTranslator::AddTerminatingKills(
    const Translator &lifter, const BasicBlockRegs *regs, llvm::BasicBlock *B) {
  llvm::IRBuilder<> ir(B);

  auto create_undef_bool = lifter.intrinsics->undefined_8;
  llvm::Value *undef_bool = nullptr;

  if (!regs->flags.kill.s.af) {
    undef_bool = KillReg(B, "AF_write", create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.cf) {
    undef_bool = KillReg(B, "CF_write", create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.df) {
    undef_bool = KillReg(B, "DF_write", create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.of) {
    undef_bool = KillReg(B, "OF_write", create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.pf) {
    undef_bool = KillReg(B, "PF_write", create_undef_bool, undef_bool);
  } else {
    asm("nop;");
  }
  if (!regs->flags.kill.s.sf) {
    undef_bool = KillReg(B, "SF_write", create_undef_bool, undef_bool);
  }
  if (!regs->flags.kill.s.zf) {
    undef_bool = KillReg(B, "ZF_write", create_undef_bool, undef_bool);
  }

  llvm::Value *undef_reg = nullptr;
  llvm::Function *create_undef_reg = kArchAMD64 == analysis->arch_name ?
                                     lifter.intrinsics->undefined_64 :
                                     lifter.intrinsics->undefined_32;

  if (!regs->regs.kill.s.rax) {
    undef_reg = KillReg(B, "EAX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rcx) {
    undef_reg = KillReg(B, "ECX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rdx) {
    undef_reg = KillReg(B, "EDX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rbx) {
    undef_reg = KillReg(B, "EBX_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rbp) {
    undef_reg = KillReg(B, "EBP_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rsi) {
    undef_reg = KillReg(B, "ESI_write", create_undef_reg, undef_reg);
  }
  if (!regs->regs.kill.s.rdi) {
    undef_reg = KillReg(B, "EDI_write", create_undef_reg, undef_reg);
  }
  if (kArchAMD64 == analysis->arch_name) {
    if (!regs->regs.kill.s.r8) {
      undef_reg = KillReg(B, "R8_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r9) {
      undef_reg = KillReg(B, "R9_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r10) {
      undef_reg = KillReg(B, "R10_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r11) {
      undef_reg = KillReg(B, "R11_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r12) {
      undef_reg = KillReg(B, "R12_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r13) {
      undef_reg = KillReg(B, "R13_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r14) {
      undef_reg = KillReg(B, "R14_write", create_undef_reg, undef_reg);
    }
    if (!regs->regs.kill.s.r15) {
      undef_reg = KillReg(B, "R15_write", create_undef_reg, undef_reg);
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
}  // namespace mcsema
