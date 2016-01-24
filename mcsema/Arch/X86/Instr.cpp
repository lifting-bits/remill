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

#include "mcsema/BC/IntrinsicTable.h"
#include "mcsema/BC/Translator.h"
#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"

#include "mcsema/Arch/X86/Instr.h"
#include "mcsema/Arch/X86/XED.h"

namespace mcsema {
namespace x86 {

enum {
  kVectorRegAlign = 64
};

Instr::Instr(const cfg::Instr *instr_, const struct xed_decoded_inst_s *xedd_)
    : ::mcsema::Instr(instr_),
      xedd(xedd_),
      xedi(xed_decoded_inst_inst(xedd)),
      iclass(xed_decoded_inst_get_iclass(xedd)),
      B(nullptr),
      F(nullptr),
      M(nullptr),
      C(nullptr),
      args(),
      prepend_instrs(),
      append_instrs() {}

Instr::~Instr(void) {}

namespace {

// Name of this instruction function.
static std::string InstructionFunctionName(const xed_decoded_inst_t *xedd) {
  std::stringstream ss;
  std::string iform_name = xed_iform_enum_t2str(
      xed_decoded_inst_get_iform_enum(xedd));
  if (xed_operand_values_has_lock_prefix(xedd)) {
    const std::string lock = "LOCK_";
    const auto idx = iform_name.find(lock);
    if (std::string::npos != idx) {
      iform_name.erase(idx, lock.size());
    }
  }
  ss << iform_name;
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

bool Instr::LiftIntoBlock(const Translator &lifter, llvm::BasicBlock *B_) {
  B = B_;
  F = B->getParent();
  M = F->getParent();
  C = &(F->getContext());

  LiftPC(instr->address());

  if (IsError()) {
    AddTerminatingTailCall(B, lifter.intrinsics->error);
    return false;

  } else if (IsDirectJump()) {
    auto target_pc = TargetPC();
    LiftPC(target_pc);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.GetLiftedBlockForPC(target_pc));
    return false;

  } else if (IsIndirectJump()) {
    LiftGeneric(lifter);  // loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.intrinsics->jump);
    return false;

  } else if (IsDirectFunctionCall()) {
    LiftGeneric(lifter);  // Adjusts the stack, stores `gpr.rip` to the stack.
    AddTerminatingTailCall(B, lifter.GetLiftedBlockForPC(TargetPC()));
    return false;

  } else if (IsIndirectFunctionCall()) {
    LiftGeneric(lifter);  // Adjusts the stack, loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.intrinsics->function_call);
    return false;

  } else if (IsFunctionReturn()) {
    LiftGeneric(lifter);  // Adjusts the stack, loads target into `gpr.rip`.
    AddTerminatingTailCall(B, lifter.intrinsics->function_return);
    return false;

  } else if (IsBranch()) {
    LiftGeneric(lifter);  // Conditionally loads taken target into `gpr.rip`.
    LiftConditionalBranch(lifter);  // Conditional branch based on `gpr.rip`.
    return false;

  // Instruction implementation handles syscall emulation.
  } else if (IsSystemCall()) {
    LiftGeneric(lifter);
    AddTerminatingTailCall(B, lifter.intrinsics->system_call);
    return false;

  } else if (IsSystemReturn()) {
    LiftGeneric(lifter);
    AddTerminatingTailCall(B, lifter.intrinsics->system_return);
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();
    return false;

  // Instruction implementation handles syscall (x86, x32) emulation.
  } else if (IsInterruptCall()) {
    LiftGeneric(lifter);
    AddTerminatingTailCall(B, lifter.intrinsics->interrupt_call);
    return false;

  } else if (IsInterruptReturn()) {
    LiftGeneric(lifter);
    AddTerminatingTailCall(B, lifter.intrinsics->interrupt_return);
    LOG(WARNING)
        << "Unsupported instruction (system return) at PC " << instr->address();
    return false;

  } else if (IsNoOp()) {
    return true;

  // Not a control-flow instruction, need to add a fall-through.
  } else {
    // TODO(pag): Should we load in the next pc? In practice, the instructions
    //            don't need access to this information; it only matters at
    //            control flows.

    LiftGeneric(lifter);
    return true;
  }
}

namespace {

// Name of the program counter register.
static std::string PCRegName(const xed_decoded_inst_t *xedd) {
  switch (xed_operand_values_get_effective_address_width(xedd)) {
    case 64: return "RIP";
    case 32: return "EIP";
    case 16: return "IP";
    default:
      LOG(ERROR) << "Unexpected address width.";
      return "";
  }
}

}  // namespace

// Store the next program counter into the associated state register. This
// lets us access this information from within instruction implementations.
void Instr::LiftPC(uintptr_t next_pc) {
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);

  llvm::IRBuilder<> ir(B);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  ir.CreateStore(
      llvm::ConstantInt::get(IntPtrTy, next_pc, false),
      ir.CreateLoad(FindVarInFunction(F, PCRegName(xedd) + "_write")));
}

// Check the types of a function's argument.
bool Instr::CheckArgumentTypes(const llvm::Function *F,
                               const std::string &func_name) {
  if (F->arg_size() != args.size()) {
    LOG(ERROR)
            << "Number of arguments don't match to " << func_name << ": "
            << "got " << args.size() << ", wanted " << F->arg_size();
    return false;
  }
  auto i = 0;
  for (const auto &arg : F->args()) {
    const auto arg_type = arg.getType();
    if (arg_type != args[i]->getType()) {
      std::string arg_types_str;
      llvm::raw_string_ostream arg_types_stream(arg_types_str);
      arg_types_stream << "\n";
      arg.print(arg_types_stream);
      arg_types_stream << " in ";
      F->getFunctionType()->print(arg_types_stream);
      arg_types_stream << "\n";
      args[i]->print(arg_types_stream);
      LOG(ERROR)
        << "Argument types don't match to " << func_name << ":"
        << arg_types_str;
      return false;
    }
    ++i;
  }
  return true;
}

// Lift a generic instruction.
void Instr::LiftGeneric(const Translator &lifter) {
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);

  // First argument is the state pointer.
  args.push_back(&*F->arg_begin());

  // Second argument is the next program counter.
  args.push_back(llvm::ConstantInt::get(IntPtrTy, NextPC(), false));

  // Lift the operands. This creates the arguments for us to call the
  // instruction implementation.
  auto num_operands = xed_decoded_inst_noperands(xedd);
  auto func_name = InstructionFunctionName(xedd);

  for (auto i = 0U; i < num_operands; ++i) {
    LiftOperand(lifter, i);
  }

  llvm::Function *F = FindFunction(M, func_name);
  llvm::GlobalVariable *FP = FindGlobaVariable(M, func_name);

  if (!F && FP) {
    CHECK(FP->isConstant() && FP->hasInitializer())
        << "Expected a `constexpr` variable as the function pointer.";
    llvm::Constant *FC = FP->getInitializer()->stripPointerCasts();
    F = llvm::dyn_cast<llvm::Function>(FC);
  }

  // Instructions that must follow the instruction function.
  auto &IList = B->getInstList();
  std::reverse(prepend_instrs.begin(), prepend_instrs.end());
  for (auto instr : prepend_instrs) {
    IList.push_back(instr);
  }

  if (F && CheckArgumentTypes(F, func_name)) {
    IList.push_back(llvm::CallInst::Create(F, args));
  } else {
    LOG(WARNING) << "Missing instruction semantics for " << func_name;
  }

  // Instructions that must follow the instruction function.
  for (auto instr : append_instrs) {
    IList.push_back(instr);
  }
}

// Lift a conditional branch instruction.
void Instr::LiftConditionalBranch(const Translator &lifter) {
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);
  auto target_pc = TargetPC();

  llvm::IRBuilder<> ir(B);
  llvm::Value *DestPC = ir.CreateLoad(ir.CreateLoad(
      FindVarInFunction(F, PCRegName(xedd) + "_read")));
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  llvm::Value *BranchPC = llvm::ConstantInt::get(IntPtrTy, target_pc, false);

  llvm::BasicBlock *Taken = llvm::BasicBlock::Create(
      *C, "branch_taken", F);

  llvm::BasicBlock *FallThrough = llvm::BasicBlock::Create(
      *C, "fall_through", F);

  AddTerminatingTailCall(Taken, lifter.GetLiftedBlockForPC(target_pc));
  AddTerminatingTailCall(FallThrough, lifter.GetLiftedBlockForPC(NextPC()));

  ir.CreateCondBr(ir.CreateICmpEQ(BranchPC, DestPC), Taken, FallThrough);
}

// Lift an operand. The goal is to be able to pass all explicit and implicit
// operands as arguments into a function that implements this instruction.
void Instr::LiftOperand(const Translator &lifter, unsigned op_num) {
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

      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
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
void Instr::LiftMemory(const Translator &lifter, const xed_operand_t *xedo,
                       unsigned op_num) {
  auto op_name = xed_operand_name(xedo);
  auto op_width = xed_decoded_inst_get_operand_width(xedd);
  auto mem_index = (XED_OPERAND_MEM1 == op_name) ? 1 : 0;  // Handles AGEN.
  auto seg = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);
  auto addr_space = AddressSpace(seg, op_name);

  llvm::IRBuilder<> ir(B);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
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
    std::vector<llvm::Value *> atomic_args;
    atomic_args.push_back(A);
    atomic_args.push_back(llvm::ConstantInt::get(Int32Ty, op_width, false));
    prepend_instrs.push_back(ir.CreateCall(
        lifter.intrinsics->atomic_begin, atomic_args));
    append_instrs.push_back(ir.CreateCall(
        lifter.intrinsics->atomic_end, atomic_args));
  }
}

// Convert an immediate constant into an LLVM `Value` for passing into the
// instruction implementation.
void Instr::LiftImmediate(xed_operand_enum_t op_name) {
  auto val = 0ULL;
  auto is_signed = false;
  auto op_size = xed_decoded_inst_get_operand_width(xedd);
  auto imm_size = xed_decoded_inst_get_immediate_width_bits(xedd);
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);

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
void Instr::LiftRegister(const xed_operand_t *xedo) {
  auto op_name = xed_operand_name(xedo);
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  std::string reg_name = xed_reg_enum_t2str(reg);
  llvm::IRBuilder<> ir(B);

  // Pass the register by reference.
  if (xed_operand_written(xedo)) {
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
      auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);
      if (xed_get_register_width_bits64(reg) < addr_width) {
        llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
        args.push_back(ir.CreateZExt(Reg, IntPtrTy));
      } else {
        args.push_back(Reg);
      }
    }
  }
}

// Lift a relative branch operand.
void Instr::LiftBranchDisplacement(void) {
  auto addr_width = xed_decoded_inst_get_machine_mode_bits(xedd);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  args.push_back(llvm::ConstantInt::get(IntPtrTy, TargetPC(), true));
}

bool Instr::IsFunctionCall(void) const {
  return XED_CATEGORY_CALL == xed_decoded_inst_get_category(xedd);
}

bool Instr::IsFunctionReturn(void) const {
  return XED_ICLASS_RET_NEAR == iclass || XED_ICLASS_RET_FAR == iclass;
}

// TODO(pag): Should far calls be treated as syscalls or indirect calls?
bool Instr::IsSystemCall(void) const {
  return XED_ICLASS_SYSCALL == iclass || XED_ICLASS_SYSCALL_AMD == iclass ||
         XED_ICLASS_SYSENTER == iclass;
}

bool Instr::IsSystemReturn(void) const {
  return XED_ICLASS_SYSRET == iclass || XED_ICLASS_SYSRET_AMD == iclass ||
         XED_ICLASS_SYSEXIT == iclass;
}

bool Instr::IsInterruptCall(void) const {
  return XED_ICLASS_INT <= iclass && XED_ICLASS_INTO >= iclass;
}

bool Instr::IsInterruptReturn(void) const {
  return XED_ICLASS_IRET <= iclass && XED_ICLASS_IRETQ >= iclass;
}

// This includes `JRCXZ`.
bool Instr::IsBranch(void) const {
  return XED_CATEGORY_COND_BR == xed_decoded_inst_get_category(xedd);
}

bool Instr::IsJump(void) const {
  return XED_CATEGORY_UNCOND_BR == xed_decoded_inst_get_category(xedd);
}

bool Instr::IsDirectFunctionCall(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR == op_name;
}

bool Instr::IsIndirectFunctionCall(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return (XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_CALL_FAR == iclass;
}

bool Instr::IsDirectJump(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR == op_name;
}

bool Instr::IsIndirectJump(void) const {
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  return (XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_JMP_FAR == iclass ||
         XED_ICLASS_XEND == iclass || XED_ICLASS_XABORT == iclass;
}

bool Instr::IsNoOp(void) const {
  switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_NOP:
    case XED_CATEGORY_WIDENOP:
      return true;
    default:
      return false;
  }
}

bool Instr::IsError(void) const {
  return XED_ICLASS_HLT == iclass;
}

uintptr_t Instr::TargetPC(void) const {
  CHECK(IsDirectJump() || IsDirectFunctionCall() || IsBranch())
      << "Can only get target PC of a direct jump, branch, or function call.";
  auto disp = xed_decoded_inst_get_branch_displacement(xedd);
  auto next_pc = static_cast<intptr_t>(NextPC());
  return static_cast<uintptr_t>(next_pc + disp);
}

uintptr_t Instr::NextPC(void) const {
  return instr->address() + instr->size();
}


}  // namespace x86
}  // namespace mcsema
