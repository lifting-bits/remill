/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/X86/Instr.h"
#include "mcsema/Arch/X86/XED.h"

#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"

DECLARE_string(os);

namespace mcsema {
namespace x86 {

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
      append_instrs() {}

Instr::~Instr(void) {}

namespace {

// Name of this instruction function.
static std::string InstructionFunctionName(const xed_decoded_inst_t *xedd) {
  auto iform = xed_decoded_inst_get_iform_enum(xedd);
  std::string iclass_name = xed_iform_enum_t2str(iform);
  auto op_size = xed_decoded_inst_get_operand_width(xedd);
  return iclass_name + "_" + std::to_string(op_size);
}

// Return the type for a given operand.
static llvm::Type *OperandType(llvm::LLVMContext &C,
                               const xed_operand_t *xedo,
                               unsigned op_size) {

  // Special case: treat AGEN operands (e.g. LEA, BND*) as having any type.
  if (XED_OPERAND_AGEN == xed_operand_name(xedo)) {
    return llvm::Type::getInt8Ty(C);
  }

  switch (xed_operand_xtype(xedo)) {
    case XED_OPERAND_XTYPE_INVALID:
      LOG(FATAL) << "Invalid operand type: XED_OPERAND_XTYPE_INVALID.";
      return nullptr;

    // Binary coded decimal. Really an array of char, and only accessed via
    // memory.
    case XED_OPERAND_XTYPE_B80:
      return llvm::Type::getInt8Ty(C);

    // Half-precision floating point. Usually packed into an XMM register.
    // What we get is a memory operand that's a pointer to four of these.
    case XED_OPERAND_XTYPE_F16:
      return llvm::Type::getHalfTy(C);

    // Single-precision floating point type.
    case XED_OPERAND_XTYPE_F32:
      return llvm::Type::getFloatTy(C);

    // Double-precision floating point type.
    case XED_OPERAND_XTYPE_F64:
      return llvm::Type::getDoubleTy(C);

    // Extended precision (internal to X87 FPU) floating point type.
    case XED_OPERAND_XTYPE_F80:
      return llvm::Type::getX86_FP80Ty(C);

    case XED_OPERAND_XTYPE_I1:
      return llvm::Type::getInt1Ty(C);

    case XED_OPERAND_XTYPE_I16:
      return llvm::Type::getInt16Ty(C);

    case XED_OPERAND_XTYPE_I32:
      return llvm::Type::getInt32Ty(C);

    case XED_OPERAND_XTYPE_I64:
      return llvm::Type::getInt64Ty(C);

    case XED_OPERAND_XTYPE_I8:
      return llvm::Type::getInt8Ty(C);

    // Specific to the effective operand size.
    case XED_OPERAND_XTYPE_INT:
      return llvm::Type::getIntNTy(C, op_size);

    case XED_OPERAND_XTYPE_STRUCT:
      LOG(WARNING)
          << "Treating XED_OPERAND_XTYPE_STRUCT as a "
          << op_size << "-bit integer.";
      return llvm::Type::getIntNTy(C, op_size);

    case XED_OPERAND_XTYPE_U128:
      return llvm::Type::getInt128Ty(C);

    case XED_OPERAND_XTYPE_U16:
      return llvm::Type::getInt16Ty(C);

    case XED_OPERAND_XTYPE_U256:
      return llvm::Type::getIntNTy(C, 256);

    case XED_OPERAND_XTYPE_U32:
    return llvm::Type::getInt32Ty(C);

    case XED_OPERAND_XTYPE_U64:
      return llvm::Type::getInt64Ty(C);

    case XED_OPERAND_XTYPE_U8:
      return llvm::Type::getInt8Ty(C);

    case XED_OPERAND_XTYPE_UINT:
      return llvm::Type::getIntNTy(C, op_size);

    case XED_OPERAND_XTYPE_VAR:
      LOG(FATAL) << "Unsupported operand type: XED_OPERAND_XTYPE_VAR.";
      return nullptr;

    case XED_OPERAND_XTYPE_LAST:
      LOG(FATAL) << "Invalid operand type: XED_OPERAND_XTYPE_LAST.";
      return nullptr;
  }
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

// Find the block method template by name.
static llvm::Function *IndirectBranchResolver(llvm::Module *M) {
  if (FLAGS_os == "linux") {
    return M->getFunction("_ZN5State22IndirectBranchResolverEv");
  } else {
    LOG(FATAL) << "Missing block method name for OS: " << FLAGS_os;
    return nullptr;
  }
}

}  // namespace

bool Instr::Lift(const BlockMap &blocks, llvm::BasicBlock *B_) {
  B = B_;
  F = B->getParent();
  M = F->getParent();
  C = &(F->getContext());

  LiftPC();

  if (IsDirectJump()) {
    AddTerminatingTailCall(B, blocks[TargetPC()]);
    return false;

  } else if (IsIndirectJump()) {
    LiftGeneric();  // loads target into `gpr.rip`.
    AddTerminatingTailCall(B, IndirectBranchResolver(M));
    return false;

  } else if (IsDirectFunctionCall()) {
    LiftGeneric();  // Adjusts the stack, stores `gpr.rip` to the stack.
    AddTerminatingTailCall(B, blocks[TargetPC()]);
    return false;

  } else if (IsIndirectFunctionCall()) {
    LiftGeneric();  // Adjusts the stack, loads target into `gpr.rip`.
    AddTerminatingTailCall(B, IndirectBranchResolver(M));
    return false;

  } else if (IsFunctionReturn()) {
    LiftGeneric();  // Adjusts the stack, loads target into `gpr.rip`.
    AddTerminatingTailCall(B, IndirectBranchResolver(M));
    return false;

  } else if (IsBranch()) {
    LiftConditionalBranch(blocks);
    return false;

  // Instruction implementation handles syscall emulation.
  } else if (IsSystemCall()) {
    LiftGeneric();
    return false;

  } else if (IsSystemReturn()) {
    LOG(FATAL)
        << "Unsupported instruction (system return) at PC " << instr->address();
    return false;

  // Instruction implementation handles syscall (x86, x32) emulation.
  } else if (IsInterruptCall()) {
    LiftGeneric();
    return false;

  } else if (IsInterruptReturn()) {
    LOG(FATAL)
        << "Unsupported instruction (system return) at PC " << instr->address();
    return false;

  // Not a control-flow instruction, need to add a fall-through.
  } else {
    LiftGeneric();
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
void Instr::LiftPC(void) {
  auto addr_width = xed_operand_values_get_effective_address_width(xedd);

  llvm::IRBuilder<> ir(B);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  ir.CreateStore(
      llvm::ConstantInt::get(IntPtrTy, NextPC(), false),
      ir.CreateLoad(FindLocalVariable(F, PCRegName(xedd) + "_write")));
}

// Lift a generic instruction.
void Instr::LiftGeneric(void) {
  args.push_back(&*F->arg_begin());

  // Lift the operands. This creates the arguments for us to call the
  // instruction implementation.
  auto num_operands = xed_decoded_inst_noperands(xedd);

  for (auto i = 0U; i < num_operands; ++i) {
    LiftOperand(i);
  }

  llvm::IRBuilder<> ir(B);

  auto func_name = InstructionFunctionName(xedd);
  if (auto F = M->getFunction(func_name)) {
    ir.CreateCall(F, args);
  } else if (auto FP = M->getGlobalVariable(func_name)) {
    CHECK(FP->isConstant() && FP->hasInitializer())
        << "Expected a `constexpr` variable as the function pointer.";
    ir.CreateCall(llvm::dyn_cast<llvm::Function>(FP->getInitializer()), args);
  } else {
    LOG(FATAL) << "Missing instruction semantics for " << func_name;
  }

  // Fixup instructions that must follow the instruction function. These handle
  // things like segment-specific memory operands.
  auto &IList = B->getInstList();
  for (auto instr : append_instrs) {
    IList.push_back(instr);
  }
}

// Lift a conditional branch instruction.
void Instr::LiftConditionalBranch(const BlockMap &blocks) {
  LiftGeneric();
  auto addr_width = xed_operand_values_get_effective_address_width(xedd);
  auto target_pc = TargetPC();

  llvm::IRBuilder<> ir(B);
  llvm::Value *DestPC = ir.CreateLoad(ir.CreateLoad(
      FindLocalVariable(F, PCRegName(xedd) + "_read")));
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  llvm::Value *BranchPC = llvm::ConstantInt::get(IntPtrTy, target_pc, false);

  llvm::BasicBlock *Taken = llvm::BasicBlock::Create(
      *C, "branch_taken", F);

  llvm::BasicBlock *FallThrough = llvm::BasicBlock::Create(
      *C, "fall_through", F);

  AddTerminatingTailCall(Taken, blocks[target_pc]);
  AddTerminatingTailCall(FallThrough, blocks[NextPC()]);

  ir.CreateCondBr(ir.CreateICmpEQ(BranchPC, DestPC), Taken, FallThrough);
}

// Lift an operand. The goal is to be able to pass all explicit and implicit
// operands as arguments into a function that implements this instruction.
void Instr::LiftOperand(unsigned op_num) {
  auto xedo = xed_inst_operand(xedi, op_num);
  if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
        LiftMemory(xedo, op_num);
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
void Instr::LiftMemory(const xed_operand_t *xedo, unsigned op_num) {
  auto op_name = xed_operand_name(xedo);
  auto op_width = xed_decoded_inst_operand_length_bits(xedd, op_num);
  auto mem_index = XED_OPERAND_MEM0 == op_name ? 0 : 1;
  auto seg = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto addr_width = xed_decoded_inst_get_memop_address_width(xedd, mem_index);
  auto addr_space = AddressSpace(seg, op_name);

  llvm::IRBuilder<> ir(B);
  llvm::Type *ValTy = OperandType(*C, xedo, op_width);
  llvm::Type *PtrTy = ValTy->getPointerTo(addr_space);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  llvm::Type *Int32Ty = llvm::Type::getInt32Ty(*C);
  llvm::Value *A = nullptr;  // Address (as an integer).
  llvm::Value *P = nullptr;  // Pointer (address space 0).
  llvm::Value *M = nullptr;  // Pointer (address space specific).

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
            FindLocalVariable(F, var_name)));
        if (xed_get_register_width_bits64(reg) < addr_width) {
          V = ir.CreateZExt(V, IntPtrTy);
        }
        return V;
      }
    };

    auto B = RegToValue(base);
    auto I = RegToValue(index);

    llvm::Value *S = llvm::ConstantInt::get(IntPtrTy, scale, true);
    llvm::Value *D = llvm::ConstantInt::get(Int32Ty, disp, true);
    if (32 < addr_width) {
      D = ir.CreateSExt(D, IntPtrTy);
    }
    A = ir.CreateAdd(ir.CreateAdd(B, ir.CreateMul(I, S)), D);
  }

  M = ir.CreateIntToPtr(A, PtrTy);
  if (addr_space) {
    P = ir.CreateAlloca(ValTy);
    if (xed_operand_read(xedo)) {
      ir.CreateStore(ir.CreateLoad(M), P);
    }
    if (xed_operand_written(xedo)) {
      auto V = new llvm::LoadInst(P);
      append_instrs.push_back(V);
      append_instrs.push_back(new llvm::StoreInst(V, M));
    }
  } else {
    P = M;
  }

  args.push_back(P);
}

// Convert an immediate constant into an LLVM `Value` for passing into the
// instruction implementation.
void Instr::LiftImmediate(xed_operand_enum_t op_name) {
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

  args.push_back(llvm::ConstantInt::get(
      llvm::Type::getIntNTy(*C, op_size), val, is_signed));
}

// Lift a register operand. We need to handle both reads and writes. We place
// writes first as they are the output operands.
void Instr::LiftRegister(const xed_operand_t *xedo) {
  auto op_name = xed_operand_name(xedo);
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  std::string reg_name = xed_reg_enum_t2str(reg);

  llvm::IRBuilder<> ir(B);
  if (xed_operand_written(xedo)) {
    args.push_back(
        ir.CreateLoad(FindLocalVariable(F, reg_name + "_write")));
  }
  if (xed_operand_read(xedo)) {
    args.push_back(
        ir.CreateLoad(
            ir.CreateLoad(FindLocalVariable(F, reg_name + "_read"))));
  }
}

// Lift a relative branch operand.
void Instr::LiftBranchDisplacement(void) {
  auto addr_width = xed_operand_values_get_effective_address_width(xedd);
  llvm::Type *IntPtrTy = llvm::Type::getIntNTy(*C, addr_width);
  args.push_back(llvm::ConstantInt::get(IntPtrTy, TargetPC(), true));
}

bool Instr::IsFunctionCall(void) const {
  return XED_ICLASS_CALL_NEAR == iclass || XED_ICLASS_CALL_FAR == iclass;
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
  return (XED_ICLASS_JB <= iclass && XED_ICLASS_JLE >= iclass) ||
         (XED_ICLASS_JNB <= iclass && XED_ICLASS_JZ >= iclass) ||
         (XED_ICLASS_LOOP <= iclass && XED_ICLASS_LOOPNE >= iclass) ||
         XED_ICLASS_XBEGIN == iclass;
}

bool Instr::IsJump(void) const {
  return XED_ICLASS_JMP == iclass || XED_ICLASS_JMP_FAR == iclass ||
         XED_ICLASS_XEND == iclass || XED_ICLASS_XABORT == iclass;
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
