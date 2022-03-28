#include <remill/BC/SleighLifter.h>

namespace remill {

LiftStatus
SleighLifter::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                            llvm::Value *state_ptr, bool is_delayed) {

  if (!inst.IsValid()) {
    LOG(ERROR) << "Invalid function" << inst.Serialize();
    inst.operands.clear();
    return kLiftedInvalidInstruction;
  }

  llvm::IRBuilder<> ir(block);

  const OpCode op = get_opcode(inst.function);
  LOG(INFO) << "Attempting to lift opcode: " << op;
  switch (op) {
    case OpCode::CPUI_BOOL_NEGATE:
      return LiftUnOp(inst, block, state_ptr, ir, op);
    case CPUI_INT_LESS:
    case CPUI_INT_SLESS:
    case CPUI_INT_EQUAL:
    case CPUI_INT_SUB:
    case CPUI_INT_SBORROW:
    case CPUI_INT_AND: return LiftBinOp(inst, block, state_ptr, ir, op); break;
    case CPUI_POPCOUNT: LiftPopCount(inst, block, state_ptr, ir); break;
    default: LOG(ERROR) << "Unsupported p-code opcode " << inst.function; break;
  }

  return kLiftedInstruction;
}

LiftStatus SleighLifter::LiftBinOp(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr,
                                   llvm::IRBuilder<> &ir, OpCode op) {
  if (inst.operands.size() != 3) {
    LOG(ERROR) << "Unexpected number of operands: " << inst.operands.size();
    inst.operands.clear();
    return kLiftedInvalidInstruction;
  }
  // We want something like `InstructionLifter::LiftOperand` but without the need for an
  // `llvm::Argument` pointer since we're not calling a function in the runtime.
  //
  // TODO(alex): This doesn't handle NULL arguments. Refactor to allow us to use the operand
  // lifting without having an argument.
  llvm::Value *out_val =
      LiftOperand(inst, block, state_ptr, nullptr, inst.operands[0]);
  llvm::Value *lhs_val =
      LiftOperand(inst, block, state_ptr, nullptr, inst.operands[1]);
  llvm::Value *rhs_val =
      LiftOperand(inst, block, state_ptr, nullptr, inst.operands[2]);

  llvm::Value *bin_op_val = nullptr;
  switch (op) {
    case CPUI_INT_LESS: bin_op_val = ir.CreateICmpULT(lhs_val, rhs_val); break;
    case CPUI_INT_SLESS: bin_op_val = ir.CreateICmpULT(lhs_val, rhs_val); break;
    case CPUI_INT_EQUAL: bin_op_val = ir.CreateICmpEQ(lhs_val, rhs_val); break;
    case CPUI_INT_SUB: bin_op_val = ir.CreateSub(lhs_val, rhs_val); break;
    case CPUI_INT_SBORROW: bin_op_val = ir.CreateURem(lhs_val, rhs_val); break;

    case CPUI_INT_AND: bin_op_val = ir.CreateAnd(lhs_val, rhs_val); break;
    default: LOG(ERROR) << "Invalid binary op " << get_opname(op); break;
  }

  // Assign the out variable to the result of the binary operation
  ir.CreateStore(bin_op_val, out_val);
  return kLiftedInstruction;
}

LiftStatus SleighLifter::LiftUnOp(Instruction &inst, llvm::BasicBlock *block,
                                  llvm::Value *state_ptr, llvm::IRBuilder<> &ir,
                                  OpCode op) {
  if (inst.operands.size() != 2) {
    LOG(ERROR) << "Unexpected number of operands";
    inst.operands.clear();
    return kLiftedInvalidInstruction;
  }

  llvm::Value *out_val =
      LiftOperand(inst, block, state_ptr, nullptr, inst.operands[0]);
  llvm::Value *operand =
      LiftOperand(inst, block, state_ptr, nullptr, inst.operands[1]);


  llvm::Value *unop_val = nullptr;
  switch (op) {
    default: LOG(ERROR) << "Invalid unary op " << get_opname(op); break;
  }

  // Assign the out variable to the result of the binary operation
  ir.CreateStore(unop_val, out_val);
  return kLiftedInstruction;
}

void SleighLifter::LiftPopCount(Instruction &inst, llvm::BasicBlock *block,
                                llvm::Value *state_ptr, llvm::IRBuilder<> &ir) {
  // TODO(alex): Call CTPOP LLVM intrinsic
}
}  // namespace remill