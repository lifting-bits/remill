/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
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

#pragma once

#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>

#include <sleigh/libsleigh.hh>

#include "remill/Arch/Instruction.h"
#include "remill/BC/InstructionLifter.h"


namespace remill {

class SleighLifter : public InstructionLifter {
 public:
  inline SleighLifter(const std::unique_ptr<const Arch> &arch_,
                      const IntrinsicTable &intrinsics_)
      : InstructionLifter(arch_, intrinsics_) {}

  virtual ~SleighLifter(void) = default;

  LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                           llvm::Value *state_ptr, bool is_delayed) override {
    if (!inst.IsValid()) {
      LOG(ERROR) << "Invalid function" << inst.Serialize();
      return kLiftedInvalidInstruction;
    }

    llvm::IRBuilder<> ir(block);

    const OpCode op = get_opcode(inst.function);
    switch (op) {
      case CPUI_INT_LESS: LiftIntLess(inst, block, state_ptr, ir); break;
      case CPUI_INT_SLESS:
      case CPUI_INT_EQUAL:
      case CPUI_INT_SUB:
      case CPUI_INT_SBORROW:
      case CPUI_INT_AND:
      case CPUI_POPCOUNT: break;
      default:
        LOG(ERROR) << "Unsupported p-code opcode " << inst.function;
        break;
    }

    return kLiftedInstruction;
  }

  void LiftIntLess(Instruction &inst, llvm::BasicBlock *block,
                   llvm::Value *state_ptr, llvm::IRBuilder<> &ir) {
    if (inst.operands.size() != 3) {
      LOG(ERROR) << "Unexpected number of operands";
      return;
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

    llvm::Value *lt_val = ir.CreateICmpULT(lhs_val, rhs_val);
    ir.CreateStore(lt_val, out_val);
  }
};

}  // namespace remill
