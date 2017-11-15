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

#ifndef REMILL_BC_LIFTER_H_
#define REMILL_BC_LIFTER_H_

namespace llvm {
class Argument;
class Function;
class Module;
class GlobalVariable;
class IntegerType;
}  // namespace llvm

namespace remill {

class Instruction;
class IntrinsicTable;
class Operand;

enum LiftStatus {
  kLiftedInvalidInstruction,
  kLiftedUnsupportedInstruction,
  kLiftedInstruction
};

// Wraps the process of lifting an instruction into a block. This resolves
// the intended instruction target to a function, and ensures that the function
// is called with the appropriate arguments.
class InstructionLifter {
 public:
  virtual ~InstructionLifter(void);

  InstructionLifter(llvm::IntegerType *word_type_,
                    const IntrinsicTable *intrinsics_);

  // Lift a single instruction into a basic block.
  virtual LiftStatus LiftIntoBlock(
      Instruction &inst, llvm::BasicBlock *block);

  // Machine word type for this architecture.
  llvm::IntegerType * const word_type;

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;

 protected:
  // Lift an operand to an instruction.
  virtual llvm::Value *LiftOperand(Instruction &inst,
                                   llvm::BasicBlock *block,
                                   llvm::Argument *arg,
                                   Operand &op);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftShiftRegisterOperand(Instruction &inst,
                                                llvm::BasicBlock *block,
                                                llvm::Argument *arg,
                                                Operand &reg);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftRegisterOperand(Instruction &inst,
                                           llvm::BasicBlock *block,
                                           llvm::Argument *arg,
                                           Operand &reg);

  // Lift an immediate operand.
  virtual llvm::Value *LiftImmediateOperand(Instruction &inst,
                                            llvm::BasicBlock *block,
                                            llvm::Argument *arg,
                                            Operand &op);

  // Lift an indirect memory operand to a value.
  virtual llvm::Value *LiftAddressOperand(Instruction &inst,
                                          llvm::BasicBlock *block,
                                          llvm::Argument *arg,
                                          Operand &mem);

 private:
  InstructionLifter(void) = delete;
};

}  // namespace remill

#endif  // REMILL_BC_LIFTER_H_
