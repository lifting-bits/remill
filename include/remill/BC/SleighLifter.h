/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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

#include <mutex>
#include <sleigh/libsleigh.hh>

#include "remill/Arch/Instruction.h"
#include "remill/BC/InstructionLifter.h"


using namespace ghidra;

namespace remill {
namespace sleigh {
// If you lift a varnode before the given pcode index, then you have a branch taken metavar
struct BranchTakenVar {
  bool invert;
  VarnodeData target_vnode;
  size_t index;
};
using MaybeBranchTakenVar = std::optional<BranchTakenVar>;

class SleighDecoder;
class SingleInstructionSleighContext;
}  // namespace sleigh


class SleighLifter : public InstructionLifter {
 private:
  class PcodeToLLVMEmitIntoBlock;

  std::unique_ptr<sleigh::SingleInstructionSleighContext> sleigh_context;
  // Architecture being used for lifting.
  // Decoder being used for disassembly

  const sleigh::SleighDecoder &decoder;

 public:
  static const std::string_view kInstructionFunctionPrefix;

  SleighLifter(const remill::Arch &arch_,
               const remill::sleigh::SleighDecoder &dec_,
               const IntrinsicTable &intrinsics_);

  virtual ~SleighLifter(void) = default;

  LiftStatus
  LiftIntoBlockWithSleighState(Instruction &inst, llvm::BasicBlock *block,
                               llvm::Value *state_ptr, bool is_delayed,
                               const sleigh::MaybeBranchTakenVar &btaken,
                               const ContextValues &context_values);

 private:
  static void SetISelAttributes(llvm::Function *);


  llvm::Function *DefineInstructionFunction(Instruction &inst,
                                            llvm::Module *target_mod);

  std::pair<LiftStatus, std::optional<llvm::Function *>>
  LiftIntoInternalBlockWithSleighState(
      Instruction &inst, llvm::Module *target_mod, bool is_delayed,
      const sleigh::MaybeBranchTakenVar &btaken,
      const ContextValues &context_values);

  ::Sleigh &GetEngine(void) const;
  const remill::Arch &arch;
};


// lets us attach state to a lifter that we need to carry on from when we decoded the instruction
class SleighLifterWithState final : public InstructionLifterIntf {
 private:
  sleigh::MaybeBranchTakenVar btaken;
  ContextValues context_values;
  std::shared_ptr<SleighLifter> lifter;

 public:
  SleighLifterWithState(sleigh::MaybeBranchTakenVar btaken,
                        ContextValues context_values,
                        std::shared_ptr<SleighLifter> lifter_);

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  virtual LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr,
                                   bool is_delayed = false) override;


  // Load the address of a register.
  virtual std::pair<llvm::Value *, llvm::Type *>
  LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                 std::string_view reg_name) const override;

  // Load the value of a register.
  virtual llvm::Value *LoadRegValue(llvm::BasicBlock *block,
                                    llvm::Value *state_ptr,
                                    std::string_view reg_name) const override;

  virtual llvm::Type *GetMemoryType() override;

  virtual void ClearCache(void) const override;

  const ContextValues &GetContextValues() const {
    return context_values;
  }
};

}  // namespace remill
