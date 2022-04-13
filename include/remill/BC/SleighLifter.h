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

#include <sleigh/libsleigh.hh>

#include "remill/Arch/Instruction.h"
#include "remill/BC/InstructionLifter.h"
#include <mutex>

class Sleigh;

namespace remill {
namespace sleigh {
class SleighArch;
class SingleInstructionSleighContext;
}  // namespace sleigh

class SleighLifter : public InstructionLifter {
  class PcodeToLLVMEmitIntoBlock;

  std::unique_ptr<sleigh::SingleInstructionSleighContext> sleigh_context;

 public:
  SleighLifter(const sleigh::SleighArch *arch_,
               const IntrinsicTable &intrinsics_);

  virtual ~SleighLifter(void) = default;

  LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                           llvm::Value *state_ptr, bool is_delayed) override;

 private:
  ::Sleigh &GetEngine(void) const;
};

}  // namespace remill
