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

#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/X86/X86Base.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill {
namespace sleigh::x86 {

class SleighX86Arch final : public SleighArch, public remill::X86ArchBase {
 public:
  SleighX86Arch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        SleighArch(
            context_, os_name_, arch_name_,
            kArchX86_SLEIGH == arch_name_ ? "x86.sla" : "x86-64.sla",
            kArchX86_SLEIGH == arch_name_ ? "x86.pspec" : "x86-64.pspec"),
        X86ArchBase(context_, os_name_, arch_name_) {}

  virtual ~SleighX86Arch(void) = default;

  void InitializeSleighContext(
      remill::sleigh::SingleInstructionSleighContext &ctxt) const override {}
};
}  // namespace sleigh::x86
Arch::ArchPtr Arch::GetSleighX86(llvm::LLVMContext *context_, OSName os_name_,
                                 ArchName arch_name_) {
  return std::make_unique<sleigh::x86::SleighX86Arch>(context_, os_name_,
                                                      arch_name_);
}
}  // namespace remill
