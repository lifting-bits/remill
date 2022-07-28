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
#include <remill/Arch/AArch32/AArch32Base.h>
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill {
namespace sleighthumb2 {

//ARM7_le.sla"
class SleighThumb2Arch final : public remill::sleigh::SleighArch,
                               public remill::AArch32ArchBase {
 public:
  SleighThumb2Arch(llvm::LLVMContext *context_, OSName os_name_,
                   ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        SleighArch(context_, os_name_, arch_name_, "ARM7_le.sla",
                   "ARMtTHUMB.pspec"),
        AArch32ArchBase(context_, os_name_, arch_name_) {}


  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const final {
    return 4;
  }

  uint64_t MinInstructionSize(void) const final {
    return 2;
  }

  uint64_t MinInstructionAlign(void) const final {
    return 2;
  }

  void InitializeSleighContext(
      remill::sleigh::SingleInstructionSleighContext &ctxt) const final {
    ctxt.GetContext().setVariableDefault("TMode", 1);
  }

  llvm::Triple Triple(void) const final {
    auto triple = BasicTriple();
    triple.setArch(llvm::Triple::thumb);
    triple.setOS(llvm::Triple::OSType::Linux);
    triple.setVendor(llvm::Triple::VendorType::UnknownVendor);
    return triple;
  }
};
}  // namespace sleighthumb2
Arch::ArchPtr Arch::GetSleighThumb2(llvm::LLVMContext *context_,
                                    OSName os_name_, ArchName arch_name_) {
  return std::make_unique<sleighthumb2::SleighThumb2Arch>(context_, os_name_,
                                                          arch_name_);
}

//     this->sleigh_ctx.GetEngine().setContextDefault("TMode", 1);

}  // namespace remill
