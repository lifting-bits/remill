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

#include "../Arch.h"
#include "SleighArch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace sleighthumb2 {

//ARM7_le.sla"
class SleighThumb2Arch final : public remill::sleigh::SleighArch {
 public:
  SleighThumb2Arch(llvm::LLVMContext *context_, OSName os_name_,
                   ArchName arch_name_)
      : SleighArch(context_, os_name_, arch_name_, "ARM7_le.sla") {}


  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const override {
    return 4;
  }

  uint64_t MinInstructionSize(void) const override {
    return 2;
  }

  uint64_t MinInstructionAlign(void) const override {
    return 2;
  }

  // TODO(Ian): take from sleigh, we can probably do this at the SLEIGH arch level to DRY.
  std::string_view StackPointerRegisterName(void) const override {
    return "SP";
  }

  // TODO(Ian): take from sleigh
  std::string_view ProgramCounterRegisterName(void) const override {
    return "PC";
  }

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst) const override {
    return false;
  }

  // TODO(Ian): take from sleigh
  llvm::CallingConv::ID DefaultCallingConv(void) const override {
    return llvm::CallingConv::C;
  }


  llvm::Triple Triple(void) const override {
    auto triple = BasicTriple();
    triple.setArch(llvm::Triple::thumb);
    triple.setOS(llvm::Triple::OSType::Linux);
    triple.setVendor(llvm::Triple::VendorType::UnknownVendor);
    return triple;
  }

  // NOTE(Ian): Copied from Arch32/Arch.cpp
  llvm::DataLayout DataLayout(void) const override {
    std::string dl;
    switch (os_name) {
      case kOSInvalid:
        LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
        break;

      case kOSLinux:
      case kOSSolaris:
      case kOSmacOS:
      case kOSWindows:
        dl = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64";
        break;
    }

    return llvm::DataLayout(dl);
  }


  void PopulateRegisterTable(void) const override {
    // TODO(Ian): uh yeah do something here
    assert(false);
  }

  // Populate a just-initialized lifted function function with architecture-
  // specific variables. TODO(Ian)
  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override {
    assert(false);
  }
};

}  // namespace sleighthumb2
Arch::ArchPtr Arch::GetSleighThumb2(llvm::LLVMContext *context_,
                                    OSName os_name_, ArchName arch_name_) {
  return std::make_unique<sleighthumb2::SleighThumb2Arch>(context_, os_name_,
                                                          arch_name_);
}


}  // namespace remill
