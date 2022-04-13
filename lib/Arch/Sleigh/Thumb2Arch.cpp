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
#include <remill/Arch/AArch32/Runtime/State.h>

#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Compat/Attributes.h>
#include <remill/BC/Compat/DebugInfo.h>
#include <remill/BC/Compat/GlobalValue.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill {
namespace sleighthumb2 {

//ARM7_le.sla"
class SleighThumb2Arch final : public remill::sleigh::SleighArch {
 public:
  SleighThumb2Arch(llvm::LLVMContext *context_, OSName os_name_,
                   ArchName arch_name_)
      : SleighArch(context_, os_name_, arch_name_, "ARM7_le.sla") {}


  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const final {
    return 4;
  }

  uint64_t MinInstructionSize(void) const final {
    return 2;
  }

  uint64_t MinInstructionAlign(void) const final {
    return 2;
  }

  // TODO(Ian): take from sleigh, we can probably do this at the SLEIGH arch level to DRY.
  std::string_view StackPointerRegisterName(void) const final {
    return "SP";
  }

  // TODO(Ian): take from sleigh
  std::string_view ProgramCounterRegisterName(void) const final {
    return "PC";
  }

  // TODO(Ian): take from sleigh
  llvm::CallingConv::ID DefaultCallingConv(void) const final {
    return llvm::CallingConv::C;
  }


  llvm::Triple Triple(void) const final {
    auto triple = BasicTriple();
    triple.setArch(llvm::Triple::thumb);
    triple.setOS(llvm::Triple::OSType::Linux);
    triple.setVendor(llvm::Triple::VendorType::UnknownVendor);
    return triple;
  }

  // NOTE(Ian): Copied from Arch32/Arch.cpp
  llvm::DataLayout DataLayout(void) const final {
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

  void PopulateRegisterTable(void) const final {
    // TODO(Ian): uh yeah do something here
    // Populate the table of register information.
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(AArch32State));

    auto u8 = llvm::Type::getInt8Ty(*context);

    auto u32 = llvm::Type::getInt32Ty(*context);

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(AArch32State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(AArch32State, access), #parent_reg_name)

    REG(R0, gpr.r0.dword, u32);
    REG(R1, gpr.r1.dword, u32);
    REG(R2, gpr.r2.dword, u32);
    REG(R3, gpr.r3.dword, u32);
    REG(R4, gpr.r4.dword, u32);
    REG(R5, gpr.r5.dword, u32);
    REG(R6, gpr.r6.dword, u32);
    REG(R7, gpr.r7.dword, u32);
    REG(R8, gpr.r8.dword, u32);
    REG(R9, gpr.r9.dword, u32);
    REG(R10, gpr.r10.dword, u32);
    REG(R11, gpr.r11.dword, u32);
    REG(R12, gpr.r12.dword, u32);
    REG(R13, gpr.r13.dword, u32);
    REG(R14, gpr.r14.dword, u32);
    REG(R15, gpr.r15.dword, u32);

    SUB_REG(SP, gpr.r13.dword, u32, R13);
    SUB_REG(LR, gpr.r14.dword, u32, R14);
    SUB_REG(PC, gpr.r15.dword, u32, R15);

    REG(N, sr.n, u8);
    REG(C, sr.c, u8);
    REG(Z, sr.z, u8);
    REG(V, sr.v, u8);
  }

  // Populate a just-initialized lifted function function with architecture-
  // specific variables. TODO(Ian)
  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const final {
    const auto &dl = module->getDataLayout();
    CHECK_EQ(sizeof(State), dl.getTypeAllocSize(StateStructType()))
        << "Mismatch between size of State type for thumb and what is in "
        << "the bitcode module";

    auto &context = module->getContext();
    auto addr = llvm::Type::getIntNTy(context, address_size);

    const auto entry_block = &bb_func->getEntryBlock();
    llvm::IRBuilder<> ir(entry_block);

    const auto pc_arg = NthArgument(bb_func, kPCArgNum);
    const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

    ir.CreateStore(pc_arg, ir.CreateAlloca(addr, nullptr, "NEXT_PC"));


    (void) this->RegisterByName("PC")->AddressOf(state_ptr_arg, ir);
  }

  void InitializeSleighContext(
      remill::sleigh::SingleInstructionSleighContext &ctxt) const final {
    ctxt.GetEngine().setContextDefault("TMode", 1);
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
