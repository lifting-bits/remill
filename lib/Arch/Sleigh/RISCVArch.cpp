/*
 * Copyright (c) 2026-present Trail of Bits, Inc.
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

#include "Arch.h"

#include <glog/logging.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <string>
#include <tuple>
#include <utility>

#define INCLUDED_FROM_REMILL
#include <remill/Arch/RISCV/Runtime/State.h>

namespace remill {
namespace sleighriscv {

class SleighRISCVDecoder : public sleigh::SleighDecoder {
 public:
  SleighRISCVDecoder(const remill::Arch &arch, std::string sla_name,
                     std::string pspec_name)
      : SleighDecoder(
            arch, std::move(sla_name), std::move(pspec_name),
            sleigh::ContextRegMappings({}, {}),
            {
                // Some Sleigh specs use ABI alias names (zero/ra/sp/...) instead
                // of x0/x1/x2/... or f0/f1/...; we remap those to canonical
                // X* / F* names.
                {"ZERO", "X0"},
                {"RA", "X1"},
                {"SP", "X2"},
                {"GP", "X3"},
                {"TP", "X4"},
                {"T0", "X5"},
                {"T1", "X6"},
                {"T2", "X7"},
                {"S0", "X8"},
                {"FP", "X8"},
                {"S1", "X9"},
                {"A0", "X10"},
                {"A1", "X11"},
                {"A2", "X12"},
                {"A3", "X13"},
                {"A4", "X14"},
                {"A5", "X15"},
                {"A6", "X16"},
                {"A7", "X17"},
                {"S2", "X18"},
                {"S3", "X19"},
                {"S4", "X20"},
                {"S5", "X21"},
                {"S6", "X22"},
                {"S7", "X23"},
                {"S8", "X24"},
                {"S9", "X25"},
                {"S10", "X26"},
                {"S11", "X27"},
                {"T3", "X28"},
                {"T4", "X29"},
                {"T5", "X30"},
                {"T6", "X31"},

                // Floating-point ABI aliases.
                {"FT0", "F0"},
                {"FT1", "F1"},
                {"FT2", "F2"},
                {"FT3", "F3"},
                {"FT4", "F4"},
                {"FT5", "F5"},
                {"FT6", "F6"},
                {"FT7", "F7"},
                {"FS0", "F8"},
                {"FS1", "F9"},
                {"FA0", "F10"},
                {"FA1", "F11"},
                {"FA2", "F12"},
                {"FA3", "F13"},
                {"FA4", "F14"},
                {"FA5", "F15"},
                {"FA6", "F16"},
                {"FA7", "F17"},
                {"FS2", "F18"},
                {"FS3", "F19"},
                {"FS4", "F20"},
                {"FS5", "F21"},
                {"FS6", "F22"},
                {"FS7", "F23"},
                {"FS8", "F24"},
                {"FS9", "F25"},
                {"FS10", "F26"},
                {"FS11", "F27"},
                {"FT8", "F28"},
                {"FT9", "F29"},
                {"FT10", "F30"},
                {"FT11", "F31"},
            }) {}

  void InitializeSleighContext(uint64_t,
                               sleigh::SingleInstructionSleighContext &,
                               const ContextValues &) const override {}

  llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *curr_pc,
                                size_t curr_insn_size,
                                const DecodingContext &) const override {
    return bldr.CreateAdd(
        curr_pc, llvm::ConstantInt::get(curr_pc->getType(), curr_insn_size));
  }
};

class SleighRISCVArch : public ArchBase {
 public:
  SleighRISCVArch(llvm::LLVMContext *context_, OSName os_name_,
                  ArchName arch_name_, std::string sla_name,
                  std::string pspec_name)
      : ArchBase(context_, os_name_, arch_name_),
        decoder(*this, std::move(sla_name), std::move(pspec_name)) {}

  DecodingContext CreateInitialContext(void) const override {
    return DecodingContext();
  }

  std::string_view StackPointerRegisterName(void) const override {
    return "X2";
  }

  std::string_view ProgramCounterRegisterName(void) const override {
    return "PC";
  }

  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override {
    return decoder.GetOpLifter();
  }

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const override {
    bool ok = decoder.DecodeInstruction(address, instr_bytes, inst, context);
    if (!ok) {
      return false;
    }

    // Sleigh models ebreak/ecall with CALLOTHER pcode ops, which the
    // generic control-flow analysis cannot classify.  Override here.
    const auto &fn = inst.function;
    if (fn == "ebreak" || fn == "c.ebreak") {
      inst.category = Instruction::Category::kCategoryError;
      inst.flows = Instruction::ErrorInsn();
    } else if (fn == "ecall") {
      inst.category = Instruction::Category::kCategoryAsyncHyperCall;
      inst.flows = Instruction::AsyncHyperCall();
    }

    return true;
  }

  uint64_t MinInstructionAlign(const DecodingContext &) const override {
    return 2;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const override {
    return 2;
  }

  uint64_t MaxInstructionSize(const DecodingContext &, bool) const override {
    return 4;
  }

  llvm::CallingConv::ID DefaultCallingConv(void) const override {
    return llvm::CallingConv::C;
  }

  llvm::Triple Triple(void) const override {
    auto triple = BasicTriple();
    switch (arch_name) {
      case kArchRISCV32: triple.setArch(llvm::Triple::riscv32); break;
      case kArchRISCV64: triple.setArch(llvm::Triple::riscv64); break;
      default:
        LOG(FATAL) << "Cannot get triple for non-RISC-V architecture "
                   << GetArchName(arch_name);
        break;
    }
    return triple;
  }

  llvm::DataLayout DataLayout(void) const override {
    switch (arch_name) {
      case kArchRISCV32:
        return llvm::DataLayout("e-m:e-p:32:32-i64:64-n32-S128");
      case kArchRISCV64:
        return llvm::DataLayout("e-m:e-p:64:64-i64:64-i128:128-n32:64-S128");
      default:
        LOG(FATAL) << "Cannot get data layout for non-RISC-V architecture "
                   << GetArchName(arch_name);
        return llvm::DataLayout("");
    }
  }

  void PopulateRegisterTable(void) const override {
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(RISCVState));

    auto u8 = llvm::Type::getInt8Ty(*context);
    auto u32 = llvm::Type::getInt32Ty(*context);
    auto u64 = llvm::Type::getInt64Ty(*context);
    auto f64 = llvm::Type::getDoubleTy(*context);

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

    RISCVState state;

    if (arch_name == kArchRISCV32) {
      REG(state, X0, gpr.x0.dword, u32);
      REG(state, X1, gpr.x1.dword, u32);
      REG(state, X2, gpr.x2.dword, u32);
      REG(state, X3, gpr.x3.dword, u32);
      REG(state, X4, gpr.x4.dword, u32);
      REG(state, X5, gpr.x5.dword, u32);
      REG(state, X6, gpr.x6.dword, u32);
      REG(state, X7, gpr.x7.dword, u32);
      REG(state, X8, gpr.x8.dword, u32);
      REG(state, X9, gpr.x9.dword, u32);
      REG(state, X10, gpr.x10.dword, u32);
      REG(state, X11, gpr.x11.dword, u32);
      REG(state, X12, gpr.x12.dword, u32);
      REG(state, X13, gpr.x13.dword, u32);
      REG(state, X14, gpr.x14.dword, u32);
      REG(state, X15, gpr.x15.dword, u32);
      REG(state, X16, gpr.x16.dword, u32);
      REG(state, X17, gpr.x17.dword, u32);
      REG(state, X18, gpr.x18.dword, u32);
      REG(state, X19, gpr.x19.dword, u32);
      REG(state, X20, gpr.x20.dword, u32);
      REG(state, X21, gpr.x21.dword, u32);
      REG(state, X22, gpr.x22.dword, u32);
      REG(state, X23, gpr.x23.dword, u32);
      REG(state, X24, gpr.x24.dword, u32);
      REG(state, X25, gpr.x25.dword, u32);
      REG(state, X26, gpr.x26.dword, u32);
      REG(state, X27, gpr.x27.dword, u32);
      REG(state, X28, gpr.x28.dword, u32);
      REG(state, X29, gpr.x29.dword, u32);
      REG(state, X30, gpr.x30.dword, u32);
      REG(state, X31, gpr.x31.dword, u32);

      // Note: the state stores PC as a `Reg`, but its externally visible size
      // is XLEN-dependent.
      REG(state, PC, pc.dword, u32);

    } else {
      REG(state, X0, gpr.x0.qword, u64);
      REG(state, X1, gpr.x1.qword, u64);
      REG(state, X2, gpr.x2.qword, u64);
      REG(state, X3, gpr.x3.qword, u64);
      REG(state, X4, gpr.x4.qword, u64);
      REG(state, X5, gpr.x5.qword, u64);
      REG(state, X6, gpr.x6.qword, u64);
      REG(state, X7, gpr.x7.qword, u64);
      REG(state, X8, gpr.x8.qword, u64);
      REG(state, X9, gpr.x9.qword, u64);
      REG(state, X10, gpr.x10.qword, u64);
      REG(state, X11, gpr.x11.qword, u64);
      REG(state, X12, gpr.x12.qword, u64);
      REG(state, X13, gpr.x13.qword, u64);
      REG(state, X14, gpr.x14.qword, u64);
      REG(state, X15, gpr.x15.qword, u64);
      REG(state, X16, gpr.x16.qword, u64);
      REG(state, X17, gpr.x17.qword, u64);
      REG(state, X18, gpr.x18.qword, u64);
      REG(state, X19, gpr.x19.qword, u64);
      REG(state, X20, gpr.x20.qword, u64);
      REG(state, X21, gpr.x21.qword, u64);
      REG(state, X22, gpr.x22.qword, u64);
      REG(state, X23, gpr.x23.qword, u64);
      REG(state, X24, gpr.x24.qword, u64);
      REG(state, X25, gpr.x25.qword, u64);
      REG(state, X26, gpr.x26.qword, u64);
      REG(state, X27, gpr.x27.qword, u64);
      REG(state, X28, gpr.x28.qword, u64);
      REG(state, X29, gpr.x29.qword, u64);
      REG(state, X30, gpr.x30.qword, u64);
      REG(state, X31, gpr.x31.qword, u64);
      REG(state, PC, pc.qword, u64);
    }

    // Floating-point register file. GC implies D, so treat these as 64-bit.
    REG(state, F0, fpr.f0.qword, f64);
    REG(state, F1, fpr.f1.qword, f64);
    REG(state, F2, fpr.f2.qword, f64);
    REG(state, F3, fpr.f3.qword, f64);
    REG(state, F4, fpr.f4.qword, f64);
    REG(state, F5, fpr.f5.qword, f64);
    REG(state, F6, fpr.f6.qword, f64);
    REG(state, F7, fpr.f7.qword, f64);
    REG(state, F8, fpr.f8.qword, f64);
    REG(state, F9, fpr.f9.qword, f64);
    REG(state, F10, fpr.f10.qword, f64);
    REG(state, F11, fpr.f11.qword, f64);
    REG(state, F12, fpr.f12.qword, f64);
    REG(state, F13, fpr.f13.qword, f64);
    REG(state, F14, fpr.f14.qword, f64);
    REG(state, F15, fpr.f15.qword, f64);
    REG(state, F16, fpr.f16.qword, f64);
    REG(state, F17, fpr.f17.qword, f64);
    REG(state, F18, fpr.f18.qword, f64);
    REG(state, F19, fpr.f19.qword, f64);
    REG(state, F20, fpr.f20.qword, f64);
    REG(state, F21, fpr.f21.qword, f64);
    REG(state, F22, fpr.f22.qword, f64);
    REG(state, F23, fpr.f23.qword, f64);
    REG(state, F24, fpr.f24.qword, f64);
    REG(state, F25, fpr.f25.qword, f64);
    REG(state, F26, fpr.f26.qword, f64);
    REG(state, F27, fpr.f27.qword, f64);
    REG(state, F28, fpr.f28.qword, f64);
    REG(state, F29, fpr.f29.qword, f64);
    REG(state, F30, fpr.f30.qword, f64);
    REG(state, F31, fpr.f31.qword, f64);

    REG(state, FCSR, fcsr.fcsr, u32);
    REG(state, FRM, fcsr.frm, u8);
    REG(state, FFLAGS, fcsr.fflags, u8);

    // Reservation state used by LR/SC (A extension).
    if (arch_name == kArchRISCV32) {
      REG(state, RESERVE_ADDRESS, reserve_address.dword, u32);
    } else {
      REG(state, RESERVE_ADDRESS, reserve_address.qword, u64);
    }
    REG(state, RESERVE, reserve, u8);
    REG(state, RESERVE_LENGTH, reserve_length, u8);

#undef REG
#undef OFFSET_OF
  }

  void FinishLiftedFunctionInitialization(llvm::Module *module,
                                         llvm::Function *bb_func) const override {
    auto &context = module->getContext();
    const auto addr = llvm::Type::getIntNTy(context, address_size);

    auto &entry_block = bb_func->getEntryBlock();
    llvm::IRBuilder<> ir(&entry_block);

    const auto pc_arg = NthArgument(bb_func, kPCArgNum);
    const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

    auto mk_alloca = [&](auto &from) {
      return ir.CreateAlloca(addr, nullptr, from.data());
    };

    ir.CreateStore(pc_arg, mk_alloca(kNextPCVariableName));
    ir.CreateStore(pc_arg, mk_alloca(kIgnoreNextPCVariableName));

    std::ignore = RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir);
  }

 private:
  SleighRISCVDecoder decoder;
};

}  // namespace sleighriscv

Arch::ArchPtr Arch::GetSleighRISCV32(llvm::LLVMContext *context_,
                                     remill::OSName os_name_,
                                     remill::ArchName arch_name_) {
  return std::make_unique<sleighriscv::SleighRISCVArch>(
      context_, os_name_, arch_name_,
      /*sla_name=*/"riscv.ilp32d.sla",
      /*pspec_name=*/"RV32GC.pspec");
}

Arch::ArchPtr Arch::GetSleighRISCV64(llvm::LLVMContext *context_,
                                     remill::OSName os_name_,
                                     remill::ArchName arch_name_) {
  return std::make_unique<sleighriscv::SleighRISCVArch>(
      context_, os_name_, arch_name_,
      /*sla_name=*/"riscv.lp64d.sla",
      /*pspec_name=*/"RV64GC.pspec");
}

}  // namespace remill
