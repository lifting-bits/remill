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

#include "Arch.h"
#include "PPC.h"

#define INCLUDED_FROM_REMILL
#include <remill/Arch/PPC/Runtime/State.h>

namespace remill {

namespace sleighppc {

static constexpr auto kPPCVLERegName = "VLEReg";

SleighPPCDecoder::SleighPPCDecoder(const remill::Arch &arch)
    : SleighDecoder(
          arch, "ppc_32_e200_be.sla", "ppc_32.pspec",
          sleigh::ContextRegMappings({{"vle", kPPCVLERegName}}, {{"vle", 1}}),
          {}) {}

llvm::Value *SleighPPCDecoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                                llvm::Value *curr_pc,
                                                size_t curr_insn_size,
                                                const DecodingContext &) const {
  // PC on thumb points to the next instructions next.
  return bldr.CreateAdd(
      curr_pc, llvm::ConstantInt::get(curr_pc->getType(), curr_insn_size));
}

void SleighPPCDecoder::InitializeSleighContext(
    uint64_t addr, remill::sleigh::SingleInstructionSleighContext &ctxt,
    const ContextValues &context_values) const {
  // If the context value mappings specify a value for the VLE register, let's pass that into
  // Sleigh.
  //
  // Otherwise, default to VLE off.
  sleigh::SetContextRegisterValueInSleigh(addr, kPPCVLERegName, "vle", 0, ctxt,
                                          context_values);
}

class SleighPPCArch : public ArchBase {
 public:
  SleighPPCArch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        decoder(*this) {}
  virtual ~SleighPPCArch() = default;

  DecodingContext CreateInitialContext(void) const override {
    return DecodingContext().PutContextReg(kPPCVLERegName, 0);
  }

  std::string_view StackPointerRegisterName(void) const override {
    return "R1";
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
    return decoder.DecodeInstruction(address, instr_bytes, inst, context);
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
    triple.setArch(llvm::Triple::ppc);
    return triple;
  }

  llvm::DataLayout DataLayout(void) const override {
    return llvm::DataLayout("e-m:e-p:32:32-i32:32-i64:64-f64:64-n32:64-S128");
  }

  void PopulateRegisterTable(void) const override {
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(PPCState));

    auto u8 = llvm::Type::getInt8Ty(*context);
    auto u32 = llvm::Type::getInt32Ty(*context);
    auto u64 = llvm::Type::getInt64Ty(*context);

    auto f64 = llvm::Type::getDoubleTy(*context);

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(PPCState, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(PPCState, access), #parent_reg_name)

    REG(R0, gpr.r0.qword, u64);
    REG(R1, gpr.r1.qword, u64);
    REG(R2, gpr.r2.qword, u64);
    REG(R3, gpr.r3.qword, u64);
    REG(R4, gpr.r4.qword, u64);
    REG(R5, gpr.r5.qword, u64);
    REG(R6, gpr.r6.qword, u64);
    REG(R7, gpr.r7.qword, u64);
    REG(R8, gpr.r8.qword, u64);
    REG(R9, gpr.r9.qword, u64);
    REG(R10, gpr.r10.qword, u64);
    REG(R11, gpr.r11.qword, u64);
    REG(R12, gpr.r12.qword, u64);
    REG(R13, gpr.r13.qword, u64);
    REG(R14, gpr.r14.qword, u64);
    REG(R15, gpr.r15.qword, u64);
    REG(R16, gpr.r16.qword, u64);
    REG(R17, gpr.r17.qword, u64);
    REG(R18, gpr.r18.qword, u64);
    REG(R19, gpr.r19.qword, u64);
    REG(R20, gpr.r20.qword, u64);
    REG(R21, gpr.r21.qword, u64);
    REG(R22, gpr.r22.qword, u64);
    REG(R23, gpr.r23.qword, u64);
    REG(R24, gpr.r24.qword, u64);
    REG(R25, gpr.r25.qword, u64);
    REG(R26, gpr.r26.qword, u64);
    REG(R27, gpr.r27.qword, u64);
    REG(R28, gpr.r28.qword, u64);
    REG(R29, gpr.r29.qword, u64);
    REG(R30, gpr.r30.qword, u64);
    REG(R31, gpr.r31.qword, u64);


    // Subregs
    SUB_REG(_R0, gpr.r0.dword, u32, R0);
    SUB_REG(_R1, gpr.r1.dword, u32, R1);
    SUB_REG(_R2, gpr.r2.dword, u32, R2);
    SUB_REG(_R3, gpr.r3.dword, u32, R3);
    SUB_REG(_R4, gpr.r4.dword, u32, R4);
    SUB_REG(_R5, gpr.r5.dword, u32, R5);
    SUB_REG(_R6, gpr.r6.dword, u32, R6);
    SUB_REG(_R7, gpr.r7.dword, u32, R7);
    SUB_REG(_R8, gpr.r8.dword, u32, R8);
    SUB_REG(_R9, gpr.r9.dword, u32, R9);
    SUB_REG(_R10, gpr.r10.dword, u32, R10);
    SUB_REG(_R11, gpr.r11.dword, u32, R11);
    SUB_REG(_R12, gpr.r12.dword, u32, R12);
    SUB_REG(_R13, gpr.r13.dword, u32, R13);
    SUB_REG(_R14, gpr.r14.dword, u32, R14);
    SUB_REG(_R15, gpr.r15.dword, u32, R15);
    SUB_REG(_R16, gpr.r16.dword, u32, R16);
    SUB_REG(_R17, gpr.r17.dword, u32, R17);
    SUB_REG(_R18, gpr.r18.dword, u32, R18);
    SUB_REG(_R19, gpr.r19.dword, u32, R19);
    SUB_REG(_R20, gpr.r20.dword, u32, R20);
    SUB_REG(_R21, gpr.r21.dword, u32, R21);
    SUB_REG(_R22, gpr.r22.dword, u32, R22);
    SUB_REG(_R23, gpr.r23.dword, u32, R23);
    SUB_REG(_R24, gpr.r24.dword, u32, R24);
    SUB_REG(_R25, gpr.r25.dword, u32, R25);
    SUB_REG(_R26, gpr.r26.dword, u32, R26);
    SUB_REG(_R27, gpr.r27.dword, u32, R27);
    SUB_REG(_R28, gpr.r28.dword, u32, R28);
    SUB_REG(_R29, gpr.r29.dword, u32, R29);
    SUB_REG(_R30, gpr.r30.dword, u32, R30);
    SUB_REG(_R31, gpr.r31.dword, u32, R31);

    REG(F0, fpr.f0.qword, f64);
    REG(F1, fpr.f1.qword, f64);
    REG(F2, fpr.f2.qword, f64);
    REG(F3, fpr.f3.qword, f64);
    REG(F4, fpr.f4.qword, f64);
    REG(F5, fpr.f5.qword, f64);
    REG(F6, fpr.f6.qword, f64);
    REG(F7, fpr.f7.qword, f64);
    REG(F8, fpr.f8.qword, f64);
    REG(F9, fpr.f9.qword, f64);
    REG(F10, fpr.f10.qword, f64);
    REG(F11, fpr.f11.qword, f64);
    REG(F12, fpr.f12.qword, f64);
    REG(F13, fpr.f13.qword, f64);
    REG(F14, fpr.f14.qword, f64);
    REG(F15, fpr.f15.qword, f64);
    REG(F16, fpr.f16.qword, f64);
    REG(F17, fpr.f17.qword, f64);
    REG(F18, fpr.f18.qword, f64);
    REG(F19, fpr.f19.qword, f64);
    REG(F20, fpr.f20.qword, f64);
    REG(F21, fpr.f21.qword, f64);
    REG(F22, fpr.f22.qword, f64);
    REG(F23, fpr.f23.qword, f64);
    REG(F24, fpr.f24.qword, f64);
    REG(F25, fpr.f25.qword, f64);
    REG(F26, fpr.f26.qword, f64);
    REG(F27, fpr.f27.qword, f64);
    REG(F28, fpr.f28.qword, f64);
    REG(F29, fpr.f29.qword, f64);
    REG(F30, fpr.f30.qword, f64);

    REG(CRALL, iar.cr.qword, u64);
    REG(CTR, iar.ctr.qword, u64);
    REG(LR, iar.lr.qword, u64);
    REG(XER, iar.xer.dword, u32);
    REG(SPEFCR, iar.spefscr.qword, u64);
    REG(ACC, iar.acc.qword, u64);

    // These are actually bitflags within XER and CR respectively. These would
    // normally be subregisters however, Sleigh treats these as entirely
    // separate registers of size 1.
    REG(XER_SO, xer_flags.so, u8);
    REG(XER_OV, xer_flags.ov, u8);
    REG(XER_CA, xer_flags.ca, u8);
    REG(XER_COUNT, xer_flags.sl, u8);

    REG(CR0, cr_flags.cr0, u8);
    REG(CR1, cr_flags.cr1, u8);
    REG(CR2, cr_flags.cr2, u8);
    REG(CR3, cr_flags.cr3, u8);
    REG(CR4, cr_flags.cr4, u8);
    REG(CR5, cr_flags.cr5, u8);
    REG(CR6, cr_flags.cr6, u8);
    REG(CR7, cr_flags.cr7, u8);

    REG(TBLR, tbr.tbl.qword, u64);
    REG(TBUR, tbr.tbu.qword, u64);

    REG(SPR103, sprg.r3.qword, u64);
    REG(SPR104, sprg.r4.qword, u64);
    REG(SPR105, sprg.r5.qword, u64);
    REG(SPR106, sprg.r6.qword, u64);
    REG(SPR107, sprg.r7.qword, u64);

    REG(SPR203, l1cfg.r0.qword, u64);
    REG(SPR204, l1cfg.r1.qword, u64);

    REG(PC, pc, u64);

    REG(TEA, signals.tea.qword, u64);
  }

  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override {
    auto &context = module->getContext();
    const auto addr = llvm::Type::getInt64Ty(context);

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
  SleighPPCDecoder decoder;
};

}  // namespace sleighppc

Arch::ArchPtr Arch::GetSleighPPC(llvm::LLVMContext *context_,
                                 remill::OSName os_name_,
                                 remill::ArchName arch_name_) {
  return std::make_unique<sleighppc::SleighPPCArch>(context_, os_name_,
                                                    arch_name_);
}

}  // namespace remill
