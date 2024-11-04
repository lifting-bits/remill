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
    return llvm::DataLayout("E-m:e-p:32:32-Fn32-i64:64-n32");
  }

  void PopulateRegisterTable(void) const override {
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(PPCState));

    auto u8 = llvm::Type::getInt8Ty(*context);
    auto u32 = llvm::Type::getInt32Ty(*context);
    auto u64 = llvm::Type::getInt64Ty(*context);

    auto f64 = llvm::Type::getDoubleTy(*context);

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

    PPCState state;

    REG(state, R0, gpr.r0.qword, u64);
    REG(state, R1, gpr.r1.qword, u64);
    REG(state, R2, gpr.r2.qword, u64);
    REG(state, R3, gpr.r3.qword, u64);
    REG(state, R4, gpr.r4.qword, u64);
    REG(state, R5, gpr.r5.qword, u64);
    REG(state, R6, gpr.r6.qword, u64);
    REG(state, R7, gpr.r7.qword, u64);
    REG(state, R8, gpr.r8.qword, u64);
    REG(state, R9, gpr.r9.qword, u64);
    REG(state, R10, gpr.r10.qword, u64);
    REG(state, R11, gpr.r11.qword, u64);
    REG(state, R12, gpr.r12.qword, u64);
    REG(state, R13, gpr.r13.qword, u64);
    REG(state, R14, gpr.r14.qword, u64);
    REG(state, R15, gpr.r15.qword, u64);
    REG(state, R16, gpr.r16.qword, u64);
    REG(state, R17, gpr.r17.qword, u64);
    REG(state, R18, gpr.r18.qword, u64);
    REG(state, R19, gpr.r19.qword, u64);
    REG(state, R20, gpr.r20.qword, u64);
    REG(state, R21, gpr.r21.qword, u64);
    REG(state, R22, gpr.r22.qword, u64);
    REG(state, R23, gpr.r23.qword, u64);
    REG(state, R24, gpr.r24.qword, u64);
    REG(state, R25, gpr.r25.qword, u64);
    REG(state, R26, gpr.r26.qword, u64);
    REG(state, R27, gpr.r27.qword, u64);
    REG(state, R28, gpr.r28.qword, u64);
    REG(state, R29, gpr.r29.qword, u64);
    REG(state, R30, gpr.r30.qword, u64);
    REG(state, R31, gpr.r31.qword, u64);


    // Subregs
    SUB_REG(state, _R0, gpr.r0.lo_bits, u32, R0);
    SUB_REG(state, _R1, gpr.r1.lo_bits, u32, R1);
    SUB_REG(state, _R2, gpr.r2.lo_bits, u32, R2);
    SUB_REG(state, _R3, gpr.r3.lo_bits, u32, R3);
    SUB_REG(state, _R4, gpr.r4.lo_bits, u32, R4);
    SUB_REG(state, _R5, gpr.r5.lo_bits, u32, R5);
    SUB_REG(state, _R6, gpr.r6.lo_bits, u32, R6);
    SUB_REG(state, _R7, gpr.r7.lo_bits, u32, R7);
    SUB_REG(state, _R8, gpr.r8.lo_bits, u32, R8);
    SUB_REG(state, _R9, gpr.r9.lo_bits, u32, R9);
    SUB_REG(state, _R10, gpr.r10.lo_bits, u32, R10);
    SUB_REG(state, _R11, gpr.r11.lo_bits, u32, R11);
    SUB_REG(state, _R12, gpr.r12.lo_bits, u32, R12);
    SUB_REG(state, _R13, gpr.r13.lo_bits, u32, R13);
    SUB_REG(state, _R14, gpr.r14.lo_bits, u32, R14);
    SUB_REG(state, _R15, gpr.r15.lo_bits, u32, R15);
    SUB_REG(state, _R16, gpr.r16.lo_bits, u32, R16);
    SUB_REG(state, _R17, gpr.r17.lo_bits, u32, R17);
    SUB_REG(state, _R18, gpr.r18.lo_bits, u32, R18);
    SUB_REG(state, _R19, gpr.r19.lo_bits, u32, R19);
    SUB_REG(state, _R20, gpr.r20.lo_bits, u32, R20);
    SUB_REG(state, _R21, gpr.r21.lo_bits, u32, R21);
    SUB_REG(state, _R22, gpr.r22.lo_bits, u32, R22);
    SUB_REG(state, _R23, gpr.r23.lo_bits, u32, R23);
    SUB_REG(state, _R24, gpr.r24.lo_bits, u32, R24);
    SUB_REG(state, _R25, gpr.r25.lo_bits, u32, R25);
    SUB_REG(state, _R26, gpr.r26.lo_bits, u32, R26);
    SUB_REG(state, _R27, gpr.r27.lo_bits, u32, R27);
    SUB_REG(state, _R28, gpr.r28.lo_bits, u32, R28);
    SUB_REG(state, _R29, gpr.r29.lo_bits, u32, R29);
    SUB_REG(state, _R30, gpr.r30.lo_bits, u32, R30);
    SUB_REG(state, _R31, gpr.r31.lo_bits, u32, R31);

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

    REG(state, CRALL, iar.cr.qword, u64);
    REG(state, CTR, iar.ctr.qword, u64);
    REG(state, LR, iar.lr.qword, u64);
    REG(state, XER, iar.xer.qword, u64);
    REG(state, SPEFCR, iar.spefscr.qword, u64);
    REG(state, ACC, iar.acc.qword, u64);

    // These are actually bitflags within XER and CR respectively. These would
    // normally be subregisters however, Sleigh treats these as entirely
    // separate registers of size 1.
    REG(state, XER_SO, xer_flags.so, u8);
    REG(state, XER_OV, xer_flags.ov, u8);
    REG(state, XER_CA, xer_flags.ca, u8);
    REG(state, XER_COUNT, xer_flags.sl, u8);

    REG(state, CR0, cr_flags.cr0, u8);
    REG(state, CR1, cr_flags.cr1, u8);
    REG(state, CR2, cr_flags.cr2, u8);
    REG(state, CR3, cr_flags.cr3, u8);
    REG(state, CR4, cr_flags.cr4, u8);
    REG(state, CR5, cr_flags.cr5, u8);
    REG(state, CR6, cr_flags.cr6, u8);
    REG(state, CR7, cr_flags.cr7, u8);

    REG(state, TBLR, tbr.tbl.qword, u64);
    REG(state, TBUR, tbr.tbu.qword, u64);

    REG(state, SPR103, sprg.r3.qword, u64);
    REG(state, SPR104, sprg.r4.qword, u64);
    REG(state, SPR105, sprg.r5.qword, u64);
    REG(state, SPR106, sprg.r6.qword, u64);
    REG(state, SPR107, sprg.r7.qword, u64);

    REG(state, SPR203, l1cfg.r0.qword, u64);
    REG(state, SPR204, l1cfg.r1.qword, u64);

    REG(state, PC, pc, u64);

    REG(state, TEA, signals.tea.qword, u64);
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
