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

#include "PPC.h"

#define INCLUDED_FROM_REMILL
#include <remill/Arch/PPC/Runtime/State.h>

namespace remill {

namespace sleighppc {

SleighPPCDecoder::SleighPPCDecoder(const remill::Arch &arch)
    : SleighDecoder(arch, "ppc_64_be.sla", "ppc_64.pspec", {}, {}) {}

llvm::Value *SleighPPCDecoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                                llvm::Value *curr_pc,
                                                size_t curr_insn_size) const {
  return nullptr;
}

void SleighPPCDecoder::InitializeSleighContext(
    remill::sleigh::SingleInstructionSleighContext &ctxt) const {}

class SleighPPCArch : public ArchBase {
 public:
  SleighPPCArch(llvm::LLVMContext *context_, OSName os_name_,
                ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        decoder(*this) {}
  virtual ~SleighPPCArch() = default;

  DecodingContext CreateInitialContext(void) const override {
    return DecodingContext();
  }

  std::string_view StackPointerRegisterName(void) const override {
    return "r1";
  }

  std::string_view ProgramCounterRegisterName(void) const override {
    // TODO(alex): PPC doesn't expose this. Need to figure out what to do here.
    return "";
  }

  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override {
    return this->decoder.GetOpLifter();
  }

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const override {
    return decoder.DecodeInstruction(address, instr_bytes, inst, context);
  }

  uint64_t MinInstructionAlign(const DecodingContext &) const override {
    return 4;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const override {
    return 4;
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
    return llvm::DataLayout("");
  }

  void PopulateRegisterTable(void) const override {
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(PPCState));

    auto u8 = llvm::Type::getInt8Ty(*context);
    auto u32 = llvm::Type::getInt32Ty(*context);
    auto u64 = llvm::Type::getInt64Ty(*context);
    auto u128 = llvm::Type::getInt128Ty(*context);

    auto f32 = llvm::Type::getFloatTy(*context);
    auto f64 = llvm::Type::getDoubleTy(*context);

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(PPCState, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(PPCState, access), #parent_reg_name)

    REG(r0, gpr.r0.qword, u64);
    REG(r1, gpr.r1.qword, u64);
    REG(r2, gpr.r2.qword, u64);
    REG(r3, gpr.r3.qword, u64);
    REG(r4, gpr.r4.qword, u64);
    REG(r5, gpr.r5.qword, u64);
    REG(r6, gpr.r6.qword, u64);
    REG(r7, gpr.r7.qword, u64);
    REG(r8, gpr.r8.qword, u64);
    REG(r9, gpr.r9.qword, u64);
    REG(r10, gpr.r10.qword, u64);
    REG(r11, gpr.r11.qword, u64);
    REG(r12, gpr.r12.qword, u64);
    REG(r13, gpr.r13.qword, u64);
    REG(r14, gpr.r14.qword, u64);
    REG(r15, gpr.r15.qword, u64);
    REG(r16, gpr.r16.qword, u64);
    REG(r17, gpr.r17.qword, u64);
    REG(r18, gpr.r18.qword, u64);
    REG(r19, gpr.r19.qword, u64);
    REG(r20, gpr.r20.qword, u64);
    REG(r21, gpr.r21.qword, u64);
    REG(r22, gpr.r22.qword, u64);
    REG(r23, gpr.r23.qword, u64);
    REG(r24, gpr.r24.qword, u64);
    REG(r25, gpr.r25.qword, u64);
    REG(r26, gpr.r26.qword, u64);
    REG(r27, gpr.r27.qword, u64);
    REG(r28, gpr.r28.qword, u64);
    REG(r29, gpr.r29.qword, u64);
    REG(r30, gpr.r30.qword, u64);
    REG(r31, gpr.r31.qword, u64);

    REG(f0, fpr.f0.qword, f64);
    REG(f1, fpr.f1.qword, f64);
    REG(f2, fpr.f2.qword, f64);
    REG(f3, fpr.f3.qword, f64);
    REG(f4, fpr.f4.qword, f64);
    REG(f5, fpr.f5.qword, f64);
    REG(f6, fpr.f6.qword, f64);
    REG(f7, fpr.f7.qword, f64);
    REG(f8, fpr.f8.qword, f64);
    REG(f9, fpr.f9.qword, f64);
    REG(f10, fpr.f10.qword, f64);
    REG(f11, fpr.f11.qword, f64);
    REG(f12, fpr.f12.qword, f64);
    REG(f13, fpr.f13.qword, f64);
    REG(f14, fpr.f14.qword, f64);
    REG(f15, fpr.f15.qword, f64);
    REG(f16, fpr.f16.qword, f64);
    REG(f17, fpr.f17.qword, f64);
    REG(f18, fpr.f18.qword, f64);
    REG(f19, fpr.f19.qword, f64);
    REG(f20, fpr.f20.qword, f64);
    REG(f21, fpr.f21.qword, f64);
    REG(f22, fpr.f22.qword, f64);
    REG(f23, fpr.f23.qword, f64);
    REG(f24, fpr.f24.qword, f64);
    REG(f25, fpr.f25.qword, f64);
    REG(f26, fpr.f26.qword, f64);
    REG(f27, fpr.f27.qword, f64);
    REG(f28, fpr.f28.qword, f64);
    REG(f29, fpr.f29.qword, f64);
    REG(f30, fpr.f30.qword, f64);

    // NOTE(alex): CR isn't one of the SPRs in the spec file, figure this out
    REG(CTR, iar.ctr.qword, u64);
    REG(LR, iar.lr.qword, u64);
    REG(XER, iar.xer.qword, u64);
    REG(SPEFCR, iar.spefscr.qword, u64);
    REG(ACC, iar.acc.qword, u64);

    // TODO(alex): Do the performance monitor registers too

    REG(TBLr, tbr.tbl.qword, u64);
    REG(TBUr, tbr.tbu.qword, u64);

    REG(spr103, sprg.r3.qword, u64);
    REG(spr104, sprg.r4.qword, u64);
    REG(spr105, sprg.r5.qword, u64);
    REG(spr106, sprg.r6.qword, u64);
    REG(spr107, sprg.r7.qword, u64);

    REG(spr203, l1cfg.r0.qword, u64);
    REG(spr204, l1cfg.r1.qword, u64);
  }

  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override {}

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
