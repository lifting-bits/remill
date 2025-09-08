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
#include "MIPS.h"

#define INCLUDED_FROM_REMILL
#include <remill/Arch/MIPS/Runtime/State.h>

namespace remill {

namespace sleighmips {
SleighMIPSDecoder::SleighMIPSDecoder(const remill::Arch &arch)
    : SleighDecoder(arch, "mips64be.sla", "mips64.pspec",
                    sleigh::ContextRegMappings({}, {}), {}) {}

llvm::Value *
SleighMIPSDecoder::LiftPcFromCurrPc(llvm::IRBuilder<> &bldr,
                                    llvm::Value *curr_pc, size_t curr_insn_size,
                                    const DecodingContext &) const {
  return bldr.CreateAdd(curr_pc, llvm::ConstantInt::get(curr_pc->getType(), 4));
}

void SleighMIPSDecoder::InitializeSleighContext(
    uint64_t addr, remill::sleigh::SingleInstructionSleighContext &ctxt,
    const ContextValues &values) const {
  //sleigh::SetContextRegisterValueInSleigh(
  //  addr, std::string("ZERO").c_str(), "zero", 0, ctxt, values);
}

class SleighMIPSArch : public ArchBase {
 public:
  SleighMIPSArch(llvm::LLVMContext *context_, OSName os_name_,
                 ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        decoder(*this) {}
  virtual ~SleighMIPSArch() = default;

  DecodingContext CreateInitialContext(void) const override {
    return DecodingContext();
  }

  std::string_view StackPointerRegisterName(void) const override {
    return "SP";
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
    inst.pc = address;
    inst.next_pc = address + instr_bytes.size();  // Default fall-through.
    inst.branch_taken_pc = 0;
    inst.branch_not_taken_pc = 0;
    inst.has_branch_taken_delay_slot = false;
    inst.has_branch_not_taken_delay_slot = false;
    inst.arch_name = arch_name;
    inst.sub_arch_name = arch_name;
    inst.branch_taken_arch_name = arch_name;
    inst.arch = this;
    inst.category = Instruction::kCategoryInvalid;
    inst.operands.clear();
    inst.flows = Instruction::InvalidInsn();

    context.UpdateContextReg(std::string("ZERO"), 0);  // What to do here?

    return this->decoder.DecodeInstruction(address, instr_bytes, inst, context);
  }

  uint64_t MinInstructionAlign(const DecodingContext &) const override {
    return 4;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const override {
    return 4;
  }

  uint64_t MaxInstructionSize(const DecodingContext &,
                              bool permit_fuse_idioms) const {
    return 8;  // Note: Technically 4 but due to delay slots we need pass 8 bytes to sleigh
  }

  llvm::CallingConv::ID DefaultCallingConv(void) const override {
    return llvm::CallingConv::C;
  }

  llvm::Triple Triple(void) const override {
    auto triple = BasicTriple();
    triple.setArch(llvm::Triple::mips64);
    return triple;
  }

  llvm::DataLayout DataLayout(void) const override {
    // M4xw: TODO: Confirm this is correct
    return llvm::DataLayout("E-m:e-p:32:32-i64:64-f128:64-n32-S64");
  }

  void PopulateRegisterTable(void) const override {
    CHECK_NOTNULL(context);

    reg_by_offset.resize(sizeof(MIPSState));

    auto u8 = llvm::Type::getInt8Ty(*context);
    auto u32 = llvm::Type::getInt32Ty(*context);
    auto u64 = llvm::Type::getInt64Ty(*context);

    auto f32 = llvm::Type::getFloatTy(*context);
    auto f64 = llvm::Type::getDoubleTy(*context);

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(MIPSState, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(MIPSState, access), #parent_reg_name)

    REG(ZERO, gpr.zero.qword, u64);
    SUB_REG(ZERO_LO, gpr.zero.dword, u32, ZERO);
    REG(AT, gpr.at.qword, u64);
    SUB_REG(AT_LO, gpr.at.dword, u32, AT);
    REG(V0, gpr.v0.qword, u64);
    SUB_REG(V0_LO, gpr.v0.dword, u32, V0);
    REG(V1, gpr.v1.qword, u64);
    SUB_REG(V1_LO, gpr.v1.dword, u32, V1);
    REG(A0, gpr.a0.qword, u64);
    SUB_REG(A0_LO, gpr.a0.dword, u32, A0);
    REG(A1, gpr.a1.qword, u64);
    SUB_REG(A1_LO, gpr.a1.dword, u32, A1);
    REG(A2, gpr.a2.qword, u64);
    SUB_REG(A2_LO, gpr.a2.dword, u32, A2);
    REG(A3, gpr.a3.qword, u64);
    SUB_REG(A3_LO, gpr.a3.dword, u32, A3);
    REG(T0, gpr.t0.qword, u64);
    SUB_REG(T0_LO, gpr.t0.dword, u32, T0);
    REG(T1, gpr.t1.qword, u64);
    SUB_REG(T1_LO, gpr.t1.dword, u32, T1);
    REG(T2, gpr.t2.qword, u64);
    SUB_REG(T2_LO, gpr.t2.dword, u32, T2);
    REG(T3, gpr.t3.qword, u64);
    SUB_REG(T3_LO, gpr.t3.dword, u32, T3);
    REG(T4, gpr.t4.qword, u64);
    SUB_REG(T4_LO, gpr.t4.dword, u32, T4);
    REG(T5, gpr.t5.qword, u64);
    SUB_REG(T5_LO, gpr.t5.dword, u32, T5);
    REG(T6, gpr.t6.qword, u64);
    SUB_REG(T6_LO, gpr.t6.dword, u32, T6);
    REG(T7, gpr.t7.qword, u64);
    SUB_REG(T7_LO, gpr.t7.dword, u32, T7);
    REG(S0, gpr.s0.qword, u64);
    SUB_REG(S0_LO, gpr.s0.dword, u32, S0);
    REG(S1, gpr.s1.qword, u64);
    SUB_REG(S1_LO, gpr.s1.dword, u32, S1);
    REG(S2, gpr.s2.qword, u64);
    SUB_REG(S2_LO, gpr.s2.dword, u32, S2);
    REG(S3, gpr.s3.qword, u64);
    SUB_REG(S3_LO, gpr.s3.dword, u32, S3);
    REG(S4, gpr.s4.qword, u64);
    SUB_REG(S4_LO, gpr.s4.dword, u32, S4);
    REG(S5, gpr.s5.qword, u64);
    SUB_REG(S5_LO, gpr.s5.dword, u32, S5);
    REG(S6, gpr.s6.qword, u64);
    SUB_REG(S6_LO, gpr.s6.dword, u32, S6);
    REG(S7, gpr.s7.qword, u64);
    SUB_REG(S7_LO, gpr.s7.dword, u32, S7);
    REG(T8, gpr.t8.qword, u64);
    SUB_REG(T8_LO, gpr.t8.dword, u32, T8);
    REG(T9, gpr.t9.qword, u64);
    SUB_REG(T9_LO, gpr.t9.dword, u32, T9);
    REG(K0, gpr.k0.qword, u64);
    SUB_REG(K0_LO, gpr.k0.dword, u32, K0);
    REG(K1, gpr.k1.qword, u64);
    SUB_REG(K1_LO, gpr.k1.dword, u32, K1);
    REG(GP, gpr.gp.qword, u64);
    SUB_REG(GP_LO, gpr.gp.dword, u32, GP);
    REG(SP, gpr.sp.qword, u64);
    SUB_REG(SP_LO, gpr.sp.dword, u32, SP);
    REG(S8, gpr.s8.qword, u64);
    SUB_REG(S8_LO, gpr.s8.dword, u32, S8);
    REG(RA, gpr.ra.qword, u64);
    SUB_REG(RA_LO, gpr.ra.dword, u32, RA);
    REG(PC, gpr.pc.qword, u64);
    SUB_REG(PC_LO, gpr.pc.dword, u32, PC);

    // Flags
    REG(ISAMODESWITCH, flags.ISAModeSwitch.qword, u8);
    REG(HI, flags.HI.qword, u64);
    REG(LO, flags.LO.qword, u64);

    // FPR
    REG(F0, fpr.f0.qword, f64);
    SUB_REG(F0_LO, fpr.f0.dword, f32, F0);
    REG(F1, fpr.f1.qword, f64);
    SUB_REG(F1_LO, fpr.f1.dword, f32, F1);
    REG(F2, fpr.f2.qword, f64);
    SUB_REG(F2_LO, fpr.f2.dword, f32, F2);
    REG(F3, fpr.f3.qword, f64);
    SUB_REG(F3_LO, fpr.f3.dword, f32, F3);
    REG(F4, fpr.f4.qword, f64);
    SUB_REG(F4_LO, fpr.f4.dword, f32, F4);
    REG(F5, fpr.f5.qword, f64);
    SUB_REG(F5_LO, fpr.f5.dword, f32, F5);
    REG(F6, fpr.f6.qword, f64);
    SUB_REG(F6_LO, fpr.f6.dword, f32, F6);
    REG(F7, fpr.f7.qword, f64);
    SUB_REG(F7_LO, fpr.f7.dword, f32, F7);
    REG(F8, fpr.f8.qword, f64);
    SUB_REG(F8_LO, fpr.f8.dword, f32, F8);
    REG(F9, fpr.f9.qword, f64);
    SUB_REG(F9_LO, fpr.f9.dword, f32, F9);
    REG(F10, fpr.f10.qword, f64);
    SUB_REG(F10_LO, fpr.f10.dword, f32, F10);
    REG(F11, fpr.f11.qword, f64);
    SUB_REG(F11_LO, fpr.f11.dword, f32, F11);
    REG(F12, fpr.f12.qword, f64);
    SUB_REG(F12_LO, fpr.f12.dword, f32, F12);
    REG(F13, fpr.f13.qword, f64);
    SUB_REG(F13_LO, fpr.f13.dword, f32, F13);
    REG(F14, fpr.f14.qword, f64);
    SUB_REG(F14_LO, fpr.f14.dword, f32, F14);
    REG(F15, fpr.f15.qword, f64);
    SUB_REG(F15_LO, fpr.f15.dword, f32, F15);
    REG(F16, fpr.f16.qword, f64);
    SUB_REG(F16_LO, fpr.f16.dword, f32, F16);
    REG(F17, fpr.f17.qword, f64);
    SUB_REG(F17_LO, fpr.f17.dword, f32, F17);
    REG(F18, fpr.f18.qword, f64);
    SUB_REG(F18_LO, fpr.f18.dword, f32, F18);
    REG(F19, fpr.f19.qword, f64);
    SUB_REG(F19_LO, fpr.f19.dword, f32, F19);
    REG(F20, fpr.f20.qword, f64);
    SUB_REG(F20_LO, fpr.f20.dword, f32, F20);
    REG(F21, fpr.f21.qword, f64);
    SUB_REG(F21_LO, fpr.f21.dword, f32, F21);
    REG(F22, fpr.f22.qword, f64);
    SUB_REG(F22_LO, fpr.f22.dword, f32, F22);
    REG(F23, fpr.f23.qword, f64);
    SUB_REG(F23_LO, fpr.f23.dword, f32, F23);
    REG(F24, fpr.f24.qword, f64);
    SUB_REG(F24_LO, fpr.f24.dword, f32, F24);
    REG(F25, fpr.f25.qword, f64);
    SUB_REG(F25_LO, fpr.f25.dword, f32, F25);
    REG(F26, fpr.f26.qword, f64);
    SUB_REG(F26_LO, fpr.f26.dword, f32, F26);
    REG(F27, fpr.f27.qword, f64);
    SUB_REG(F27_LO, fpr.f27.dword, f32, F27);
    REG(F28, fpr.f28.qword, f64);
    SUB_REG(F28_LO, fpr.f28.dword, f32, F28);
    REG(F29, fpr.f29.qword, f64);
    SUB_REG(F29_LO, fpr.f29.dword, f32, F29);
    REG(F30, fpr.f30.qword, f64);
    SUB_REG(F30_LO, fpr.f30.dword, f32, F30);
    REG(F31, fpr.f31.qword, f64);
    SUB_REG(F31_LO, fpr.f31.dword, f32, F31);

    // COP0
    REG(INDEX, cop0.Index.qword, u64);
    REG(RANDOM, cop0.Random.qword, u64);
    REG(ENTRYLO0, cop0.EntryLo0.qword, u64);
    REG(ENTRYLO1, cop0.EntryLo1.qword, u64);
    REG(CONTEXT, cop0.Context.qword, u64);
    REG(PAGEMASK, cop0.PageMask.qword, u64);
    REG(WIRED, cop0.Wired.qword, u64);
    REG(HWRENA, cop0.HWREna.qword, u64);
    REG(BADVADDR, cop0.BadVAddr.qword, u64);
    REG(COUNT, cop0.Count.qword, u64);
    REG(ENTRYHI, cop0.EntryHi.qword, u64);
    REG(COMPARE, cop0.Compare.qword, u64);
    REG(STATUS, cop0.Status.qword, u64);
    REG(CAUSE, cop0.Cause.qword, u64);
    REG(EPC, cop0.EPC.qword, u64);
    REG(PRID, cop0.PRId.qword, u64);
    REG(CONFIG, cop0.Config.qword, u64);
    REG(LLADDR, cop0.LLAddr.qword, u64);
    REG(WATCHLO, cop0.WatchLo.qword, u64);
    REG(WATCHHI, cop0.WatchHi.qword, u64);
    REG(XCONTEXT, cop0.XContext.qword, u64);
    REG(COP0_REG21, cop0.cop0_reg21.qword, u64);
    REG(COP0_REG22, cop0.cop0_reg22.qword, u64);
    REG(DEBUG, cop0.Debug.qword, u64);
    REG(DEPC, cop0.DEPC.qword, u64);
    REG(PERFCNT, cop0.PerfCnt.qword, u64);
    REG(ERRCTL, cop0.ErrCtl.qword, u64);
    REG(CACHEERR, cop0.CacheErr.qword, u64);
    REG(TAGLO, cop0.TagLo.qword, u64);
    REG(TAGHI, cop0.TagHi.qword, u64);
    REG(ERRORPC, cop0.ErrorEPC.qword, u64);
    REG(DESAVE, cop0.DESAVE.qword, u64);

    // COP1
    // TODO: Maybe move fpr here?
    REG(FCSR, cop1.FCSR.dword, u32);
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

    /*auto u8 = llvm::Type::getInt8Ty(context);
    auto zero_c = ir.CreateAlloca(u8, nullptr, "ZERO");
    ir.CreateStore(llvm::Constant::getNullValue(u8), zero_c);*/

    std::ignore = RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir);
  }

 private:
  SleighMIPSDecoder decoder;
};

}  // namespace sleighmips

Arch::ArchPtr Arch::GetSleighMIPS(llvm::LLVMContext *context_,
                                  remill::OSName os_name_,
                                  remill::ArchName arch_name_) {
  return std::make_unique<sleighmips::SleighMIPSArch>(context_, os_name_,
                                                      arch_name_);
}

}  // namespace remill
