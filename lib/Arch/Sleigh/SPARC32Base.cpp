/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
#include <remill/Arch/SPARC32/SPARC32Base.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

namespace remill {
// Returns the name of the stack pointer register.
std::string_view SPARC32ArchBase::StackPointerRegisterName(void) const {
  return "SP";
}

// Returns the name of the program counter register.
std::string_view SPARC32ArchBase::ProgramCounterRegisterName(void) const {
  return "PC";
}

uint64_t SPARC32ArchBase::MinInstructionAlign(const DecodingContext &) const {
  return 4;
}

uint64_t SPARC32ArchBase::MinInstructionSize(const DecodingContext &) const {
  return 4;
}

// Returns `true` if memory access are little endian byte ordered.
bool SPARC32ArchBase::MemoryAccessIsLittleEndian(void) const {
  return false;
}

// Returns `true` if a given instruction might have a delay slot.
bool SPARC32ArchBase::MayHaveDelaySlot(const Instruction &inst) const {
  return inst.has_branch_taken_delay_slot ||
         inst.has_branch_not_taken_delay_slot;
}

// Returns `true` if we should lift the semantics of `next_inst` as a delay
// slot of `inst`. The `branch_taken_path` tells us whether we are in the
// context of the taken path of a branch or the not-taken path of a branch.
bool SPARC32ArchBase::NextInstructionIsDelayed(const Instruction &inst,
                                           const Instruction &next_inst,
                                           bool branch_taken_path) const {
  if (inst.delayed_pc != next_inst.pc) {
    return false;
  }

  if (branch_taken_path) {
    return inst.has_branch_taken_delay_slot;
  } else {
    return inst.has_branch_not_taken_delay_slot;
  }
}

// Maximum number of bytes in an instruction.
uint64_t SPARC32ArchBase::MaxInstructionSize(const DecodingContext &,
                            bool permit_fuse_idioms) const {
  return permit_fuse_idioms ? 8 : 4;  // To handle `SET` idioms.
}

// Default calling convention for this architecture.
llvm::CallingConv::ID SPARC32ArchBase::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;
}

// Populate the table of register information.
void SPARC32ArchBase::PopulateRegisterTable(void) const {

  reg_by_offset.resize(sizeof(SPARC32State));

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);
  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  SPARC32State state;

  REG(state, PC, pc.dword, u32);

  REG(state, CWP, cwp.dword, u32);

  REG(state, I0_1, gpr.i0_1.qword, u64);
  REG(state, I2_3, gpr.i2_3.qword, u64);
  REG(state, I4_5, gpr.i4_5.qword, u64);
  REG(state, FP_7, gpr.fp_7.qword, u64);
  REG(state, L0_1, gpr.l0_1.qword, u64);
  REG(state, L2_3, gpr.l2_3.qword, u64);
  REG(state, L4_5, gpr.l4_5.qword, u64);
  REG(state, L6_7, gpr.l6_7.qword, u64);
  REG(state, O0_1, gpr.o0_1.qword, u64);
  REG(state, O2_3, gpr.o2_3.qword, u64);
  REG(state, O4_5, gpr.o4_5.qword, u64);
  REG(state, SP_7, gpr.sp_7.qword, u64);
  REG(state, G0_1, gpr.g0_1.qword, u64);
  REG(state, G2_3, gpr.g2_3.qword, u64);
  REG(state, G4_5, gpr.g4_5.qword, u64);
  REG(state, G6_7, gpr.g6_7.qword, u64);

  SUB_REG(state, I0, gpr.i0_1.reg1.dword, u32, I0_1);
  SUB_REG(state, I1, gpr.i0_1.reg2.dword, u32, I0_1);
  SUB_REG(state, I2, gpr.i2_3.reg1.dword, u32, I2_3);
  SUB_REG(state, I3, gpr.i2_3.reg2.dword, u32, I2_3);
  SUB_REG(state, I4, gpr.i4_5.reg1.dword, u32, I4_5);
  SUB_REG(state, I5, gpr.i4_5.reg2.dword, u32, I4_5);
  SUB_REG(state, FP, gpr.fp_7.reg1.dword, u32, FP_7);
  SUB_REG(state, I7, gpr.fp_7.reg2.dword, u32, FP_7);
  SUB_REG(state, L0, gpr.l0_1.reg1.dword, u32, L0_1);
  SUB_REG(state, L1, gpr.l0_1.reg2.dword, u32, L0_1);
  SUB_REG(state, L2, gpr.l2_3.reg1.dword, u32, L2_3);
  SUB_REG(state, L3, gpr.l2_3.reg2.dword, u32, L2_3);
  SUB_REG(state, L4, gpr.l4_5.reg1.dword, u32, L4_5);
  SUB_REG(state, L5, gpr.l4_5.reg2.dword, u32, L4_5);
  SUB_REG(state, L6, gpr.l6_7.reg1.dword, u32, L6_7);
  SUB_REG(state, L7, gpr.l6_7.reg2.dword, u32, L6_7);
  SUB_REG(state, O0, gpr.o0_1.reg1.dword, u32, O0_1);
  SUB_REG(state, O1, gpr.o0_1.reg2.dword, u32, O0_1);
  SUB_REG(state, O2, gpr.o2_3.reg1.dword, u32, O2_3);
  SUB_REG(state, O3, gpr.o2_3.reg2.dword, u32, O2_3);
  SUB_REG(state, O4, gpr.o4_5.reg1.dword, u32, O4_5);
  SUB_REG(state, O5, gpr.o4_5.reg2.dword, u32, O4_5);
  SUB_REG(state, SP, gpr.sp_7.reg1.dword, u32, SP_7);
  SUB_REG(state, O7, gpr.sp_7.reg2.dword, u32, SP_7);

  SUB_REG(state, G0, gpr.g0_1.reg1.dword, u32, G0_1);
  SUB_REG(state, G1, gpr.g0_1.reg2.dword, u32, G0_1);
  SUB_REG(state, G2, gpr.g2_3.reg1.dword, u32, G2_3);
  SUB_REG(state, G3, gpr.g2_3.reg2.dword, u32, G2_3);
  SUB_REG(state, G4, gpr.g4_5.reg1.dword, u32, G4_5);
  SUB_REG(state, G5, gpr.g4_5.reg2.dword, u32, G4_5);
  SUB_REG(state, G6, gpr.g6_7.reg1.dword, u32, G6_7);
  SUB_REG(state, G7, gpr.g6_7.reg2.dword, u32, G6_7);

  // Ancillary State Register
  REG(state, Y, asr.yreg.dword, u32);
  REG(state, TICK, asr.tick.dword, u32);
  REG(state, CCR, asr.ccr.dword, u32);
  REG(state, PCR, asr.pcr.dword, u32);
  REG(state, PIC, asr.pic.dword, u32);
  REG(state, GSR, asr.gsr.dword, u32);
  REG(state, SOFTINT_SET, asr.softint_set.dword, u32);
  REG(state, SOFTINT_CLR, asr.softint_clr.dword, u32);
  REG(state, SOFTINT, asr.softint.dword, u32);
  REG(state, TICK_CMPR, asr.tick_cmpr.dword, u32);
  REG(state, STICK, asr.stick.dword, u32);
  REG(state, STICK_CMPR, asr.stick_cmpr.dword, u32);

  REG(state, I_CF, ccr.icc.i_cf, u8);
  REG(state, I_VF, ccr.icc.i_vf, u8);
  REG(state, I_ZF, ccr.icc.i_zf, u8);
  REG(state, I_NF, ccr.icc.i_nf, u8);

  REG(state, X_CF, ccr.xcc.x_cf, u8);
  REG(state, X_VF, ccr.xcc.x_vf, u8);
  REG(state, X_ZF, ccr.xcc.x_zf, u8);
  REG(state, X_NF, ccr.xcc.x_nf, u8);

  REG(state, ccf_fcc0, fsr.fcc0, u8);
  REG(state, ccf_fcc1, fsr.fcc1, u8);
  REG(state, ccf_fcc2, fsr.fcc2, u8);
  REG(state, ccf_fcc3, fsr.fcc3, u8);

  REG(state, fsr_aexc, fsr.aexc, u8);
  REG(state, fsr_cexc, fsr.cexc, u8);

  REG(state, FQ0, fpreg.v[0], u128);
  REG(state, FQ4, fpreg.v[1], u128);
  REG(state, FQ8, fpreg.v[2], u128);
  REG(state, FQ12, fpreg.v[3], u128);
  REG(state, FQ16, fpreg.v[4], u128);
  REG(state, FQ20, fpreg.v[5], u128);
  REG(state, FQ24, fpreg.v[6], u128);
  REG(state, FQ28, fpreg.v[7], u128);

  SUB_REG(state, FS0, fpreg.v[0].floats.elems[0], f32, FQ0);
  SUB_REG(state, FS1, fpreg.v[0].floats.elems[1], f32, FQ0);
  SUB_REG(state, FS2, fpreg.v[0].floats.elems[2], f32, FQ0);
  SUB_REG(state, FS3, fpreg.v[0].floats.elems[3], f32, FQ0);
  SUB_REG(state, FS4, fpreg.v[1].floats.elems[0], f32, FQ4);
  SUB_REG(state, FS5, fpreg.v[1].floats.elems[1], f32, FQ4);
  SUB_REG(state, FS6, fpreg.v[1].floats.elems[2], f32, FQ4);
  SUB_REG(state, FS7, fpreg.v[1].floats.elems[3], f32, FQ4);
  SUB_REG(state, FS8, fpreg.v[2].floats.elems[0], f32, FQ8);
  SUB_REG(state, FS9, fpreg.v[2].floats.elems[1], f32, FQ8);
  SUB_REG(state, FS10, fpreg.v[2].floats.elems[2], f32, FQ8);
  SUB_REG(state, FS11, fpreg.v[2].floats.elems[3], f32, FQ8);
  SUB_REG(state, FS12, fpreg.v[3].floats.elems[0], f32, FQ12);
  SUB_REG(state, FS13, fpreg.v[3].floats.elems[1], f32, FQ12);
  SUB_REG(state, FS14, fpreg.v[3].floats.elems[2], f32, FQ12);
  SUB_REG(state, FS15, fpreg.v[3].floats.elems[3], f32, FQ12);
  SUB_REG(state, FS16, fpreg.v[4].floats.elems[0], f32, FQ16);
  SUB_REG(state, FS17, fpreg.v[4].floats.elems[1], f32, FQ16);
  SUB_REG(state, FS18, fpreg.v[4].floats.elems[2], f32, FQ16);
  SUB_REG(state, FS19, fpreg.v[4].floats.elems[3], f32, FQ16);
  SUB_REG(state, FS20, fpreg.v[5].floats.elems[0], f32, FQ20);
  SUB_REG(state, FS21, fpreg.v[5].floats.elems[1], f32, FQ20);
  SUB_REG(state, FS22, fpreg.v[5].floats.elems[2], f32, FQ20);
  SUB_REG(state, FS23, fpreg.v[5].floats.elems[3], f32, FQ20);
  SUB_REG(state, FS24, fpreg.v[6].floats.elems[0], f32, FQ24);
  SUB_REG(state, FS25, fpreg.v[6].floats.elems[1], f32, FQ24);
  SUB_REG(state, FS26, fpreg.v[6].floats.elems[2], f32, FQ24);
  SUB_REG(state, FS27, fpreg.v[6].floats.elems[3], f32, FQ24);
  SUB_REG(state, FS28, fpreg.v[7].floats.elems[0], f32, FQ28);
  SUB_REG(state, FS29, fpreg.v[7].floats.elems[1], f32, FQ28);
  SUB_REG(state, FS30, fpreg.v[7].floats.elems[2], f32, FQ28);
  SUB_REG(state, FS31, fpreg.v[7].floats.elems[3], f32, FQ28);

  SUB_REG(state, FD0, fpreg.v[0].doubles.elems[0], f64, FQ0);
  SUB_REG(state, FD2, fpreg.v[0].doubles.elems[1], f64, FQ0);
  SUB_REG(state, FD4, fpreg.v[1].doubles.elems[0], f64, FQ4);
  SUB_REG(state, FD6, fpreg.v[1].doubles.elems[1], f64, FQ4);
  SUB_REG(state, FD8, fpreg.v[2].doubles.elems[0], f64, FQ8);
  SUB_REG(state, FD10, fpreg.v[2].doubles.elems[1], f64, FQ8);
  SUB_REG(state, FD12, fpreg.v[3].doubles.elems[0], f64, FQ12);
  SUB_REG(state, FD14, fpreg.v[3].doubles.elems[1], f64, FQ12);
  SUB_REG(state, FD16, fpreg.v[4].doubles.elems[0], f64, FQ16);
  SUB_REG(state, FD18, fpreg.v[4].doubles.elems[1], f64, FQ16);
  SUB_REG(state, FD20, fpreg.v[5].doubles.elems[0], f64, FQ20);
  SUB_REG(state, FD22, fpreg.v[5].doubles.elems[1], f64, FQ20);
  SUB_REG(state, FD24, fpreg.v[6].doubles.elems[0], f64, FQ24);
  SUB_REG(state, FD26, fpreg.v[6].doubles.elems[1], f64, FQ24);
  SUB_REG(state, FD28, fpreg.v[7].doubles.elems[0], f64, FQ28);
  SUB_REG(state, FD30, fpreg.v[7].doubles.elems[1], f64, FQ28);
  
  REG(state, DECOMPILE_MODE, decompile_mode, u8);
  REG(state, DIDRESTORE, didrestore, u8);
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void SPARC32ArchBase::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {

  auto &context = module->getContext();
  auto u8 = llvm::Type::getInt8Ty(context);
  auto u32 = llvm::Type::getInt32Ty(context);
  auto addr = llvm::Type::getIntNTy(context, address_size);

  auto zero_u8 = llvm::Constant::getNullValue(u8);
  auto zero_u32 = llvm::Constant::getNullValue(u32);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "g0"), false);
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "ignore_write_to_g0"),
                 false);

  // this is for unknown asr to avoid crash.
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "asr"), false);

  ir.CreateStore(zero_u8, ir.CreateAlloca(u8, nullptr, "IGNORE_BRANCH_TAKEN"),
                 false);
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "IGNORE_PC"), false);
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "IGNORE_RETURN_PC"),
                 false);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  ir.CreateStore(pc_arg,
                 ir.CreateAlloca(addr, nullptr, kNextPCVariableName.data()));
  ir.CreateStore(
      pc_arg, ir.CreateAlloca(addr, nullptr, kIgnoreNextPCVariableName.data()));


  ir.CreateStore(pc_arg,
                 RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir),
                 false);
}

llvm::Triple SPARC32ArchBase::Triple(void) const {
  auto triple = BasicTriple();
  triple.setArch(llvm::Triple::sparc);
  return triple;
}

llvm::DataLayout SPARC32ArchBase::DataLayout(void) const {
  return llvm::DataLayout("E-m:e-p:32:32-i64:64-f128:64-n32-S64");
}

}  // remill
