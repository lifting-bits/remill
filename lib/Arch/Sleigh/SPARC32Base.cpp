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

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(SPARC32State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(SPARC32State, access), #parent_reg_name)

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);
  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  REG(PC, pc.dword, u32);

  REG(NEXT_PC, next_pc.dword, u32);

  REG(CWP, cwp.dword, u32);

  REG(SP, gpr.o6.dword, u32);

  REG(FP, gpr.i6.dword, u32);

  REG(I0, gpr.i0.dword, u32);
  REG(I1, gpr.i1.dword, u32);
  REG(I2, gpr.i2.dword, u32);
  REG(I3, gpr.i3.dword, u32);
  REG(I4, gpr.i4.dword, u32);
  REG(I5, gpr.i5.dword, u32);
  SUB_REG(I6, gpr.i6.dword, u32, FP);
  REG(I7, gpr.i7.dword, u32);
  REG(L0, gpr.l0.dword, u32);
  REG(L1, gpr.l1.dword, u32);
  REG(L2, gpr.l2.dword, u32);
  REG(L3, gpr.l3.dword, u32);
  REG(L4, gpr.l4.dword, u32);
  REG(L5, gpr.l5.dword, u32);
  REG(L6, gpr.l6.dword, u32);
  REG(L7, gpr.l7.dword, u32);
  REG(O0, gpr.o0.dword, u32);
  REG(O1, gpr.o1.dword, u32);
  REG(O2, gpr.o2.dword, u32);
  REG(O3, gpr.o3.dword, u32);
  REG(O4, gpr.o4.dword, u32);
  REG(O5, gpr.o5.dword, u32);
  SUB_REG(O6, gpr.o6.dword, u32, SP);
  REG(O7, gpr.o7.dword, u32);

  REG(G0, gpr.g0.dword, u32);
  REG(G1, gpr.g1.dword, u32);
  REG(G2, gpr.g2.dword, u32);
  REG(G3, gpr.g3.dword, u32);
  REG(G4, gpr.g4.dword, u32);
  REG(G5, gpr.g5.dword, u32);
  REG(G6, gpr.g6.dword, u32);
  REG(G7, gpr.g7.dword, u32);

  // Ancillary State Register
  REG(tick, tick.dword, u32);
  REG(y, yreg.dword, u32);
  REG(ccs, ccs.dword, u32);
  REG(pcr, pcr.dword, u32);
  REG(pic, pic.dword, u32);
  REG(gsr, gsr.dword, u32);
  REG(softint_set, softint_set, u32);
  REG(softint_clr, softint_clr, u32);
  REG(softint, softint, u32);
  REG(tick_cmpr, tick_cmpr, u32);
  REG(stick, stick, u32);
  REG(stick_cmpr, stick_cmpr, u32);

  REG(asr7, asr.asr7, u32);
  REG(asr8, asr.asr8, u32);
  REG(asr9, asr.asr9, u32);
  REG(asr10, asr.asr10, u32);
  REG(asr11, asr.asr11, u32);
  REG(asr12, asr.asr12, u32);
  REG(asr13, asr.asr13, u32);
  REG(asr14, asr.asr14, u32);
  REG(asr15, asr.asr15, u32);
  REG(asr16, asr.asr16, u32);
  REG(asr17, asr.asr17, u32);
  REG(asr18, asr.asr18, u32);
  REG(asr19, asr.asr19, u32);
  REG(asr20, asr.asr20, u32);
  REG(asr21, asr.asr21, u32);
  REG(asr22, asr.asr22, u32);
  REG(asr23, asr.asr23, u32);
  REG(asr24, asr.asr24, u32);
  REG(asr25, asr.asr25, u32);
  REG(asr26, asr.asr26, u32);
  REG(asr27, asr.asr27, u32);
  REG(asr28, asr.asr28, u32);
  REG(asr29, asr.asr29, u32);
  REG(asr30, asr.asr30, u32);
  REG(asr31, asr.asr31, u32);

  REG(ccf_fcc0, fsr.fcc0, u8);
  REG(ccf_fcc1, fsr.fcc1, u8);
  REG(ccf_fcc2, fsr.fcc2, u8);
  REG(ccf_fcc3, fsr.fcc3, u8);

  REG(fsr_aexc, fsr.aexc, u8);
  REG(fsr_cexc, fsr.cexc, u8);

  REG(v0, fpreg.v[0], u128);
  REG(v1, fpreg.v[1], u128);
  REG(v2, fpreg.v[2], u128);
  REG(v3, fpreg.v[3], u128);
  REG(v4, fpreg.v[4], u128);
  REG(v5, fpreg.v[5], u128);
  REG(v6, fpreg.v[6], u128);
  REG(v7, fpreg.v[7], u128);

  SUB_REG(f0, fpreg.v[0].floats.elems[0], f32, v0);
  SUB_REG(f1, fpreg.v[0].floats.elems[1], f32, v0);
  SUB_REG(f2, fpreg.v[0].floats.elems[2], f32, v0);
  SUB_REG(f3, fpreg.v[0].floats.elems[3], f32, v0);
  SUB_REG(f4, fpreg.v[1].floats.elems[0], f32, v1);
  SUB_REG(f5, fpreg.v[1].floats.elems[1], f32, v1);
  SUB_REG(f6, fpreg.v[1].floats.elems[2], f32, v1);
  SUB_REG(f7, fpreg.v[1].floats.elems[3], f32, v1);
  SUB_REG(f8, fpreg.v[2].floats.elems[0], f32, v2);
  SUB_REG(f9, fpreg.v[2].floats.elems[1], f32, v2);
  SUB_REG(f10, fpreg.v[2].floats.elems[2], f32, v2);
  SUB_REG(f11, fpreg.v[2].floats.elems[3], f32, v2);
  SUB_REG(f12, fpreg.v[3].floats.elems[0], f32, v3);
  SUB_REG(f13, fpreg.v[3].floats.elems[1], f32, v3);
  SUB_REG(f14, fpreg.v[3].floats.elems[2], f32, v3);
  SUB_REG(f15, fpreg.v[3].floats.elems[3], f32, v3);
  SUB_REG(f16, fpreg.v[4].floats.elems[0], f32, v4);
  SUB_REG(f17, fpreg.v[4].floats.elems[1], f32, v4);
  SUB_REG(f18, fpreg.v[4].floats.elems[2], f32, v4);
  SUB_REG(f19, fpreg.v[4].floats.elems[3], f32, v4);
  SUB_REG(f20, fpreg.v[5].floats.elems[0], f32, v5);
  SUB_REG(f21, fpreg.v[5].floats.elems[1], f32, v5);
  SUB_REG(f22, fpreg.v[5].floats.elems[2], f32, v5);
  SUB_REG(f23, fpreg.v[5].floats.elems[3], f32, v5);
  SUB_REG(f24, fpreg.v[6].floats.elems[0], f32, v6);
  SUB_REG(f25, fpreg.v[6].floats.elems[1], f32, v6);
  SUB_REG(f26, fpreg.v[6].floats.elems[2], f32, v6);
  SUB_REG(f27, fpreg.v[6].floats.elems[3], f32, v6);
  SUB_REG(f28, fpreg.v[7].floats.elems[0], f32, v7);
  SUB_REG(f29, fpreg.v[7].floats.elems[1], f32, v7);
  SUB_REG(f30, fpreg.v[7].floats.elems[2], f32, v7);
  SUB_REG(f31, fpreg.v[7].floats.elems[3], f32, v7);

  SUB_REG(d0, fpreg.v[0].doubles.elems[0], f64, v0);
  SUB_REG(d2, fpreg.v[0].doubles.elems[1], f64, v0);
  SUB_REG(d4, fpreg.v[1].doubles.elems[0], f64, v1);
  SUB_REG(d6, fpreg.v[1].doubles.elems[1], f64, v1);
  SUB_REG(d8, fpreg.v[2].doubles.elems[0], f64, v2);
  SUB_REG(d10, fpreg.v[2].doubles.elems[1], f64, v2);
  SUB_REG(d12, fpreg.v[3].doubles.elems[0], f64, v3);
  SUB_REG(d14, fpreg.v[3].doubles.elems[1], f64, v3);
  SUB_REG(d16, fpreg.v[4].doubles.elems[0], f64, v4);
  SUB_REG(d18, fpreg.v[4].doubles.elems[1], f64, v4);
  SUB_REG(d20, fpreg.v[5].doubles.elems[0], f64, v5);
  SUB_REG(d22, fpreg.v[5].doubles.elems[1], f64, v5);
  SUB_REG(d24, fpreg.v[6].doubles.elems[0], f64, v6);
  SUB_REG(d26, fpreg.v[6].doubles.elems[1], f64, v6);
  SUB_REG(d28, fpreg.v[7].doubles.elems[0], f64, v7);
  SUB_REG(d30, fpreg.v[7].doubles.elems[1], f64, v7);

  // NOTE(pag): This is a bit of a lie, but kind of like in x87 with 80-bit
  //            extended precision, we treat quad precision floats as being
  //            doubles.
  SUB_REG(q0, fpreg.v[0].doubles.elems[0], f64, v0);
  SUB_REG(q4, fpreg.v[1].doubles.elems[0], f64, v1);
  SUB_REG(q8, fpreg.v[2].doubles.elems[0], f64, v2);
  SUB_REG(q12, fpreg.v[3].doubles.elems[0], f64, v3);
  SUB_REG(q16, fpreg.v[4].doubles.elems[0], f64, v4);
  SUB_REG(q20, fpreg.v[5].doubles.elems[0], f64, v5);
  SUB_REG(q24, fpreg.v[6].doubles.elems[0], f64, v6);
  SUB_REG(q28, fpreg.v[7].doubles.elems[0], f64, v7);
  
  REG(DECOMPILE_MODE, decompile_mode, u8);
  REG(DIDRESTORE, didrestore, u8);
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void SPARC32ArchBase::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {

  auto &context = module->getContext();
  auto u8 = llvm::Type::getInt8Ty(context);
  auto u32 = llvm::Type::getInt32Ty(context);

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
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "IGNORE_NEXT_PC"),
                 false);
  ir.CreateStore(zero_u32, ir.CreateAlloca(u32, nullptr, "IGNORE_RETURN_PC"),
                 false);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  (void) RegisterByName(kNextPCVariableName)->AddressOf(state_ptr_arg, ir);

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
