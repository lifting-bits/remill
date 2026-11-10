/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

#include "SPARC64Arch.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>

#include <iterator>
#include <string>

#include "SPARC.h"

// clang-format off
#include <remill/Arch/SPARC64/Runtime/State.h>
// clang-format on

namespace remill {
namespace {

// `DECOMPILE_MODE` is a fake register of Ghidra's SPARC specification. When it
// is 1, as in `SparcV9.pspec`, `save` and `restore` only move the in and out
// registers instead of also spilling and filling the register window backing
// store through computed register-space addresses, which would be lifted as
// memory accesses. It is provided as a decoding context value.
static constexpr const char *kDecompileModeReg = "DECOMPILE_MODE";

// The register names below are Ghidra's, upper-cased like the Sleigh lifter
// does when it looks registers up.
static const char *const kGPRNames[] = {
    "G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7", "O0", "O1", "O2",
    "O3", "O4", "O5", "SP", "O7", "L0", "L1", "L2", "L3", "L4", "L5",
    "L6", "L7", "I0", "I1", "I2", "I3", "I4", "I5", "FP", "I7"};

static const char *const kASRNames[] = {
    "TICK",    "Y",         "CCR",         "PCR",
    "PIC",     "GSR",       "SOFTINT_SET", "SOFTINT_CLR",
    "SOFTINT", "TICK_CMPR", "STICK",       "STICK_CMPR"};

static const char *const kPrivNames[] = {
    "TPC1",     "TPC2",     "TPC3",    "TPC4",    "TNPC1",   "TNPC2",
    "TNPC3",    "TNPC4",    "TSTATE1", "TSTATE2", "TSTATE3", "TSTATE4",
    "TT1",      "TT2",      "TT3",     "TT4",     "TCK",     "TBA",
    "PSTATE",   "TL",       "PIL",     "CWP",     "CANSAVE", "CANRESTORE",
    "CLEANWIN", "OTHERWIN", "WSTATE",  "FQ",      "VER",     "GL"};

#define NUM_REGS(field) (sizeof(SPARC64State::field) / sizeof(SPARC64Reg))
static_assert(std::size(kGPRNames) == NUM_REGS(gpr));
static_assert(std::size(kASRNames) == NUM_REGS(asr));
static_assert(std::size(kPrivNames) == NUM_REGS(priv));
#undef NUM_REGS

}  // namespace

SleighSPARC64Decoder::SleighSPARC64Decoder(const remill::Arch &arch)
    : SleighDecoder(
          arch, "SparcV9_64.sla", "SparcV9.pspec",
          sleigh::ContextRegMappings({{kDecompileModeReg, kDecompileModeReg}},
                                     {{kDecompileModeReg, 1}}),
          {}) {}

void SleighSPARC64Decoder::InitializeSleighContext(
    uint64_t, remill::sleigh::SingleInstructionSleighContext &,
    const ContextValues &) const {}

// The value of the `PC` register while the instruction executes: on SPARC,
// the address of the instruction itself.
llvm::Value *
SleighSPARC64Decoder::LiftPcFromCurrPc(llvm::IRBuilder<> &,
                                       llvm::Value *curr_pc, size_t,
                                       const DecodingContext &) const {
  return curr_pc;
}

SPARC64Arch::SPARC64Arch(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      decoder(*this) {}

std::string_view SPARC64Arch::StackPointerRegisterName(void) const {
  return "SP";
}

std::string_view SPARC64Arch::ProgramCounterRegisterName(void) const {
  return "PC";
}

uint64_t SPARC64Arch::MinInstructionAlign(const DecodingContext &) const {
  return 4;
}

uint64_t SPARC64Arch::MinInstructionSize(const DecodingContext &) const {
  return 4;
}

// Sleigh decodes a delayed control transfer together with the instruction in
// its delay slot, so an instruction can be 8 bytes long. (Hence the
// architecture never reports a separate delay slot.)
uint64_t SPARC64Arch::MaxInstructionSize(const DecodingContext &, bool) const {
  return 8;
}

llvm::CallingConv::ID SPARC64Arch::DefaultCallingConv(void) const {
  return llvm::CallingConv::C;
}

llvm::Triple SPARC64Arch::Triple(void) const {
  auto triple = BasicTriple();
  triple.setArch(llvm::Triple::sparcv9);
  return triple;
}

llvm::DataLayout SPARC64Arch::DataLayout(void) const {
  return llvm::DataLayout("E-m:e-i64:64-n32:64-S128");
}

bool SPARC64Arch::MemoryAccessIsLittleEndian(void) const {
  return false;
}

void SPARC64Arch::PopulateRegisterTable(void) const {
  reg_by_offset.resize(sizeof(SPARC64State));

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);
  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  SPARC64State state;

#define OFFSET_OF(access) \
  (reinterpret_cast<uintptr_t>(&state.access) - \
   reinterpret_cast<uintptr_t>(&state))

  for (auto i = 0u; i < std::size(kGPRNames); ++i) {
    AddRegister(kGPRNames[i], u64, OFFSET_OF(gpr[i].qword), nullptr);
  }
  for (auto i = 0u; i < std::size(kASRNames); ++i) {
    AddRegister(kASRNames[i], u64, OFFSET_OF(asr[i].qword), nullptr);
  }
  for (auto i = 0u; i < std::size(kPrivNames); ++i) {
    AddRegister(kPrivNames[i], u64, OFFSET_OF(priv[i].qword), nullptr);
  }

  AddRegister("PC", u64, OFFSET_OF(pc.qword), nullptr);
  AddRegister("NPC", u64, OFFSET_OF(npc.qword), nullptr);
  AddRegister("FSR", u64, OFFSET_OF(fsr.qword), nullptr);

  AddRegister("X_NF", u8, OFFSET_OF(flags.x_nf), nullptr);
  AddRegister("X_ZF", u8, OFFSET_OF(flags.x_zf), nullptr);
  AddRegister("X_VF", u8, OFFSET_OF(flags.x_vf), nullptr);
  AddRegister("X_CF", u8, OFFSET_OF(flags.x_cf), nullptr);
  AddRegister("I_NF", u8, OFFSET_OF(flags.i_nf), nullptr);
  AddRegister("I_ZF", u8, OFFSET_OF(flags.i_zf), nullptr);
  AddRegister("I_VF", u8, OFFSET_OF(flags.i_vf), nullptr);
  AddRegister("I_CF", u8, OFFSET_OF(flags.i_cf), nullptr);
  AddRegister("FCC0", u8, OFFSET_OF(flags.fcc0), nullptr);
  AddRegister("FCC1", u8, OFFSET_OF(flags.fcc1), nullptr);
  AddRegister("FCC2", u8, OFFSET_OF(flags.fcc2), nullptr);
  AddRegister("FCC3", u8, OFFSET_OF(flags.fcc3), nullptr);
  AddRegister("ASI", u8, OFFSET_OF(flags.asi), nullptr);
  AddRegister("FPRS", u8, OFFSET_OF(flags.fprs), nullptr);
  AddRegister("DIDRESTORE", u8, OFFSET_OF(flags.didrestore), nullptr);

  // Ghidra numbers the floating-point registers big-endian: `fs(4q)` is the
  // high half of `fd(4q)`, which is the high half of `fq(4q)`. Like the
  // semantics, the state is laid out in SPARC's big-endian byte order, so
  // the high halves come first. Only `fq0`-`fq28` have single-precision
  // halves.
  for (auto q = 0u; q < std::size(state.fpreg); ++q) {
    const auto quad = "FQ" + std::to_string(4u * q);
    AddRegister(quad.c_str(), u128, OFFSET_OF(fpreg[q]), nullptr);
    for (auto d = 0u; d < 2u; ++d) {
      AddRegister(("FD" + std::to_string(4u * q + 2u * d)).c_str(), f64,
                  OFFSET_OF(fpreg[q].doubles.elems[d]), quad.c_str());
    }
    for (auto f = 0u; q < 8u && f < 4u; ++f) {
      AddRegister(("FS" + std::to_string(4u * q + f)).c_str(), f32,
                  OFFSET_OF(fpreg[q].floats.elems[f]), quad.c_str());
    }
  }

#undef OFFSET_OF
}

void SPARC64Arch::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {
  auto addr = llvm::Type::getIntNTy(module->getContext(), address_size);

  llvm::IRBuilder<> ir(&bb_func->getEntryBlock());
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

DecodingContext SPARC64Arch::CreateInitialContext(void) const {
  return DecodingContext({{kDecompileModeReg, 1u}});
}

OperandLifter::OpLifterPtr SPARC64Arch::DefaultLifter(
    const remill::IntrinsicTable &intrinsics_table) const {
  return std::make_shared<InstructionLifter>(this, intrinsics_table);
}

bool SPARC64Arch::DecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst,
                                    DecodingContext context) const {
  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
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

  if (!this->decoder.DecodeInstruction(address, inst_bytes, inst, context)) {
    return false;
  }
  sparc::CategorizeStructReturn(inst);
  return true;
}

Arch::ArchPtr Arch::GetSPARC64Sleigh(llvm::LLVMContext *context_,
                                     OSName os_name_, ArchName arch_name_) {
  return std::make_unique<SPARC64Arch>(context_, os_name_, arch_name_);
}

}  // namespace remill
