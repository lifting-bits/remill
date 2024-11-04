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
#include <remill/Arch/ArchBase.h>  // For `Arch` and `ArchImpl`.

#include "Decode.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

// clang-format off
#define ADDRESS_SIZE_BITS 64
#define INCLUDED_FROM_REMILL
#include "remill/Arch/SPARC64/Runtime/State.h"

// clang-format on

namespace remill {
namespace sparc {
namespace {
static const std::string_view kSPRegName = "sp";
static const std::string_view kPCRegName = "pc";
}  // namespace

class SPARC64Arch final : public DefaultContextAndLifter {
 public:
  SPARC64Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_),
        DefaultContextAndLifter(context_, os_name_, arch_name_) {}

  virtual ~SPARC64Arch(void) = default;

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void) const final {
    return kSPRegName;
  }

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void) const final {
    return kPCRegName;
  }

  uint64_t MinInstructionAlign(const DecodingContext &) const final {
    return 4;
  }

  uint64_t MinInstructionSize(const DecodingContext &) const final {
    return 4;
  }

  // Maximum number of bytes in an instruction.
  uint64_t MaxInstructionSize(const DecodingContext &,
                              bool permit_fuse_idioms) const final {
    return permit_fuse_idioms ? 8 : 4;  // To handle `SET` idioms.
  }

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final {
    return llvm::CallingConv::C;
  }

  // Populate the table of register information.
  void PopulateRegisterTable(void) const final;

  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override;

  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;

  // Decode an instruction.
  bool ArchDecodeInstruction(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst) const final;

  // Returns `true` if memory access are little endian byte ordered.
  bool MemoryAccessIsLittleEndian(void) const final {
    return false;
  }

  // Returns `true` if a given instruction might have a delay slot.
  bool MayHaveDelaySlot(const Instruction &inst) const final;

  // Returns `true` if we should lift the semantics of `next_inst` as a delay
  // slot of `inst`. The `branch_taken_path` tells us whether we are in the
  // context of the taken path of a branch or the not-taken path of a branch.
  virtual bool NextInstructionIsDelayed(const Instruction &inst,
                                        const Instruction &next_inst,
                                        bool branch_taken_path) const final;
};

// Populate the table of register information.
void SPARC64Arch::PopulateRegisterTable(void) const {

  reg_by_offset.resize(sizeof(SPARC64State));

#define OFFSET_OF(state, access) \
  (reinterpret_cast<uintptr_t>(&state.access) \
    - reinterpret_cast<uintptr_t>(&state))

#define REG(state, name, access, type) \
  AddRegister(#name, type, OFFSET_OF(state, access), nullptr)

#define SUB_REG(state, name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(state, access), #parent_reg_name)

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto u128 = llvm::Type::getInt128Ty(*context);
  auto f32 = llvm::Type::getFloatTy(*context);
  auto f64 = llvm::Type::getDoubleTy(*context);

  std::vector<llvm::Type *> window_types(33, u64);
  auto window_type = RegisterWindowType();
  auto window_ptr_type = llvm::PointerType::get(*context, 0);
  window_types.push_back(window_ptr_type);
  window_type->setBody(window_types, false);

  SPARC64State state;

  REG(state, pc, pc.qword, u64);
  SUB_REG(state, PC, pc.qword, u64, pc);

  REG(state, npc, next_pc.qword, u64);
  SUB_REG(state, NEXT_PC, next_pc.qword, u64, npc);

  REG(state, sp, gpr.o6.qword, u64);
  SUB_REG(state, SP, gpr.o6.qword, u64, sp);

  REG(state, fp, gpr.i6.qword, u64);
  SUB_REG(state, FP, gpr.i6.qword, u64, fp);

  REG(state, i0, gpr.i0.qword, u64);
  REG(state, i1, gpr.i1.qword, u64);
  REG(state, i2, gpr.i2.qword, u64);
  REG(state, i3, gpr.i3.qword, u64);
  REG(state, i4, gpr.i4.qword, u64);
  REG(state, i5, gpr.i5.qword, u64);
  SUB_REG(state, i6, gpr.i6.qword, u64, fp);
  REG(state, i7, gpr.i7.qword, u64);
  REG(state, l0, gpr.l0.qword, u64);
  REG(state, l1, gpr.l1.qword, u64);
  REG(state, l2, gpr.l2.qword, u64);
  REG(state, l3, gpr.l3.qword, u64);
  REG(state, l4, gpr.l4.qword, u64);
  REG(state, l5, gpr.l5.qword, u64);
  REG(state, l6, gpr.l6.qword, u64);
  REG(state, l7, gpr.l7.qword, u64);
  REG(state, o0, gpr.o0.qword, u64);
  REG(state, o1, gpr.o1.qword, u64);
  REG(state, o2, gpr.o2.qword, u64);
  REG(state, o3, gpr.o3.qword, u64);
  REG(state, o4, gpr.o4.qword, u64);
  REG(state, o5, gpr.o5.qword, u64);
  SUB_REG(state, o6, gpr.o6.qword, u64, sp);
  REG(state, o7, gpr.o7.qword, u64);

  REG(state, g1, gpr.g1.qword, u64);
  REG(state, g2, gpr.g2.qword, u64);
  REG(state, g3, gpr.g3.qword, u64);
  REG(state, g4, gpr.g4.qword, u64);
  REG(state, g5, gpr.g5.qword, u64);
  REG(state, g6, gpr.g6.qword, u64);
  REG(state, g7, gpr.g7.qword, u64);

  // Ancillary State Register
  REG(state, y, asr.yreg.qword, u64);
  REG(state, asi, asr.asi_flat, u64);
  REG(state, tick, asr.tick, u64);
  REG(state, fprs, asr.fprs_flat, u64);
  REG(state, gsr, asr.gsr.flat, u64);
  REG(state, softint, asr.softint, u64);
  REG(state, stick, asr.stick, u64);
  REG(state, stick_cmpr, asr.stick_cmpr, u64);
  REG(state, cfr, asr.cfr, u64);

  REG(state, icc_c, asr.ccr.icc.c, u8);
  REG(state, icc_v, asr.ccr.icc.v, u8);
  REG(state, icc_z, asr.ccr.icc.z, u8);
  REG(state, icc_n, asr.ccr.icc.n, u8);

  REG(state, xcc_c, asr.ccr.xcc.c, u8);
  REG(state, xcc_v, asr.ccr.xcc.v, u8);
  REG(state, xcc_z, asr.ccr.xcc.z, u8);
  REG(state, xcc_n, asr.ccr.xcc.n, u8);

  REG(state, ccf_fcc0, fsr.fcc0, u8);
  REG(state, ccf_fcc1, fsr.fcc1, u8);
  REG(state, ccf_fcc2, fsr.fcc2, u8);
  REG(state, ccf_fcc3, fsr.fcc3, u8);

  REG(state, ccc, csr.ccc, u8);

  REG(state, fsr_aexc, fsr.aexc, u8);
  REG(state, fsr_cexc, fsr.cexc, u8);

  REG(state, v0, fpreg.v[0], u128);
  REG(state, v1, fpreg.v[1], u128);
  REG(state, v2, fpreg.v[2], u128);
  REG(state, v3, fpreg.v[3], u128);
  REG(state, v4, fpreg.v[4], u128);
  REG(state, v5, fpreg.v[5], u128);
  REG(state, v6, fpreg.v[6], u128);
  REG(state, v7, fpreg.v[7], u128);
  REG(state, v8, fpreg.v[8], u128);
  REG(state, v9, fpreg.v[9], u128);
  REG(state, v10, fpreg.v[10], u128);
  REG(state, v11, fpreg.v[11], u128);
  REG(state, v12, fpreg.v[12], u128);
  REG(state, v13, fpreg.v[13], u128);
  REG(state, v14, fpreg.v[14], u128);
  REG(state, v15, fpreg.v[15], u128);

  SUB_REG(state, f0, fpreg.v[0].floats.elems[0], f32, v0);
  SUB_REG(state, f1, fpreg.v[0].floats.elems[1], f32, v0);
  SUB_REG(state, f2, fpreg.v[0].floats.elems[2], f32, v0);
  SUB_REG(state, f3, fpreg.v[0].floats.elems[3], f32, v0);
  SUB_REG(state, f4, fpreg.v[1].floats.elems[0], f32, v1);
  SUB_REG(state, f5, fpreg.v[1].floats.elems[1], f32, v1);
  SUB_REG(state, f6, fpreg.v[1].floats.elems[2], f32, v1);
  SUB_REG(state, f7, fpreg.v[1].floats.elems[3], f32, v1);
  SUB_REG(state, f8, fpreg.v[2].floats.elems[0], f32, v2);
  SUB_REG(state, f9, fpreg.v[2].floats.elems[1], f32, v2);
  SUB_REG(state, f10, fpreg.v[2].floats.elems[2], f32, v2);
  SUB_REG(state, f11, fpreg.v[2].floats.elems[3], f32, v2);
  SUB_REG(state, f12, fpreg.v[3].floats.elems[0], f32, v3);
  SUB_REG(state, f13, fpreg.v[3].floats.elems[1], f32, v3);
  SUB_REG(state, f14, fpreg.v[3].floats.elems[2], f32, v3);
  SUB_REG(state, f15, fpreg.v[3].floats.elems[3], f32, v3);
  SUB_REG(state, f16, fpreg.v[4].floats.elems[0], f32, v4);
  SUB_REG(state, f17, fpreg.v[4].floats.elems[1], f32, v4);
  SUB_REG(state, f18, fpreg.v[4].floats.elems[2], f32, v4);
  SUB_REG(state, f19, fpreg.v[4].floats.elems[3], f32, v4);
  SUB_REG(state, f20, fpreg.v[5].floats.elems[0], f32, v5);
  SUB_REG(state, f21, fpreg.v[5].floats.elems[1], f32, v5);
  SUB_REG(state, f22, fpreg.v[5].floats.elems[2], f32, v5);
  SUB_REG(state, f23, fpreg.v[5].floats.elems[3], f32, v5);
  SUB_REG(state, f24, fpreg.v[6].floats.elems[0], f32, v6);
  SUB_REG(state, f25, fpreg.v[6].floats.elems[1], f32, v6);
  SUB_REG(state, f26, fpreg.v[6].floats.elems[2], f32, v6);
  SUB_REG(state, f27, fpreg.v[6].floats.elems[3], f32, v6);
  SUB_REG(state, f28, fpreg.v[7].floats.elems[0], f32, v7);
  SUB_REG(state, f29, fpreg.v[7].floats.elems[1], f32, v7);
  SUB_REG(state, f30, fpreg.v[7].floats.elems[2], f32, v7);
  SUB_REG(state, f31, fpreg.v[7].floats.elems[3], f32, v7);
  SUB_REG(state, f32, fpreg.v[8].floats.elems[0], f32, v8);
  SUB_REG(state, f33, fpreg.v[8].floats.elems[1], f32, v8);
  SUB_REG(state, f34, fpreg.v[8].floats.elems[2], f32, v8);
  SUB_REG(state, f35, fpreg.v[8].floats.elems[3], f32, v8);
  SUB_REG(state, f36, fpreg.v[9].floats.elems[0], f32, v9);
  SUB_REG(state, f37, fpreg.v[9].floats.elems[1], f32, v9);
  SUB_REG(state, f38, fpreg.v[9].floats.elems[2], f32, v9);
  SUB_REG(state, f39, fpreg.v[9].floats.elems[3], f32, v9);
  SUB_REG(state, f40, fpreg.v[10].floats.elems[0], f32, v10);
  SUB_REG(state, f41, fpreg.v[10].floats.elems[1], f32, v10);
  SUB_REG(state, f42, fpreg.v[10].floats.elems[2], f32, v10);
  SUB_REG(state, f43, fpreg.v[10].floats.elems[3], f32, v10);
  SUB_REG(state, f44, fpreg.v[11].floats.elems[0], f32, v11);
  SUB_REG(state, f45, fpreg.v[11].floats.elems[1], f32, v11);
  SUB_REG(state, f46, fpreg.v[11].floats.elems[2], f32, v11);
  SUB_REG(state, f47, fpreg.v[11].floats.elems[3], f32, v11);
  SUB_REG(state, f48, fpreg.v[12].floats.elems[0], f32, v12);
  SUB_REG(state, f49, fpreg.v[12].floats.elems[1], f32, v12);
  SUB_REG(state, f50, fpreg.v[12].floats.elems[2], f32, v12);
  SUB_REG(state, f51, fpreg.v[12].floats.elems[3], f32, v12);
  SUB_REG(state, f52, fpreg.v[13].floats.elems[0], f32, v13);
  SUB_REG(state, f53, fpreg.v[13].floats.elems[1], f32, v13);
  SUB_REG(state, f54, fpreg.v[13].floats.elems[2], f32, v13);
  SUB_REG(state, f55, fpreg.v[13].floats.elems[3], f32, v13);
  SUB_REG(state, f56, fpreg.v[14].floats.elems[0], f32, v14);
  SUB_REG(state, f57, fpreg.v[14].floats.elems[1], f32, v14);
  SUB_REG(state, f58, fpreg.v[14].floats.elems[2], f32, v14);
  SUB_REG(state, f59, fpreg.v[14].floats.elems[3], f32, v14);
  SUB_REG(state, f60, fpreg.v[15].floats.elems[0], f32, v15);
  SUB_REG(state, f61, fpreg.v[15].floats.elems[1], f32, v15);
  SUB_REG(state, f62, fpreg.v[15].floats.elems[2], f32, v15);
  SUB_REG(state, f63, fpreg.v[15].floats.elems[3], f32, v15);

  SUB_REG(state, d0, fpreg.v[0].doubles.elems[0], f64, v0);
  SUB_REG(state, d2, fpreg.v[0].doubles.elems[1], f64, v0);
  SUB_REG(state, d4, fpreg.v[1].doubles.elems[0], f64, v1);
  SUB_REG(state, d6, fpreg.v[1].doubles.elems[1], f64, v1);
  SUB_REG(state, d8, fpreg.v[2].doubles.elems[0], f64, v2);
  SUB_REG(state, d10, fpreg.v[2].doubles.elems[1], f64, v2);
  SUB_REG(state, d12, fpreg.v[3].doubles.elems[0], f64, v3);
  SUB_REG(state, d14, fpreg.v[3].doubles.elems[1], f64, v3);
  SUB_REG(state, d16, fpreg.v[4].doubles.elems[0], f64, v4);
  SUB_REG(state, d18, fpreg.v[4].doubles.elems[1], f64, v4);
  SUB_REG(state, d20, fpreg.v[5].doubles.elems[0], f64, v5);
  SUB_REG(state, d22, fpreg.v[5].doubles.elems[1], f64, v5);
  SUB_REG(state, d24, fpreg.v[6].doubles.elems[0], f64, v6);
  SUB_REG(state, d26, fpreg.v[6].doubles.elems[1], f64, v6);
  SUB_REG(state, d28, fpreg.v[7].doubles.elems[0], f64, v7);
  SUB_REG(state, d30, fpreg.v[7].doubles.elems[1], f64, v7);
  SUB_REG(state, d32, fpreg.v[8].doubles.elems[0], f64, v8);
  SUB_REG(state, d34, fpreg.v[8].doubles.elems[1], f64, v8);
  SUB_REG(state, d36, fpreg.v[9].doubles.elems[0], f64, v9);
  SUB_REG(state, d38, fpreg.v[9].doubles.elems[1], f64, v9);
  SUB_REG(state, d40, fpreg.v[10].doubles.elems[0], f64, v10);
  SUB_REG(state, d42, fpreg.v[10].doubles.elems[1], f64, v10);
  SUB_REG(state, d44, fpreg.v[11].doubles.elems[0], f64, v11);
  SUB_REG(state, d46, fpreg.v[11].doubles.elems[1], f64, v11);
  SUB_REG(state, d48, fpreg.v[12].doubles.elems[0], f64, v12);
  SUB_REG(state, d50, fpreg.v[12].doubles.elems[1], f64, v12);
  SUB_REG(state, d52, fpreg.v[13].doubles.elems[0], f64, v13);
  SUB_REG(state, d54, fpreg.v[13].doubles.elems[1], f64, v13);
  SUB_REG(state, d56, fpreg.v[14].doubles.elems[0], f64, v14);
  SUB_REG(state, d58, fpreg.v[14].doubles.elems[1], f64, v14);
  SUB_REG(state, d60, fpreg.v[15].doubles.elems[0], f64, v15);
  SUB_REG(state, d62, fpreg.v[15].doubles.elems[1], f64, v15);

  // NOTE(pag): This is a bit of a lie, but kind of like in x87 with 80-bit
  //            extended precision, we treat quad precision floats as being
  //            doubles.
  SUB_REG(state, q0, fpreg.v[0].doubles.elems[0], f64, v0);
  SUB_REG(state, q4, fpreg.v[1].doubles.elems[0], f64, v1);
  SUB_REG(state, q8, fpreg.v[2].doubles.elems[0], f64, v2);
  SUB_REG(state, q12, fpreg.v[3].doubles.elems[0], f64, v3);
  SUB_REG(state, q16, fpreg.v[4].doubles.elems[0], f64, v4);
  SUB_REG(state, q20, fpreg.v[5].doubles.elems[0], f64, v5);
  SUB_REG(state, q24, fpreg.v[6].doubles.elems[0], f64, v6);
  SUB_REG(state, q28, fpreg.v[7].doubles.elems[0], f64, v7);
  SUB_REG(state, q32, fpreg.v[8].doubles.elems[0], f64, v8);
  SUB_REG(state, q36, fpreg.v[9].doubles.elems[0], f64, v9);
  SUB_REG(state, q40, fpreg.v[10].doubles.elems[0], f64, v10);
  SUB_REG(state, q44, fpreg.v[11].doubles.elems[0], f64, v11);
  SUB_REG(state, q48, fpreg.v[12].doubles.elems[0], f64, v12);
  SUB_REG(state, q52, fpreg.v[13].doubles.elems[0], f64, v13);
  SUB_REG(state, q56, fpreg.v[14].doubles.elems[0], f64, v14);
  SUB_REG(state, q60, fpreg.v[15].doubles.elems[0], f64, v15);

  REG(state, PREV_WINDOW_LINK, window, window_ptr_type);
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void SPARC64Arch::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {

  auto &context = module->getContext();
  auto u8 = llvm::Type::getInt8Ty(context);
  auto u32 = llvm::Type::getInt32Ty(context);
  auto u64 = llvm::Type::getInt64Ty(context);

  auto zero_u8 = llvm::Constant::getNullValue(u8);
  auto zero_u32 = llvm::Constant::getNullValue(u32);
  auto zero_u64 = llvm::Constant::getNullValue(u64);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "g0"), false);
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "ignore_write_to_g0"),
                 false);

  // this is for unknown asr to avoid crash.
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "asr"), false);

  // NOTE(pag): Passing `nullptr` as the type will force `Arch::AddRegister`
  //            to infer the type based on what it finds. It's a pointer to
  //            a structure type, so we can check that.
  const auto prev_window_link = this->RegisterByName("PREV_WINDOW_LINK");
  CHECK(prev_window_link->type->isPointerTy());
  const auto window_type = RegisterWindowType();
  CHECK(window_type->isStructTy());

  auto window = ir.CreateAlloca(window_type, nullptr, "WINDOW");
  ir.CreateAlloca(prev_window_link->type, nullptr, "PREV_WINDOW");

  // `WINDOW_LINK = &(WINDOW->prev_window);`
  llvm::Value *gep_indexes[2] = {zero_u32, llvm::ConstantInt::get(u32, 33)};
  auto window_link =
      ir.CreateInBoundsGEP(window_type, window, gep_indexes, "WINDOW_LINK");
  auto nullptr_window = llvm::Constant::getNullValue(prev_window_link->type);
  ir.CreateStore(nullptr_window, window_link, false);

  ir.CreateStore(zero_u8, ir.CreateAlloca(u8, nullptr, "IGNORE_BRANCH_TAKEN"),
                 false);
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "IGNORE_PC"), false);
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "IGNORE_NEXT_PC"),
                 false);
  ir.CreateStore(zero_u64, ir.CreateAlloca(u64, nullptr, "IGNORE_RETURN_PC"),
                 false);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  (void) RegisterByName(kNextPCVariableName)->AddressOf(state_ptr_arg, ir);

  ir.CreateStore(pc_arg,
                 RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir),
                 false);
}

llvm::Triple SPARC64Arch::Triple(void) const {
  auto triple = BasicTriple();
  triple.setArch(llvm::Triple::sparcv9);
  return triple;
}

llvm::DataLayout SPARC64Arch::DataLayout(void) const {
  return llvm::DataLayout("E-m:e-i64:64-n32:64-S128");
}

// Returns `true` if a given instruction might have a delay slot.
bool SPARC64Arch::MayHaveDelaySlot(const Instruction &inst) const {
  return inst.has_branch_taken_delay_slot ||
         inst.has_branch_not_taken_delay_slot;
}

// Returns `true` if we should lift the semantics of `next_inst` as a delay
// slot of `inst`. The `branch_taken_path` tells us whether we are in the
// context of the taken path of a branch or the not-taken path of a branch.
bool SPARC64Arch::NextInstructionIsDelayed(const Instruction &inst,
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

// Decode an instruction.
bool SPARC64Arch::ArchDecodeInstruction(uint64_t address,
                                        std::string_view inst_bytes,
                                        Instruction &inst) const {

  inst.pc = address;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.branch_taken_arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;

  if (address % 4) {
    return false;
  }

  if (inst_bytes.size() != 4 && inst_bytes.size() != 8) {
    return false;
  }

  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    inst.bytes.resize(inst_bytes.size());
  } else {
    inst.bytes = inst_bytes;
  }

  if (!sparc64::TryDecode(inst)) {
    inst.category = Instruction::kCategoryInvalid;
    inst.operands.clear();
    LOG(ERROR) << "Unable to decode: " << inst.Serialize();
    return false;
  }

  return inst.IsValid();
}

}  // namespace sparc

Arch::ArchPtr Arch::GetSPARC64(llvm::LLVMContext *context_, OSName os_name_,
                               ArchName arch_name_) {
  if (arch_name_ == kArchSparc64) {
    return std::make_unique<sparc::SPARC64Arch>(context_, os_name_, arch_name_);

  } else {
    LOG(FATAL) << "Invalid arch name passed to Arch::GetSPARC::"
               << GetArchName(arch_name_);
    return {};
  }
}

}  // namespace remill
