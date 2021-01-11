/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

// clang-format off
#define ADDRESS_SIZE_BITS 16
#define INCLUDED_FROM_REMILL
#include "remill/Arch/MSP430/Runtime/State.h"
// clang-format on

namespace remill {
namespace msp430 {
namespace {
static const std::string_view kSPRegName = "R1";
static const std::string_view kPCRegName = "R0";
}  // namespace

class MSP430Arch final : public Arch {
 public:
  MSP430Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
      : Arch(context_, os_name_, arch_name_) {}

  virtual ~MSP430Arch(void) = default;

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void) const final {
    return kSPRegName;
  }

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void) const final {
    return kPCRegName;
  }

  // Maximum number of bytes in an instruction.
  uint64_t MaxInstructionSize(void) const final {
    return 6;
  }

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final {
    return llvm::CallingConv::C;
  }

  // Populate the `__remill_basic_block` function with variables.
  void PopulateBasicBlockFunction(llvm::Module *module,
                                  llvm::Function *bb_func) const override;

  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;

  // Decode an instruction.
  bool DecodeInstruction(
      uint64_t address, std::string_view instr_bytes,
      Instruction &inst) const final;

  // Returns `true` if memory access are little endian byte ordered.
  bool MemoryAccessIsLittleEndian(void) const final {
    return true;
  }

  // Returns `true` if a given instruction might have a delay slot.
  bool MayHaveDelaySlot(const Instruction &) const final {
    return false;
  }

  // Returns `true` if we should lift the semantics of `next_inst` as a delay
  // slot of `inst`. The `branch_taken_path` tells us whether we are in the
  // context of the taken path of a branch or the not-taken path of a branch.
  virtual bool NextInstructionIsDelayed(const Instruction &,
                                        const Instruction &,
                                        bool) const final {
    return false;
  }
};

// Populate the `__remill_basic_block` function with variables.
void MSP430Arch::PopulateBasicBlockFunction(llvm::Module *module,
                                             llvm::Function *bb_func) const {

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(MSP430State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(MSP430State, access), #parent_reg_name)

  auto &context = module->getContext();
  auto u8 = llvm::Type::getInt8Ty(context);
  auto u16 = llvm::Type::getInt16Ty(context);
  auto zero_u16 = llvm::Constant::getNullValue(u16);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);


  REG(r0, gpr.r0.word, u16);
  SUB_REG(PC, gpr.r0.word, u16, r0);

  REG(r1, gpr.r1.word, u16);
  SUB_REG(SP, gpr.r1.word, u16, r1);

  REG(r2, gpr.r2.word, u16);
  SUB_REG(SR, gpr.r2.word, u16, sr);

  // NOTE(pag): `r3` is hardwired zero.
  ir.CreateStore(zero_u16, ir.CreateAlloca(u16, nullptr, "r3"));
  ir.CreateAlloca(u16, nullptr, "ignore_write_to_r3");

  REG(r4, gpr.r4.word, u16);
  REG(r5, gpr.r5.word, u16);
  REG(r6, gpr.r6.word, u16);
  REG(r7, gpr.r7.word, u16);
  REG(r8, gpr.r8.word, u16);
  REG(r9, gpr.r9.word, u16);
  REG(r10, gpr.r10.word, u16);
  REG(r11, gpr.r11.word, u16);
  REG(r12, gpr.r12.word, u16);
  REG(r13, gpr.r13.word, u16);
  REG(r14, gpr.r14.word, u16);
  REG(r15, gpr.r15.word, u16);

  REG(n, nzcv.n, u8);
  REG(z, nzcv.z, u8);
  REG(c, nzcv.c, u8);
  REG(v, nzcv.v, u8);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);

  ir.CreateStore(pc_arg, ir.CreateAlloca(u16, nullptr, "NEXT_PC"));
  ir.CreateStore(
      pc_arg, RegisterByName(kPCVariableName)->AddressOf(state_ptr_arg, ir),
      false);
}

llvm::Triple MSP430Arch::Triple(void) const {
  auto triple = BasicTriple();
  triple.setArch(llvm::Triple::msp430);
  return triple;
}

llvm::DataLayout MSP430Arch::DataLayout(void) const {
  return llvm::DataLayout("e-m:e-p:16:16-i32:16-i64:16-f32:16-f64:16-a:8-n8:16-S16");
}

union InstFormat {
  uint16_t flat;
  struct Format0 {
    uint16_t dest_reg:4;
    uint16_t ad:2;
    uint16_t bw:1;
    uint16_t opcode:3;
    uint16_t must_be_0b000100:6;
  } __attribute__((packed)) f0;

  struct Format1 {
    int16_t pc_offset:10;
    uint16_t cond:3;
    uint16_t must_be_0b001:3;
  } __attribute__((packed)) f1;

  struct Format2 {
    uint16_t dest_reg:4;
    uint16_t as:2;
    uint16_t bw:1;
    uint16_t ad:1;
    uint16_t src_reg:4;
    uint16_t opcode:4;
  } __attribute__((packed)) f2;
} __attribute__((packed));


static_assert(sizeof(InstFormat) == 2);

static const std::string_view kReadIntRegName[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

static const std::string_view kWriteIntRegName[] = {
  "r0", "r1", "r2", "ignore_write_to_r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

// Indexed by the bits `opcode:bw`.
static const std::string_view kFormat0OpName[] = {
    "RRC",
    "RRCB",
    "SWPB",  // NOTE(pag): No distinction between byte/word form.
    "SWPB",  // NOTE(pag): No distinction between byte/word form.
    "RRA",
    "RRAB",
    "SXT",  // NOTE(pag): No distinction between byte/word form.
    "SXT",  // NOTE(pag): No distinction between byte/word form.
    "PUSH",
    "PUSHB",
    "CALL",  // NOTE(pag): No distinction between byte/word form.
    "CALL",  // NOTE(pag): No distinction between byte/word form.
    "RETI",  // NOTE(pag): No distinction between byte/word form.
    "RETI",  // NOTE(pag): No distinction between byte/word form.
    {},  // `0b111` is unused.
    {},  // `0b111` is unused.
};

// Add two fake operands for consistency of register writeback.
static void NoWriteBack(Instruction &inst) {
  inst.operands.emplace_back();
  auto &reg_update_op = inst.operands.back();
  reg_update_op.action = Operand::kActionWrite;
  reg_update_op.type = Operand::kTypeRegister;
  reg_update_op.size = 16u;
  reg_update_op.reg.name = kWriteIntRegName[3];
  reg_update_op.reg.size = 16u;

  inst.operands.emplace_back();
  auto &new_reg_val_op = inst.operands.back();
  new_reg_val_op.action = Operand::kActionRead;
  new_reg_val_op.type = Operand::kTypeImmediate;
  new_reg_val_op.size = 16u;
  new_reg_val_op.imm.is_signed = false;
  new_reg_val_op.imm.val = 0;
}

// Add the linear next program counter. The idea here is that the extended
// operands to MSP430 instructions are really double-indirections and more
// like pseudo operands.
static void AddNextPC(Instruction &inst) {
  inst.operands.emplace_back();
  auto &new_mem_addr_op = inst.operands.back();
  new_mem_addr_op.addr.kind = Operand::Address::kAddressCalculation;
  new_mem_addr_op.type = Operand::kTypeAddress;
  new_mem_addr_op.size = 16;
  new_mem_addr_op.action = Operand::kActionRead;
  new_mem_addr_op.addr.address_size = 16u;
  new_mem_addr_op.addr.base_reg.name = kReadIntRegName[0];
  new_mem_addr_op.addr.base_reg.size = 16u;
  new_mem_addr_op.addr.displacement = inst.next_pc - inst.pc;
}

// Direct read or write of a register, no writeback. We don't bother with
// specifying `8` or `16` bits for operand size here because we'll have a
// size-specific to handle that.
static void AddDirectRegisterOp(Instruction &inst, Operand::Action action,
                                unsigned reg_num, bool can_writeback) {
  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeRegister;
  op.size = 16;
  op.action = action;
  if (Operand::kActionRead == action) {
    inst.function += "_R";
    if (reg_num == 3u) {
      op.type = Operand::kTypeImmediate;
      op.imm.is_signed = false;
      op.imm.val = 0;
    } else {
      op.reg.name = kReadIntRegName[reg_num];
      op.reg.size = 16;
    }
  } else {
    inst.function += "_Rw";
    op.reg.name = kWriteIntRegName[reg_num];
    op.reg.size = 16;
  }

  if (can_writeback) {
    NoWriteBack(inst);
  }
}

// Direct read of a short immediate operand embedded in the instruction.
// No writeback.
static bool TryAddShortImmOp(Instruction &inst, Operand::Action action,
                             uint64_t val, bool can_writeback,
                             bool is_signed=false) {
  if (Operand::kActionRead != action) {
    return false;
  }

  inst.operands.emplace_back();
  auto &op = inst.operands.back();
  op.type = Operand::kTypeImmediate;
  op.size = 16;  // Let a byte-specific SEM interpret it otherwise.
  op.action = Operand::kActionRead;
  op.imm.is_signed = is_signed;
  op.imm.val = val;

  if (can_writeback) {
    NoWriteBack(inst);
  }
  return false;
}

static bool TryAddAbsAddressOp(Instruction &inst, Operand::Action action,
                               unsigned access_size, bool can_writeback) {

  // Make sure we can read the bytes.
  auto offset = inst.next_pc - inst.pc;
  inst.next_pc += 2u;
  if (inst.bytes.size() < (inst.next_pc - inst.pc)) {
    return false;
  }

  // Calculate the address.
  uint16_t addr = inst.bytes[offset++];
  addr |= static_cast<uint16_t>(inst.bytes[offset]) << 8u;

  inst.operands.emplace_back();
  auto &mem_addr_op = inst.operands.back();

  inst.function += "_M";
  if (access_size == 8) {
    inst.function += "8";
  } else {
    inst.function += "16";
  }

  if (Operand::kActionWrite == action) {
    mem_addr_op.addr.kind = Operand::Address::kMemoryWrite;
    inst.function += "w";
  } else {
    mem_addr_op.addr.kind = Operand::Address::kMemoryRead;
  }

  mem_addr_op.type = Operand::kTypeAddress;
  mem_addr_op.size = access_size;
  mem_addr_op.action = action;
  mem_addr_op.addr.address_size = 16;
  mem_addr_op.addr.displacement = static_cast<int64_t>(static_cast<uint32_t>(addr));

  if (can_writeback) {
    NoWriteBack(inst);
  }
  return true;
}

// Try to add an operand like `x(Rn)`.
static bool TryAddIndexedAddressOp(Instruction &inst, Operand::Action action,
                                   unsigned reg_num, unsigned access_size,
                                   bool can_writeback) {
  // Make sure we can read the bytes.
  auto offset = inst.next_pc - inst.pc;
  inst.next_pc += 2u;
  if (inst.bytes.size() < (inst.next_pc - inst.pc)) {
    return false;
  }

  // Calculate the index.
  uint16_t udisp = inst.bytes[offset++];
  udisp |= static_cast<uint16_t>(inst.bytes[offset]) << 8u;

  inst.operands.emplace_back();
  auto &mem_addr_op = inst.operands.back();

  inst.function += "_M";
  if (access_size == 8) {
    inst.function += "8";
  } else {
    inst.function += "16";
  }

  if (Operand::kActionWrite == action) {
    mem_addr_op.addr.kind = Operand::Address::kMemoryWrite;
    inst.function += "w";
  } else {
    mem_addr_op.addr.kind = Operand::Address::kMemoryRead;
  }

  mem_addr_op.type = Operand::kTypeAddress;
  mem_addr_op.size = access_size;
  mem_addr_op.action = action;
  mem_addr_op.addr.address_size = 16u;
  mem_addr_op.addr.base_reg.name = kReadIntRegName[reg_num];
  mem_addr_op.addr.base_reg.size = 16u;
  mem_addr_op.addr.displacement =
      static_cast<int64_t>(static_cast<int16_t>(udisp));

  if (can_writeback) {
    NoWriteBack(inst);
  }

  return true;
}

// Try to add an operand like `@Rn`.
static void AddRegIndirectMemOp(Instruction &inst, Operand::Action action,
                                unsigned reg_num, unsigned access_size,
                                bool can_writeback) {

  inst.operands.emplace_back();
  auto &mem_addr_op = inst.operands.back();

  inst.function += "_M";
  if (access_size == 8) {
    inst.function += "8";
  } else {
    inst.function += "16";
  }

  if (Operand::kActionWrite == action) {
    mem_addr_op.addr.kind = Operand::Address::kMemoryWrite;
    inst.function += "w";
  } else {
    mem_addr_op.addr.kind = Operand::Address::kMemoryRead;
  }

  mem_addr_op.type = Operand::kTypeAddress;
  mem_addr_op.size = access_size;
  mem_addr_op.action = action;
  mem_addr_op.addr.address_size = 16u;
  mem_addr_op.addr.base_reg.name = kReadIntRegName[reg_num];
  mem_addr_op.addr.base_reg.size = 16u;
  mem_addr_op.addr.displacement = 0;

  if (can_writeback) {
    NoWriteBack(inst);
  }
}

// Try to add an operand like `@Rn+`.
static void AddPostIncrementRegIndirectMemOp(Instruction &inst,
                                             Operand::Action action,
                                             unsigned reg_num,
                                             unsigned access_size,
                                             bool can_writeback) {

  inst.operands.emplace_back();
  auto &mem_addr_op = inst.operands.back();

  inst.function += "_M";
  if (access_size == 8) {
    inst.function += "8";
  } else {
    inst.function += "16";
  }

  if (Operand::kActionWrite == action) {
    mem_addr_op.addr.kind = Operand::Address::kMemoryWrite;
    inst.function += "w";
  } else {
    mem_addr_op.addr.kind = Operand::Address::kMemoryRead;
  }

  mem_addr_op.type = Operand::kTypeAddress;
  mem_addr_op.size = access_size;
  mem_addr_op.action = action;
  mem_addr_op.addr.address_size = 16u;
  mem_addr_op.addr.base_reg.name = kReadIntRegName[reg_num];
  mem_addr_op.addr.base_reg.size = 16u;
  mem_addr_op.addr.displacement = 0;

  if (can_writeback) {
    inst.operands.emplace_back();
    auto &reg_update_op = inst.operands.back();
    reg_update_op.action = Operand::kActionWrite;
    reg_update_op.type = Operand::kTypeRegister;
    reg_update_op.size = 16u;
    reg_update_op.reg.name = kWriteIntRegName[reg_num];
    reg_update_op.reg.size = 16u;

    inst.operands.emplace_back();
    auto &new_mem_addr_op = inst.operands.back();
    new_mem_addr_op.addr.kind = Operand::Address::kAddressCalculation;
    new_mem_addr_op.type = Operand::kTypeAddress;
    new_mem_addr_op.size = access_size;
    new_mem_addr_op.action = Operand::kActionRead;
    new_mem_addr_op.addr.address_size = 16u;
    new_mem_addr_op.addr.base_reg.name = kReadIntRegName[reg_num];
    new_mem_addr_op.addr.base_reg.size = 16u;
    new_mem_addr_op.addr.displacement = access_size / 8u;
  }
}

// All operands, are decoded as either register operands or memory operands,
// even if some of the register operands are technically constants. Each
// logical operand to an instruction generates three operands to a Remill
// semantic: an operand containing the value to use, and operand containing
// a register to update on a write-back operand, and a register containing
// the value to write-back.
static bool TryDecodeOperand(Instruction &inst, Operand::Action action,
                             uint16_t addressing_mode, uint16_t reg_num,
                             unsigned access_size, bool can_writeback) {

  if (2 == reg_num) {
    switch (addressing_mode & 0b11u) {
      case 0b00u:
        AddDirectRegisterOp(inst, action, reg_num, can_writeback);
        return true;
      case 0b01u:
        return TryAddAbsAddressOp(inst, action, access_size, can_writeback);
      case 0b10u:
        return TryAddShortImmOp(inst, action, 4u, can_writeback);
      case 0b11u:
        return TryAddShortImmOp(inst, action, 8u, can_writeback);
    }
  } else if (3 == reg_num) {
    switch (addressing_mode & 0b11u) {
      case 0b00u:
        return TryAddShortImmOp(inst, action, 0u, can_writeback);
      case 0b01u:
        return TryAddShortImmOp(inst, action, 1u, can_writeback);
      case 0b10u:
        return TryAddShortImmOp(inst, action, 2u, can_writeback);
      case 0b11u:
        return TryAddShortImmOp(
            inst, action, static_cast<uint64_t>(static_cast<int64_t>(-1)),
            can_writeback, true);
    }
  } else {
    // Only the register direct and indexed register addressing modes are
    // supported for destination operands.
    if (action == Operand::kActionWrite && (addressing_mode & 0b10) != 0u) {
      return false;
    }

    switch (addressing_mode & 0b11u) {
      case 0b00u:
        AddDirectRegisterOp(inst, action, reg_num, can_writeback);
        return true;
      case 0b01u:
        return TryAddIndexedAddressOp(inst, action, reg_num, access_size,
                                      can_writeback);
      case 0b10u:
        AddRegIndirectMemOp(inst, action, reg_num, access_size, can_writeback);
        return true;
      case 0b11u:
        AddPostIncrementRegIndirectMemOp(inst, action, reg_num, access_size,
                                         can_writeback);
        return true;
    }
  }
  return false;
}

static bool TryDecodeRRC(remill::Instruction &inst,
                         InstFormat::Format0 native) {
  if (!TryDecodeOperand(inst, Operand::kActionWrite, native.ad,
                        native.dest_reg, native.bw ? 8u : 16u, true)) {
    return false;
  }
  AddNextPC(inst);
  return true;
}

static bool TryDecodeSWP(remill::Instruction &inst,
                         InstFormat::Format0 native) {
  if (!TryDecodeOperand(inst, Operand::kActionWrite, native.ad,
                        native.dest_reg, 16u, true)) {
    return false;
  }
  AddNextPC(inst);
  return true;
}

static bool TryDecodeRRA(remill::Instruction &inst,
                         InstFormat::Format0 native) {
  if (!TryDecodeOperand(inst, Operand::kActionWrite, native.ad,
                        native.dest_reg, native.bw ? 8u : 16u, true)) {
    return false;
  }
  AddNextPC(inst);
  return true;
}

static bool TryDecodeSXT(remill::Instruction &inst,
                         InstFormat::Format0 native) {
  if (!TryDecodeOperand(inst, Operand::kActionWrite, native.ad,
                        native.dest_reg, 16u, true)) {
    return false;
  }
  AddNextPC(inst);
  return true;
}

static bool TryDecodePUSH(remill::Instruction &inst,
                          InstFormat::Format0 native) {
  // CPU BUG: PUSH #4 and PUSH #8 do not work when the short encoding
  // using @r2 and @r2+ is used.
  if (native.dest_reg == 2 && (native.ad == 0b10u || native.ad == 0b11u)) {
    return false;
  }
  if (!TryDecodeOperand(inst, Operand::kActionWrite, native.ad,
                        native.dest_reg, native.bw ? 8u : 16u, true)) {
    return false;
  }
  AddNextPC(inst);
  return true;
}

static bool TryDecodeCALL(remill::Instruction &inst,
                          InstFormat::Format0 native) {
  return false;
}

static bool TryDecodeRETI(remill::Instruction &inst,
                          InstFormat::Format0 native) {
  return false;
}

static bool TryDecodeInvalidFormat0(remill::Instruction &,
                                    InstFormat::Format0 ) {
  return false;
}

static bool (*kFormat0Decoders[])(remill::Instruction &,
                                  InstFormat::Format0) = {
  TryDecodeRRC,
  TryDecodeSWP,
  TryDecodeRRA,
  TryDecodeSXT,
  TryDecodePUSH,
  TryDecodeCALL,
  TryDecodeRETI,
  TryDecodeInvalidFormat0
};

static bool TryDecodeFormat0(remill::Instruction &inst,
                             InstFormat::Format0 native) {
  auto op_name = kFormat0OpName[(native.opcode << 1u) | native.bw];
  if (op_name.empty()) {
    return false;
  }

  inst.function = op_name;
  return kFormat0Decoders[native.opcode](inst, native);
}

static bool TryDecodeFormat1(remill::Instruction &inst,
                             InstFormat::Format1 native) {
  return false;
}

static bool TryDecodeFormat2(remill::Instruction &inst,
                             InstFormat::Format2 native) {
  return false;
}

// Decode an instruction.
bool MSP430Arch::DecodeInstruction(
    uint64_t address, std::string_view inst_bytes, Instruction &inst) const {

  inst.pc = address;
  inst.arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;

  // We use `inst.next_pc` as a sort of accumulator to track what pseudo
  // operands will be implicitly "jumped over" by this instruction. E.g.
  // adding an operand that does `@r0+` will increment `inst.next_pc`.
  inst.next_pc = inst.pc + 2u;

  // The instruction address must be even.
  if (address & 1u) {
    return false;
  }

  // All instructions are two bytes. Some instructions refer to operands that
  // are embedded in memory beside the instruction itself, and so adjacent
  // constants are a form of pseudo operand.
  if (inst_bytes.size() != 2 && inst_bytes.size() != 4 &&
      inst_bytes.size() != 6) {
    return false;
  }

  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    inst.bytes.resize(inst_bytes.size());
  } else {
    inst.bytes = inst_bytes;
  }

  InstFormat format = {};
  format.flat = static_cast<uint16_t>(inst.bytes[0]);
  format.flat |= static_cast<uint16_t>(inst.bytes[1]) << 8u;

  auto ret = false;
  if (format.f0.must_be_0b000100 == 0b000100u) {
    ret = TryDecodeFormat0(inst, format.f0);

  } else if (format.f1.must_be_0b001 == 0b001u) {
    ret = TryDecodeFormat1(inst, format.f1);

  } else {
    ret = TryDecodeFormat2(inst, format.f2);
  }

  if (!ret) {
    inst.category = Instruction::kCategoryInvalid;
    inst.operands.clear();
    LOG(ERROR)
        << "Unable to decode: " << inst.Serialize();
    return false;
  }

  return inst.IsValid();
}

} // namespace msp430

Arch::ArchPtr Arch::GetMSP430(
    llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_) {
  if (arch_name_ == kArchMSP430) {
    return std::make_unique<msp430::MSP430Arch>(context_, os_name_, arch_name_);

  } else {
    LOG(FATAL)
        << "Invalid arch name passed to Arch::GetMSP430::"
        << GetArchName(arch_name_);
    return {};
  }
}

} // namespace remill
