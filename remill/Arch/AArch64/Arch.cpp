/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/AArch64/Decode.h"
#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace {

//template <uint32_t from_high, uint32_t to_low>
//static inline uint32_t Extract(uint32_t inst) {
//  auto num_bits = (from_high - to_low) + 1U;
//  return (inst >> to_low) & ((1U << num_bits) - 1U);
//}

template <uint32_t bit, typename T>
static inline T Select(T val) {
  return (val >> bit) & T(1);
}

Instruction::Category InstCategory(const aarch64::InstData &inst) {
  switch (inst.iclass) {
    case aarch64::InstName::INVALID:
      return Instruction::kCategoryInvalid;

    // TODO(pag): B.cond.
    case aarch64::InstName::B:
      if (aarch64::InstForm::B_ONLY_CONDBRANCH == inst.iform) {
        return Instruction::kCategoryConditionalBranch;
      } else {
        return Instruction::kCategoryDirectJump;
      }

    case aarch64::InstName::BR:
      return Instruction::kCategoryIndirectJump;

    case aarch64::InstName::CBZ:
    case aarch64::InstName::CBNZ:
    case aarch64::InstName::TBZ:
    case aarch64::InstName::TBNZ:
      return Instruction::kCategoryConditionalBranch;

    case aarch64::InstName::BL:
      return Instruction::kCategoryDirectFunctionCall;

    case aarch64::InstName::BLR:
      return Instruction::kCategoryIndirectFunctionCall;

    case aarch64::InstName::RET:
      return Instruction::kCategoryFunctionReturn;

    case aarch64::InstName::HLT:
      return Instruction::kCategoryError;

    case aarch64::InstName::HVC:
    case aarch64::InstName::SMC:
    case aarch64::InstName::SVC:
    case aarch64::InstName::SYS:  // Has aliases `IC`, `DC`, `AT`, and `TLBI`.
    case aarch64::InstName::SYSL:
      return Instruction::kCategoryAsyncHyperCall;

    case aarch64::InstName::NOP:
      return Instruction::kCategoryNoOp;

    // Note: These are implemented with synchronous hyper calls.
    case aarch64::InstName::BRK:
      return Instruction::kCategoryNormal;

    default:
      return Instruction::kCategoryNormal;
  }
}

class AArch64Arch : public Arch {
 public:
  AArch64Arch(OSName os_name_, ArchName arch_name_);

  virtual ~AArch64Arch(void);

  void PrepareModule(llvm::Module *mod) const override;

  // Decode an instruction.
  bool DecodeInstruction(
      uint64_t address, const std::string &instr_bytes,
      Instruction &inst) const override;

 private:
  AArch64Arch(void) = delete;
};

AArch64Arch::AArch64Arch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_) {}

AArch64Arch::~AArch64Arch(void) {}

void AArch64Arch::PrepareModule(llvm::Module *mod) const {
  std::string dl;
  llvm::Triple triple("aarch64-unknown-unknown-");

  switch (os_name) {
    case kOSLinux:
      triple.setOS(llvm::Triple::Linux);

      switch (arch_name) {
        case kArchAArch64LittleEndian:
          triple.setArch(llvm::Triple::aarch64);
          dl = "e-m:e-i64:64-i128:128-n32:64-S128";
          break;

        default:
          LOG(FATAL)
              << "Cannot prepare AArch64 module for architecture "
              << GetArchName(arch_name);
          break;
      }
      break;

    default:
      LOG(FATAL)
          << "Cannot prepare module for AArch64 code on OS "
          << GetOSName(os_name);
      break;
  }

  mod->setDataLayout(dl);
  mod->setTargetTriple(triple.normalize());

  // Go and remove compile-time attributes added into the semantics. These
  // can screw up later compilation. We purposefully compile semantics with
  // things like auto-vectorization disabled so that it keeps the bitcode
  // to a simpler subset of the available LLVM instruction set. If/when we
  // compile this bitcode back into machine code, we may want to use those
  // features, and clang will complain if we try to do so if these metadata
  // remain present.
  auto &context = mod->getContext();

  llvm::AttributeSet target_attribs;
  target_attribs = target_attribs.addAttribute(
      context, llvm::AttributeSet::FunctionIndex, "target-features");
  target_attribs = target_attribs.addAttribute(
      context, llvm::AttributeSet::FunctionIndex, "target-cpu");

  for (llvm::Function &func : *mod) {
    auto attribs = func.getAttributes();
    attribs = attribs.removeAttributes(
        context, llvm::AttributeSet::FunctionIndex, target_attribs);
    func.setAttributes(attribs);
  }
}

enum RegClass {
  kRegX,
  kRegW
};

static const char * const kPrefixX = "X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X"
                                     "\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X\0X"
                                     "\0X\0X\0X\0\0\0\0\0";
static const char * const kPrefixW = "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW";

static const char *RegPrefix(RegClass size, uint32_t number) {
  return kRegX == size ? &(kPrefixX[number * 2]) : &(kPrefixW[number]);
}

static const char * const kNumberName[] = {
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
    "LP", "SP"
};


using RegNum = uint8_t;

static const char *RegNumberName(RegNum number) {
  CHECK_LE(number, 31U);
  return kNumberName[number];
}

static std::string RegName(RegClass rclass, RegNum number) {
  std::stringstream ss;
  ss << RegPrefix(rclass, number);
  ss << RegNumberName(number);
  return ss.str();
}

static size_t ReadRegSize(RegClass rclass) {
  switch (rclass) {
    case kRegX:
      return 64;
    case kRegW:
      return 32;
  }
}

static size_t WriteRegSize(RegClass rclass) {
  switch (rclass) {
    case kRegX:
    case kRegW:
      return 64;
  }
}

enum Action {
  kActionRead,
  kActionWrite,
  kActionReadWrite
};

static Operand::Register Reg(Action action, RegClass rclass, RegNum reg_num) {
  Operand::Register reg;
  if (kActionWrite == action) {
    reg.name = RegName(rclass, reg_num);
    reg.size = WriteRegSize(rclass);
  } else if (kActionRead == action) {
    reg.name = RegName(rclass, reg_num);
    reg.size = ReadRegSize(rclass);
  } else {
    LOG(FATAL)
        << "Reg function only takes a simple read or write action.";
  }
  return reg;
}

static void AddRegOperand(Instruction &inst, Action action,
                          RegClass rclass, RegNum reg_num) {
  Operand op;
  op.type = Operand::kTypeRegister;

  if (kActionWrite == action || kActionReadWrite == action) {
    op.reg = Reg(kActionWrite, rclass, reg_num);
    op.size = op.reg.size;
    op.action = Operand::kActionWrite;
    inst.operands.push_back(op);
  }

  if (kActionRead == action || kActionReadWrite == action) {
    op.reg = Reg(kActionRead, rclass, reg_num);
    op.size = op.reg.size;
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

static void AddNextPC(Instruction &inst) {
  Operand op;
  op.type = Operand::kTypeAddress;
  op.size = 64;
  op.addr.address_size = 64;
  op.addr.base_reg.name = "PC";
  op.addr.base_reg.size = 64;
  op.addr.displacement = 4;

  op.action = Operand::kActionRead;
  op.addr.kind = Operand::Address::kAddressCalculation;
  inst.operands.push_back(op);
}

// Base+offset memory operands are equivalent to indexing into an array.
//
// We have something like this:
//    [<Xn|SP>, #<imm>]
//
// Which gets is:
//    addr = Xn + imm
//    ... deref addr and do stuff ...
static void AddBasePlusOffsetMemOp(Instruction &inst, Action action,
                                   uint64_t access_size,
                                   RegNum base_reg, uint64_t disp) {
  Operand op;
  op.type = Operand::kTypeAddress;
  op.size = access_size;
  op.addr.address_size = 64;
  op.addr.base_reg = Reg(kActionRead, kRegX, base_reg);
  op.addr.displacement = disp;

  if (kActionWrite == action || kActionReadWrite == action) {
    op.action = Operand::kActionWrite;
    op.addr.kind = Operand::Address::kMemoryWrite;
    inst.operands.push_back(op);
  }

  if (kActionRead == action || kActionReadWrite == action) {
    op.action = Operand::kActionRead;
    op.addr.kind = Operand::Address::kMemoryRead;
    inst.operands.push_back(op);
  }
}

// Pre-index memory operands write back the result of the displaced address
// to the base register.
//
// We have something like this:
//    [<Xn|SP>, #<imm>]!
//
// Which gets us:
//    addr = Xn + imm
//    ... deref addr and do stuff ...
//    Xn = addr + imm
//
// So we add in two operands: one that is a register write operand for Xn,
// the other that is the value of (Xn + imm + imm).
static void AddPreIndexMemOp(Instruction &inst, Action action,
                             uint64_t access_size,
                             RegNum base_reg, uint64_t disp) {
  AddBasePlusOffsetMemOp(inst, action, access_size, base_reg, disp);
  auto addr_op = inst.operands[inst.operands.size() - 1];

  Operand reg_op;
  reg_op.type = Operand::kTypeRegister;
  reg_op.action = Operand::kActionWrite;
  reg_op.reg = Reg(kActionWrite, kRegX, base_reg);
  reg_op.size = reg_op.reg.size;
  inst.operands.push_back(reg_op);

  addr_op.addr.kind = Operand::Address::kAddressCalculation;
  addr_op.addr.address_size = 64;
  addr_op.addr.base_reg = Reg(kActionRead, kRegX, base_reg);
  addr_op.addr.displacement *= 2;
  inst.operands.push_back(addr_op);
}

// Post-index memory operands write back the result of the displaced address
// to the base register.
//
// We have something like this:
//    [<Xn|SP>], #<imm>
//
// Which gets us:
//    addr = Xn
//    ... deref addr and do stuff ...
//    Xn = addr + imm
//
// So we add in two operands: one that is a register write operand for Xn,
// the other that is the value of (Xn + imm).
static void AddPostIndexMemOp(Instruction &inst, Action action,
                              uint64_t access_size,
                              RegNum base_reg, uint64_t disp) {
  AddBasePlusOffsetMemOp(inst, action, access_size, base_reg, 0);
  auto addr_op = inst.operands[inst.operands.size() - 1];

  Operand reg_op;
  reg_op.type = Operand::kTypeRegister;
  reg_op.action = Operand::kActionWrite;
  reg_op.reg = Reg(kActionWrite, kRegX, base_reg);
  reg_op.size = reg_op.reg.size;
  inst.operands.push_back(reg_op);

  addr_op.addr.kind = Operand::Address::kAddressCalculation;
  addr_op.addr.address_size = 64;
  addr_op.addr.base_reg = Reg(kActionRead, kRegX, base_reg);
  addr_op.addr.displacement = disp;
  inst.operands.push_back(addr_op);
}

enum {
  kInstructionSize = 4  // Number of bytes in an instruction.
};

bool AArch64Arch::DecodeInstruction(
    uint64_t address, const std::string &inst_bytes,
    Instruction &inst) const {

  aarch64::InstData dinst = {};
  auto bytes = reinterpret_cast<const uint8_t *>(inst_bytes.data());

  inst.arch_name = arch_name;
  inst.pc = address;
  inst.next_pc = address + kInstructionSize;

  if (kInstructionSize != inst_bytes.size()) {
    inst.function = "INVALID_SIZE";
    return false;

  } else if (0 != (address % kInstructionSize)) {
    inst.function = "INVALID_UNALIGNED";
    return false;

  } else if (!aarch64::TryExtract(bytes, dinst)) {
    inst.function = "INVALID_ENCODING";
    return false;
  }

  inst.category = InstCategory(dinst);
  inst.function = aarch64::InstFormToString(dinst.iform);

  if (!aarch64::TryDecode(dinst, inst)) {
    inst.category = Instruction::kCategoryInvalid;
    return false;
  }

  return true;
}

}  // namespace

namespace aarch64 {

// RET  {<Xn>}
bool TryDecodeRET_64R_BRANCH_REG(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegX, data.Rn);
  return true;
}


// BLR  <Xn>
bool TryDecodeBLR_64_BRANCH_REG(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegX, data.Rn);
  AddNextPC(inst);
  return true;
}

// STP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_32_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegW, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, kActionWrite, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeSTP_64_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegX, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPreIndexMemOp(inst, kActionWrite, 128, data.Rn, offset << 3);
  return true;
}

// STP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_32_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegW, data.Rt);
  AddRegOperand(inst, kActionRead, kRegW, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, kActionWrite, 64, data.Rn, offset << 2);
  return true;
}

// STP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeSTP_64_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionRead, kRegX, data.Rt);
  AddRegOperand(inst, kActionRead, kRegX, data.Rt2);
  uint64_t offset = static_cast<uint64_t>(data.imm7.simm7);
  AddPostIndexMemOp(inst, kActionWrite, 128, data.Rn, offset << 3);
  return true;
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_32_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt2);
  AddPostIndexMemOp(inst, kActionRead, 64, data.Rn,
                    static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>], #<imm>
bool TryDecodeLDP_64_LDSTPAIR_POST(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt2);
  AddPostIndexMemOp(inst, kActionRead, 128, data.Rn,
                    static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_32_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt2);
  AddPreIndexMemOp(inst, kActionRead, 64, data.Rn,
                   static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]!
bool TryDecodeLDP_64_LDSTPAIR_PRE(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt2);
  AddPreIndexMemOp(inst, kActionRead, 128, data.Rn,
                   static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

// LDP  <Wt1>, <Wt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_32_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt2);
  AddBasePlusOffsetMemOp(inst, kActionRead, 64, data.Rn,
                         static_cast<uint64_t>(data.imm7.simm7) << 2);
  return true;
}

// LDP  <Xt1>, <Xt2>, [<Xn|SP>{, #<imm>}]
bool TryDecodeLDP_64_LDSTPAIR_OFF(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt);
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt2);
  AddBasePlusOffsetMemOp(inst, kActionRead, 128, data.Rn,
                         static_cast<uint64_t>(data.imm7.simm7) << 3);
  return true;
}

// LDR  <Wt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_32_LDST_POS(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt);
  AddBasePlusOffsetMemOp(inst, kActionRead, 32, data.Rn,
                         data.imm12.uimm << 2);
  return true;
}

// LDR  <Xt>, [<Xn|SP>{, #<pimm>}]
bool TryDecodeLDR_64_LDST_POS(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt);
  AddBasePlusOffsetMemOp(inst, kActionRead, 64, data.Rn,
                         data.imm12.uimm << 3);
  return true;
}

static void AddPCRegMemOp(Instruction &inst, Action action, uint64_t disp) {
  Operand op;
  op.type = Operand::kTypeAddress;
  op.size = 64;
  op.addr.address_size = 64;
  op.addr.base_reg.name = "PC";
  op.addr.base_reg.size = 64;
  op.addr.displacement = disp;
  if (kActionRead == action) {
    op.action = Operand::kActionRead;
    op.addr.kind = Operand::Address::kMemoryRead;
  } else if (kActionWrite == action) {
    op.action = Operand::kActionWrite;
    op.addr.kind = Operand::Address::kMemoryWrite;
  } else {
    LOG(FATAL)
        << "AddPCRegMemOp only accepts simple operand actions.";
  }
  inst.operands.push_back(op);
}

// LDR  <Wt>, <label>
bool TryDecodeLDR_32_LOADLIT(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegW, data.Rt);
  AddPCRegMemOp(inst, kActionRead,
                static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return false;
}

// LDR  <Xt>, <label>
bool TryDecodeLDR_64_LOADLIT(const InstData &data, Instruction &inst) {
  AddRegOperand(inst, kActionWrite, kRegX, data.Rt);
  AddPCRegMemOp(inst, kActionRead,
                static_cast<uint64_t>(data.imm19.simm19) << 2ULL);
  return true;
}

// LDR LDR_32_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 0 size     0
//  31 1 size     1
// LDR  <Wt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_32_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

// LDR LDR_64_ldst_regoff:
//   0 x Rt       0
//   1 x Rt       1
//   2 x Rt       2
//   3 x Rt       3
//   4 x Rt       4
//   5 x Rn       0
//   6 x Rn       1
//   7 x Rn       2
//   8 x Rn       3
//   9 x Rn       4
//  10 0
//  11 1
//  12 x S        0
//  13 x option   0
//  14 x option   1
//  15 x option   2
//  16 x Rm       0
//  17 x Rm       1
//  18 x Rm       2
//  19 x Rm       3
//  20 x Rm       4
//  21 1
//  22 1 opc      0
//  23 0 opc      1
//  24 0
//  25 0
//  26 0 V        0
//  27 1
//  28 1
//  29 1
//  30 1 size     0
//  31 1 size     1
// LDR  <Xt>, [<Xn|SP>, (<Wm>|<Xm>){, <extend> {<amount>}}]
bool TryDecodeLDR_64_LDST_REGOFF(const InstData &, Instruction &) {
  return false;
}

}  // namespace aarch64

// TODO(pag): We pretend that these are singletons, but they aren't really!
const Arch *Arch::GetAArch64(
    OSName os_name_, ArchName arch_name_) {
  return new AArch64Arch(os_name_, arch_name_);
}

}  // namespace remill
