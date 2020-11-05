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

#include "remill/Arch/Instruction.h"

#include <glog/logging.h>

#include <iomanip>
#include <sstream>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

namespace remill {

Operand::Register::Register(void) : size(0) {}

Operand::ShiftRegister::ShiftRegister(void)
    : shift_size(0),
      extract_size(0),
      shift_op(Operand::ShiftRegister::kShiftInvalid),
      extend_op(Operand::ShiftRegister::kExtendInvalid) {}

Operand::Immediate::Immediate(void) : val(0), is_signed(false) {}

Operand::Address::Address(void)
    : scale(0),
      displacement(0),
      address_size(0),
      kind(kInvalid) {}

Operand::Operand(void)
    : type(Operand::kTypeInvalid),
      action(Operand::kActionInvalid),
      size(0) {}

namespace {
static int64_t SignedImmediate(uint64_t val, uint64_t size) {
  switch (size) {
    case 8: return static_cast<int64_t>(static_cast<int8_t>(val));
    case 16: return static_cast<int64_t>(static_cast<int16_t>(val));
    case 32: return static_cast<int64_t>(static_cast<int32_t>(val));
    default: return static_cast<int64_t>(val);
  }
}
}  // namespace

std::string Operand::Serialize(void) const {
  std::stringstream ss;
  switch (action) {
    case Operand::kActionInvalid: ss << "(INVALID_OP "; break;
    case Operand::kActionRead: ss << "(READ_OP "; break;
    case Operand::kActionWrite: ss << "(WRITE_OP "; break;
  }
  switch (type) {
    case Operand::kTypeInvalid: ss << "(INVALID)"; break;

    case Operand::kTypeRegister:
      ss << "(REG_" << reg.size << " " << reg.name << ")";
      break;

    case Operand::kTypeShiftRegister:

      switch (shift_reg.shift_op) {
        case Operand::ShiftRegister::kShiftInvalid: break;

        case Operand::ShiftRegister::kShiftLeftWithZeroes: ss << "(LSL "; break;

        case Operand::ShiftRegister::kShiftLeftWithOnes: ss << "(MSL "; break;

        case Operand::ShiftRegister::kShiftUnsignedRight: ss << "(LSR "; break;

        case Operand::ShiftRegister::kShiftSignedRight: ss << "(ASR "; break;

        case Operand::ShiftRegister::kShiftLeftAround: ss << "(ROL "; break;

        case Operand::ShiftRegister::kShiftRightAround: ss << "(ROR "; break;
      }

      switch (shift_reg.extend_op) {
        case Operand::ShiftRegister::kExtendInvalid:
          ss << "(REG_" << shift_reg.reg.size << " " << shift_reg.reg.name
             << ")";
          break;

        case Operand::ShiftRegister::kExtendSigned:
          ss << "(SEXT (TRUNC (REG_" << shift_reg.reg.size << " "
             << shift_reg.reg.name << ") " << shift_reg.extract_size << ") "
             << size << ")";
          break;

        case Operand::ShiftRegister::kExtendUnsigned:
          ss << "(ZEXT (TRUNC (REG_" << shift_reg.reg.size << " "
             << shift_reg.reg.name << ") " << shift_reg.extract_size << ") "
             << size << ")";
          break;
      }

      if (Operand::ShiftRegister::kShiftInvalid != shift_reg.shift_op) {
        ss << " " << shift_reg.shift_size << ")";
      }

      break;

    case Operand::kTypeImmediate:
      ss << "(";
      if (imm.is_signed) {
        ss << "SIGNED_IMM_" << size << " ";
        auto simm = SignedImmediate(imm.val, size);
        if (simm < 0) {
          ss << "-0x" << std::hex << static_cast<uint64_t>(-simm) << std::dec;
        } else {
          ss << "0x" << std::hex << imm.val << std::dec;
        }
      } else {
        ss << "IMM_" << size << " " << std::hex << imm.val << std::dec << ")";
      }
      break;

    case Operand::kTypeAddress:
      ss << "(";

      // Nice version of the memory size.
      switch (size) {
        case 8: ss << "BYTE"; break;
        case 16: ss << "WORD"; break;
        case 32: ss << "DWORD"; break;
        case 64: ss << "QWORD"; break;
        case 80: ss << "TBYTE"; break;
        case 128: ss << "OWORD"; break;
        case 256: ss << "DOWORD"; break;
        case 512: ss << "QOWORD"; break;
        default:
          CHECK(!(size & 7))
              << "Memory operand size must be divisible by 8; got " << size
              << " bits.";
          ss << std::dec << (size / 8) << "_BYTES";
          break;
      }

      ss << "_PTR";

      int num_components = 0;
      if (addr.displacement) {
        ++num_components;
      }
      if (!addr.segment_base_reg.name.empty()) {
        ++num_components;
      }
      if (!addr.base_reg.name.empty()) {
        ++num_components;
      }
      if (!addr.index_reg.name.empty()) {
        ++num_components;
      }

      if (1 < num_components) {
        ss << " (ADD";
      }

      if (!addr.segment_base_reg.name.empty()) {
        ss << " (REG_" << addr.segment_base_reg.size << " "
           << addr.segment_base_reg.name << ")";
      }

      if (!addr.base_reg.name.empty()) {
        ss << " (REG_" << addr.base_reg.size << " " << addr.base_reg.name
           << ")";
      }

      if (addr.scale) {
        CHECK(!addr.index_reg.name.empty());
        ss << " (MUL";
      }

      if (!addr.index_reg.name.empty()) {
        ss << " (REG_" << addr.index_reg.size << " " << addr.index_reg.name
           << ")";
      }

      if (addr.scale) {
        ss << " (IMM_" << addr.index_reg.size << " 0x" << std::hex << addr.scale
           << std::dec << ")";
        ss << ")";  // End of `(MUL`.
      }

      if (addr.displacement) {
        ss << " (SIGNED_IMM_" << addr.address_size << " ";
        if (0 > addr.displacement) {
          ss << "-0x" << std::hex << (-addr.displacement) << std::dec;
        } else {
          ss << "0x" << std::hex << addr.displacement << std::dec;
        }
        ss << ")";  // End of `(SIGNED_IMM_`.
      }
      if (1 < num_components) {
        ss << ")";  // End of `(ADD`.
      }
      ss << ")";  // End of `(ADDR_`.
      break;
  }
  ss << ")";
  return ss.str();
}

Instruction::Instruction(void)
    : pc(0),
      next_pc(0),
      delayed_pc(0),
      branch_taken_pc(0),
      branch_not_taken_pc(0),
      arch_name(kArchInvalid),
      arch(nullptr),
      is_atomic_read_modify_write(false),
      has_branch_taken_delay_slot(false),
      has_branch_not_taken_delay_slot(false),
      in_delay_slot(false),
      category(Instruction::kCategoryInvalid) {}

void Instruction::Reset(void) {
  pc = 0;
  next_pc = 0;
  delayed_pc = 0;
  branch_taken_pc = 0;
  branch_not_taken_pc = 0;
  arch_name = kArchInvalid;
  is_atomic_read_modify_write = false;
  has_branch_taken_delay_slot = false;
  has_branch_not_taken_delay_slot = false;
  in_delay_slot = false;
  category = Instruction::kCategoryInvalid;
  arch = nullptr;
  operands.clear();
  function.clear();
  bytes.clear();
}

std::string Instruction::Serialize(void) const {
  std::stringstream ss;
  ss << "(";
  switch (arch_name) {
    case kArchInvalid: break;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512: ss << "AMD64"; break;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512: ss << "X86"; break;
    case kArchAArch64LittleEndian: ss << "AArch64"; break;
    case kArchSparc32: ss << "SPARC32"; break;
    case kArchSparc64: ss << "SPARC64"; break;
  }

  ss << " " << std::hex << pc;

  if (IsValid()) {
    if (bytes.empty()) {
      ss << " (NO-BYTES)";

    } else {
      ss << " (BYTES";
      for (auto byte : bytes) {
        ss << " " << std::setw(2) << std::setfill('0') << std::hex
           << static_cast<unsigned>(static_cast<uint8_t>(byte));
      }
      ss << ")";
    }

  } else if (bytes.empty()) {
    ss << " (NO-BYTES)";

  } else {

    // if the instruction is invalid print the bytes
    // It will be helpful in mapping to the instruction in the absence of binary
    ss << " (BYTES";
    for (auto byte : bytes) {
      ss << " " << std::setw(2) << std::setfill('0') << std::hex
         << static_cast<unsigned>(static_cast<uint8_t>(byte));
    }
    ss << ")";
  }

  if (function.empty()) {
    ss << " !NO-FUNCTION!";
  } else {
    ss << " " << function;
  }

  for (const auto &op : operands) {
    ss << " " << op.Serialize();
  }

  if (is_atomic_read_modify_write) {
    ss << " IS_ATOMIC";
  }

  if (has_branch_taken_delay_slot || has_branch_not_taken_delay_slot) {
    ss << " (DELAY_SLOT";
    if (has_branch_taken_delay_slot) {
      ss << " (TAKEN " << std::hex << delayed_pc << std::dec << ")";
    }
    if (has_branch_not_taken_delay_slot) {
      ss << " (NOT_TAKEN " << std::hex << delayed_pc << std::dec << ")";
    }
    ss << ")";
  }

  if (in_delay_slot) {
    ss << " IN_DELAY_SLOT";
  }

  switch (category) {
    case Instruction::kCategoryDirectJump:
      ss << " (BRANCH " << std::hex << branch_taken_pc << ")";
      break;
    case Instruction::kCategoryDirectFunctionCall:
      ss << " (DIRECT_CALL (TAKEN " << std::hex << branch_taken_pc << ")"
         << " (RETURN " << branch_not_taken_pc << "))";
      break;
    case Instruction::kCategoryIndirectFunctionCall:
      ss << " (INDIRECT_CALL (TAKEN <unknown>)"
         << " (RETURN " << branch_not_taken_pc << "))";
      break;
    case Instruction::kCategoryConditionalBranch:
      ss << " (COND_BRANCH (TAKEN " << std::hex << branch_taken_pc << ")"
         << " (NOT_TAKEN " << branch_not_taken_pc << std::dec << "))";
      break;
    default: break;
  }

  ss << ")";
  return ss.str();
}

}  // namespace remill
