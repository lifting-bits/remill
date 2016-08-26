/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <sstream>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"

namespace remill {

Operand::Register::Register(void)
    : size(0) {}

Operand::Immediate::Immediate(void)
    : val(0),
      is_signed(false) {}

Operand::Address::Address(void)
    : scale(0),
      displacement(0),
      address_size(0) {}

Operand::Operand(void)
    : type(Operand::kTypeInvalid),
      action(Operand::kActionInvalid),
      size(0) {}

std::string Operand::Debug(void) const {
  std::stringstream ss;
  switch (action) {
    case Operand::kActionInvalid:
      ss << "(INVALID_OP ";
      break;
    case Operand::kActionRead:
      ss << "(READ_OP ";
      break;
    case Operand::kActionWrite:
      ss << "(WRITE_OP ";
      break;
  }
  switch (type) {
    case Operand::kTypeInvalid:
      ss << "(INVALID)";
      break;

    case Operand::kTypeRegister:
      ss << "(REG_" << reg.size << " " << reg.name << ")";
      break;

    case Operand::kTypeImmediate:
      ss << "(";
      if (imm.is_signed) {
        ss << "SIGNED_";
      }
      ss << "IMM_" << size << " " << std::hex << imm.val << std::dec << ")";
      break;

    case Operand::kTypeAddress:
      ss << "(ADDR " << size << " " << addr.address_size;
      if (!addr.segment_reg.name.empty()) {
        ss << " (SEGMENT " << addr.segment_reg.name << ")";
      }

      ss << " " << addr.base_reg.name;
      if (!addr.index_reg.name.empty()) {
        ss << " + (" << addr.index_reg.name << " * " << addr.scale << ")";
      }
      if (addr.displacement) {
        if (0 > addr.displacement) {
          ss << " - " << std::hex << (-addr.displacement) << std::dec;
        } else {
          ss << " + " << std::hex << addr.displacement << std::dec;
        }
      }
      ss << "))";
      break;
  }
  ss << ")";
  return ss.str();
}

Instruction::Instruction(void)
    : pc(0),
      next_pc(0),
      branch_taken_pc(0),
      branch_not_taken_pc(0),
      arch_name(kArchInvalid),
      operand_size(0),
      is_atomic_read_modify_write(false),
      category(Instruction::kCategoryInvalid) {}

std::string Instruction::Debug(void) const {
  std::stringstream ss;
  ss << "(";
  switch (arch_name) {
    case kArchInvalid:
      break;
    case kArchAMD64:
      ss << "AMD64_";
      break;
    case kArchX86:
      ss << "X86_";
      break;
  }
  ss << "INSTR " << std::hex << pc << " " << std::dec << (next_pc - pc) << " ";
  if (is_atomic_read_modify_write) {
    ss << "ATOMIC ";
  }
  ss << function;
  for (const auto &op : operands) {
    ss << std::endl << op.Debug();
  }
  ss << ")";
  return ss.str();
}

}  // namespace remill
