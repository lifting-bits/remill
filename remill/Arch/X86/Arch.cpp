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

#include <glog/logging.h>

#include <map>
#include <memory>
#include <sstream>
#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/X86/XED.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace {

static const xed_state_t kXEDState32 = {
    XED_MACHINE_MODE_LONG_COMPAT_32,
    XED_ADDRESS_WIDTH_32b};

static const xed_state_t kXEDState64 = {
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b};

static bool Is64Bit(ArchName arch_name) {
  return kArchAMD64 == arch_name || kArchAMD64_AVX == arch_name ||
         kArchAMD64_AVX512 == arch_name;
}

static bool IsFunctionReturn(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_RET_NEAR == iclass || XED_ICLASS_RET_FAR == iclass;
}

// TODO(pag): Should far calls be treated as syscalls or indirect calls?
static bool IsSystemCall(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_SYSCALL == iclass || XED_ICLASS_SYSCALL_AMD == iclass ||
         XED_ICLASS_SYSENTER == iclass;
}

static bool IsSystemReturn(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_SYSRET == iclass || XED_ICLASS_SYSRET_AMD == iclass ||
         XED_ICLASS_SYSEXIT == iclass;
}

static bool IsInterruptCall(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_INT == iclass || XED_ICLASS_INT1 == iclass ||
         XED_ICLASS_INT3 == iclass;
}

static bool IsConditionalInterruptCall(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_INTO == iclass || XED_ICLASS_BOUND == iclass;
}

static bool IsInterruptReturn(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_IRET <= iclass && XED_ICLASS_IRETQ >= iclass;
}

// This includes `JRCXZ`.
static bool IsConditionalBranch(const xed_decoded_inst_t *xedd) {
  return XED_CATEGORY_COND_BR == xed_decoded_inst_get_category(xedd);
}

static bool IsDirectFunctionCall(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR == op_name;
}

static bool IsIndirectFunctionCall(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return (XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_CALL_FAR == iclass;
}

static bool IsDirectJump(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR == op_name;
}

static bool IsIndirectJump(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return (XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_JMP_FAR == iclass ||
         XED_ICLASS_XEND == iclass || XED_ICLASS_XABORT == iclass;
}

static bool IsNoOp(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_NOP:
    case XED_CATEGORY_WIDENOP:
      return true;
    default:
      return false;
  }
}

static bool IsError(const xed_decoded_inst_t *xedd) {
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_HLT == iclass || XED_ICLASS_UD2 == iclass;
}

static bool IsInvalid(const xed_decoded_inst_t *xedd) {
  return XED_ICLASS_INVALID == xed_decoded_inst_get_iclass(xedd);
}

// Return the category of this instuction.
static Instruction::Category CreateCategory(const xed_decoded_inst_t *xedd) {
  if (IsInvalid(xedd)) {
    return Instruction::kCategoryInvalid;

  } else if (IsError(xedd)) {
    return Instruction::kCategoryError;

  } else if (IsDirectJump(xedd)) {
    return Instruction::kCategoryDirectJump;

  } else if (IsIndirectJump(xedd)) {
    return Instruction::kCategoryIndirectJump;

  } else if (IsDirectFunctionCall(xedd)) {
    return Instruction::kCategoryDirectFunctionCall;

  } else if (IsIndirectFunctionCall(xedd)) {
    return Instruction::kCategoryIndirectFunctionCall;

  } else if (IsFunctionReturn(xedd)) {
    return Instruction::kCategoryFunctionReturn;

  } else if (IsConditionalBranch(xedd)) {
    return Instruction::kCategoryConditionalBranch;

  // Instruction implementation handles syscall emulation.
  } else if (IsSystemCall(xedd)) {
    return Instruction::kCategoryAsyncHyperCall;

  } else if (IsSystemReturn(xedd)) {
    return Instruction::kCategoryAsyncHyperCall;

  // Instruction implementation handles syscall (x86, x32) emulation. This is
  // invoked even for conditional interrupt, where a special flag is used to
  // denote that the interrupt should happen.
  } else if (IsInterruptCall(xedd)) {
    return Instruction::kCategoryAsyncHyperCall;

  } else if (IsConditionalInterruptCall(xedd)) {
    return Instruction::kCategoryConditionalAsyncHyperCall;

  } else if (IsInterruptReturn(xedd)) {
    return Instruction::kCategoryAsyncHyperCall;

  } else if (IsNoOp(xedd)) {
    return Instruction::kCategoryNoOp;

  } else {
    return Instruction::kCategoryNormal;
  }
}

std::map<xed_iform_enum_t, xed_iform_enum_t> kUnlockedIform = {
    {XED_IFORM_ADC_LOCK_MEMb_IMMb_80r2, XED_IFORM_ADC_MEMb_IMMb_80r2},
    {XED_IFORM_ADC_LOCK_MEMv_IMMz, XED_IFORM_ADC_MEMv_IMMz},
    {XED_IFORM_ADC_LOCK_MEMb_IMMb_82r2, XED_IFORM_ADC_MEMb_IMMb_82r2},
    {XED_IFORM_ADC_LOCK_MEMv_IMMb, XED_IFORM_ADC_MEMv_IMMb},
    {XED_IFORM_ADC_LOCK_MEMb_GPR8, XED_IFORM_ADC_MEMb_GPR8},
    {XED_IFORM_ADC_LOCK_MEMv_GPRv, XED_IFORM_ADC_MEMv_GPRv},
    {XED_IFORM_DEC_LOCK_MEMb, XED_IFORM_DEC_MEMb},
    {XED_IFORM_DEC_LOCK_MEMv, XED_IFORM_DEC_MEMv},
    {XED_IFORM_NOT_LOCK_MEMb, XED_IFORM_NOT_MEMb},
    {XED_IFORM_NOT_LOCK_MEMv, XED_IFORM_NOT_MEMv},
    {XED_IFORM_SUB_LOCK_MEMb_IMMb_80r5, XED_IFORM_SUB_MEMb_IMMb_80r5},
    {XED_IFORM_SUB_LOCK_MEMv_IMMz, XED_IFORM_SUB_MEMv_IMMz},
    {XED_IFORM_SUB_LOCK_MEMb_IMMb_82r5, XED_IFORM_SUB_MEMb_IMMb_82r5},
    {XED_IFORM_SUB_LOCK_MEMv_IMMb, XED_IFORM_SUB_MEMv_IMMb},
    {XED_IFORM_SUB_LOCK_MEMb_GPR8, XED_IFORM_SUB_MEMb_GPR8},
    {XED_IFORM_SUB_LOCK_MEMv_GPRv, XED_IFORM_SUB_MEMv_GPRv},
    {XED_IFORM_BTC_LOCK_MEMv_IMMb, XED_IFORM_BTC_MEMv_IMMb},
    {XED_IFORM_BTC_LOCK_MEMv_GPRv, XED_IFORM_BTC_MEMv_GPRv},
    {XED_IFORM_AND_LOCK_MEMb_IMMb_80r4, XED_IFORM_AND_MEMb_IMMb_80r4},
    {XED_IFORM_AND_LOCK_MEMv_IMMz, XED_IFORM_AND_MEMv_IMMz},
    {XED_IFORM_AND_LOCK_MEMb_IMMb_82r4, XED_IFORM_AND_MEMb_IMMb_82r4},
    {XED_IFORM_AND_LOCK_MEMv_IMMb, XED_IFORM_AND_MEMv_IMMb},
    {XED_IFORM_AND_LOCK_MEMb_GPR8, XED_IFORM_AND_MEMb_GPR8},
    {XED_IFORM_AND_LOCK_MEMv_GPRv, XED_IFORM_AND_MEMv_GPRv},
    {XED_IFORM_CMPXCHG_LOCK_MEMb_GPR8, XED_IFORM_CMPXCHG_MEMb_GPR8},
    {XED_IFORM_CMPXCHG_LOCK_MEMv_GPRv, XED_IFORM_CMPXCHG_MEMv_GPRv},
    {XED_IFORM_INC_LOCK_MEMb, XED_IFORM_INC_MEMb},
    {XED_IFORM_INC_LOCK_MEMv, XED_IFORM_INC_MEMv},
    {XED_IFORM_OR_LOCK_MEMb_IMMb_80r1, XED_IFORM_OR_MEMb_IMMb_80r1},
    {XED_IFORM_OR_LOCK_MEMv_IMMz, XED_IFORM_OR_MEMv_IMMz},
    {XED_IFORM_OR_LOCK_MEMb_IMMb_82r1, XED_IFORM_OR_MEMb_IMMb_82r1},
    {XED_IFORM_OR_LOCK_MEMv_IMMb, XED_IFORM_OR_MEMv_IMMb},
    {XED_IFORM_OR_LOCK_MEMb_GPR8, XED_IFORM_OR_MEMb_GPR8},
    {XED_IFORM_OR_LOCK_MEMv_GPRv, XED_IFORM_OR_MEMv_GPRv},
    {XED_IFORM_XADD_LOCK_MEMb_GPR8, XED_IFORM_XADD_MEMb_GPR8},
    {XED_IFORM_XADD_LOCK_MEMv_GPRv, XED_IFORM_XADD_MEMv_GPRv},
    {XED_IFORM_ADD_LOCK_MEMb_IMMb_80r0, XED_IFORM_ADD_MEMb_IMMb_80r0},
    {XED_IFORM_ADD_LOCK_MEMv_IMMz, XED_IFORM_ADD_MEMv_IMMz},
    {XED_IFORM_ADD_LOCK_MEMb_IMMb_82r0, XED_IFORM_ADD_MEMb_IMMb_82r0},
    {XED_IFORM_ADD_LOCK_MEMv_IMMb, XED_IFORM_ADD_MEMv_IMMb},
    {XED_IFORM_ADD_LOCK_MEMb_GPR8, XED_IFORM_ADD_MEMb_GPR8},
    {XED_IFORM_ADD_LOCK_MEMv_GPRv, XED_IFORM_ADD_MEMv_GPRv},
    {XED_IFORM_SBB_LOCK_MEMb_IMMb_80r3, XED_IFORM_SBB_MEMb_IMMb_80r3},
    {XED_IFORM_SBB_LOCK_MEMv_IMMz, XED_IFORM_SBB_MEMv_IMMz},
    {XED_IFORM_SBB_LOCK_MEMb_IMMb_82r3, XED_IFORM_SBB_MEMb_IMMb_82r3},
    {XED_IFORM_SBB_LOCK_MEMv_IMMb, XED_IFORM_SBB_MEMv_IMMb},
    {XED_IFORM_SBB_LOCK_MEMb_GPR8, XED_IFORM_SBB_MEMb_GPR8},
    {XED_IFORM_SBB_LOCK_MEMv_GPRv, XED_IFORM_SBB_MEMv_GPRv},
    {XED_IFORM_BTS_LOCK_MEMv_IMMb, XED_IFORM_BTS_MEMv_IMMb},
    {XED_IFORM_BTS_LOCK_MEMv_GPRv, XED_IFORM_BTS_MEMv_GPRv},
    {XED_IFORM_XOR_LOCK_MEMb_IMMb_80r6, XED_IFORM_XOR_MEMb_IMMb_80r6},
    {XED_IFORM_XOR_LOCK_MEMv_IMMz, XED_IFORM_XOR_MEMv_IMMz},
    {XED_IFORM_XOR_LOCK_MEMb_IMMb_82r6, XED_IFORM_XOR_MEMb_IMMb_82r6},
    {XED_IFORM_XOR_LOCK_MEMv_IMMb, XED_IFORM_XOR_MEMv_IMMb},
    {XED_IFORM_XOR_LOCK_MEMb_GPR8, XED_IFORM_XOR_MEMb_GPR8},
    {XED_IFORM_XOR_LOCK_MEMv_GPRv, XED_IFORM_XOR_MEMv_GPRv},
    {XED_IFORM_BTR_LOCK_MEMv_IMMb, XED_IFORM_BTR_MEMv_IMMb},
    {XED_IFORM_BTR_LOCK_MEMv_GPRv, XED_IFORM_BTR_MEMv_GPRv},
    {XED_IFORM_CMPXCHG8B_LOCK_MEMq, XED_IFORM_CMPXCHG8B_MEMq},
    {XED_IFORM_CMPXCHG8B_LOCK_MEMq, XED_IFORM_CMPXCHG8B_MEMq},
    {XED_IFORM_CMPXCHG16B_LOCK_MEMdq, XED_IFORM_CMPXCHG16B_MEMdq},
    {XED_IFORM_NEG_LOCK_MEMb, XED_IFORM_NEG_MEMb},
    {XED_IFORM_NEG_LOCK_MEMv, XED_IFORM_NEG_MEMv},
};

// Name of this instruction function.
static std::string InstructionFunctionName(const xed_decoded_inst_t *xedd) {

  // If this instuction is marked as atomic via the `LOCK` prefix then we want
  // to remove it because we will already be surrounding the call to the
  // semantics function with the atomic begin/end intrinsics.
  auto iform = xed_decoded_inst_get_iform_enum(xedd);
  if (xed_operand_values_has_lock_prefix(xedd)) {
    CHECK(kUnlockedIform.count(iform))
        << xed_iform_enum_t2str(iform) << " has no unlocked iform mapping.";
    iform = kUnlockedIform[iform];
  }

  std::stringstream ss;
  std::string iform_name = xed_iform_enum_t2str(iform);
  ss << iform_name;

  // Some instuctions are "scalable", i.e. there are variants of the
  // instuction for each effective operand size. We represent these in
  // the semantics files with `_<size>`, so we need to look up the correct
  // selection.
  if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_SCALABLE)) {
    ss << "_";
    ss << xed_decoded_inst_get_operand_width(xedd);
  }

  // Suffix the ISEL function name with the segment register name for these two
  // iforms so that we know which hypercall to use.
  if (XED_IFORM_MOV_SEG_MEMw == iform ||
      XED_IFORM_MOV_SEG_GPR16 == iform) {
    ss << "_";
    ss << xed_reg_enum_t2str(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0));
  }

  return ss.str();
}

// Decode an instruction into the XED instuction format.
static bool DecodeXED(xed_decoded_inst_t *xedd,
                      const xed_state_t *mode,
                      const std::string &inst_bytes,
                      uint64_t address) {
  auto num_bytes = inst_bytes.size();
  auto bytes = reinterpret_cast<const uint8_t *>(inst_bytes.data());
  xed_decoded_inst_zero_set_mode(xedd, mode);
  xed_decoded_inst_set_input_chip(xedd, XED_CHIP_INVALID);
  auto err = xed_decode(xedd, bytes, static_cast<uint32_t>(num_bytes));

  if (XED_ERROR_NONE != err) {
    LOG(ERROR)
        << "Unable to decode instuction at " << std::hex << address
        << " with error: " << xed_error_enum_t2str(err) << ".";
    return false;
  }

  return true;
}

// Variable operand for a read register.
static Operand::Register RegOp(xed_reg_enum_t reg) {
  Operand::Register reg_op;
  if (XED_REG_INVALID != reg) {
    switch (reg) {
      case XED_REG_ST0:
        reg_op.name = "ST0";
        break;
      case XED_REG_ST1:
        reg_op.name = "ST1";
        break;
      case XED_REG_ST2:
        reg_op.name = "ST2";
        break;
      case XED_REG_ST3:
        reg_op.name = "ST3";
        break;
      case XED_REG_ST4:
        reg_op.name = "ST4";
        break;
      case XED_REG_ST5:
        reg_op.name = "ST5";
        break;
      case XED_REG_ST6:
        reg_op.name = "ST6";
        break;
      case XED_REG_ST7:
        reg_op.name = "ST7";
        break;
      default:
        reg_op.name = xed_reg_enum_t2str(reg);
        break;
    }
    if (XED_REG_X87_FIRST <= reg && XED_REG_X87_LAST >= reg) {
      reg_op.size = 64;
    } else {
      reg_op.size = xed_get_register_width_bits64(reg);
    }
  }
  return reg_op;
}

static Operand::Register SegBaseRegOp(xed_reg_enum_t reg,
                                      unsigned addr_size) {
  auto op = RegOp(reg);
  if (XED_REG_INVALID != reg) {
    op.name += "_BASE";
    op.size = addr_size;
  }
  return op;
}

// Decode a memory operand.
static void DecodeMemory(Instruction &inst,
                         const xed_decoded_inst_t *xedd,
                         const xed_operand_t *xedo,
                         int mem_index) {

  auto iform = xed_decoded_inst_get_iform_enum(xedd);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  auto op_name = xed_operand_name(xedo);
  auto segment = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto base_wide = xed_get_largest_enclosing_register(base);
  auto inst_size = static_cast<int64_t>(xed_decoded_inst_get_length(xedd));

  // NOTE(pag): This isn't quite right (eg. it's for SCALABALE only), but works
  // mostly right most of the time.
  auto size = xed_decoded_inst_get_operand_width(xedd);
  if (XED_IFORM_MOV_MEMw_SEG == iform) {
    size = 16;
  }

  // Deduce the implicit segment register if it is absent.
  if (XED_REG_INVALID == segment) {
    segment = XED_REG_DS;
    if (XED_REG_RSP == base_wide || XED_REG_RBP == base_wide) {
      segment = XED_REG_SS;
    }
  }

  // On AMD64, only the `FS` and `GS` segments are non-zero.
  if (Is64Bit(inst.arch_name) &&
      XED_REG_FS != segment &&
      XED_REG_GS != segment) {
    segment = XED_REG_INVALID;

  // AGEN operands, e.g. for the `LEA` instuction, can be marked with an
  // explicit segment, but it is ignored.
  } else if (XED_OPERAND_AGEN == op_name) {
    segment = XED_REG_INVALID;
  }

  // Special case: `POP [xSP + ...] uses the value of `xSP` after incrementing
  // it by the stack width.
  if (XED_ICLASS_POP == iclass && XED_REG_RSP == base_wide) {
    disp += static_cast<int64_t>(size / 8);
  }

  Operand op = {};
  op.size = size;

  op.type = Operand::kTypeAddress;
  op.addr.address_size = xed_decoded_inst_get_memop_address_width(
      xedd, mem_index);

  op.addr.segment_base_reg = SegBaseRegOp(segment, op.addr.address_size);
  op.addr.base_reg = RegOp(base);
  op.addr.index_reg = RegOp(index);
  op.addr.scale = XED_REG_INVALID != index ? static_cast<int64_t>(scale) : 0;
  op.addr.displacement = disp;

  // PC-relative memory accesses are relative to the next PC. Rename the base
  // register to use `PC` as the register name.
  if (XED_REG_RIP == base_wide) {
    op.addr.base_reg.name = "PC";
    op.addr.displacement += static_cast<int64_t>(inst_size);
  }

  // We always pass destination operands first, then sources. Memory operands
  // are represented by their addresses, and in the instuction implementations,
  // accessed via intrinsics.
  if (xed_operand_written(xedo)) {
    op.action = Operand::kActionWrite;
    op.addr.kind = Operand::Address::kMemoryWrite;
    inst.operands.push_back(op);
  }

  if (xed_operand_read(xedo)) {
    op.action = Operand::kActionRead;
    if (XED_OPERAND_AGEN == op_name) {
      op.addr.kind = Operand::Address::kAddressCalculation;
    } else {
      op.addr.kind = Operand::Address::kMemoryRead;
    }
    inst.operands.push_back(op);
  }
}

// Decode an immediate constant.
static void DecodeImmediate(Instruction &inst,
                            const xed_decoded_inst_t *xedd,
                            xed_operand_enum_t op_name) {
  auto val = 0ULL;
  auto is_signed = false;
  auto imm_size = xed_decoded_inst_get_immediate_width_bits(xedd);

  CHECK(imm_size <= inst.operand_size)
      << "Immediate size is greater than effective operand size at "
      << std::hex << inst.pc << ".";

  if (XED_OPERAND_IMM0SIGNED == op_name ||
      xed_operand_values_get_immediate_is_signed(xedd)) {
    val = static_cast<uint64_t>(
        static_cast<int64_t>(xed_decoded_inst_get_signed_immediate(xedd)));
    is_signed = true;

  } else if (XED_OPERAND_IMM0 == op_name) {
    val = static_cast<uint64_t>(xed_decoded_inst_get_unsigned_immediate(xedd));

  } else if (XED_OPERAND_IMM1_BYTES == op_name || XED_OPERAND_IMM1 == op_name) {
    val = static_cast<uint64_t>(xed_decoded_inst_get_second_immediate(xedd));

  } else {
    CHECK(false)
        << "Unexpected immediate type "
        << xed_operand_enum_t2str(op_name) << ".";
  }

  Operand op = {};
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;
  op.size = imm_size;
  op.imm.is_signed = is_signed;
  op.imm.val = val;
  inst.operands.push_back(op);
}

// Decode a register operand.
static void DecodeRegister(Instruction &inst,
                           const xed_decoded_inst_t *xedd,
                           const xed_operand_t *xedo,
                           xed_operand_enum_t op_name) {
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  CHECK(XED_REG_INVALID != reg)
      << "Cannot get name of invalid register.";

  Operand op = {};
  op.type = Operand::kTypeRegister;
  op.reg = RegOp(reg);
  op.size = op.reg.size;

  // Pass the register by reference.
  if (xed_operand_written(xedo)) {
    op.action = Operand::kActionWrite;
    if (Is64Bit(inst.arch_name)) {
      if (XED_REG_GPR32_FIRST <= reg && XED_REG_GPR32_LAST > reg) {
        op.reg.name[0] = 'R';  // Convert things like `EAX` into `RAX`.
        op.size = 64;
        op.reg.size = 64;

      } else if (XED_REG_XMM_FIRST <= reg && XED_REG_ZMM_LAST >= reg) {
        if (kArchAMD64_AVX512 == inst.arch_name) {
          op.reg.name[0] = 'Z';  // Convert things like `XMM` into `ZMM`.
          op.reg.size = 512;
          op.size = 512;

        } else if (kArchAMD64_AVX == inst.arch_name) {
          op.reg.name[0] = 'Y';  // Convert things like `XMM` into `YMM`.
          op.reg.size = 256;
          op.size = 256;
        }
      }
    }
    inst.operands.push_back(op);
  }

  if (xed_operand_read(xedo)) {
    op.action = Operand::kActionRead;
    inst.operands.push_back(op);
  }
}

static void DecodeConditionalInterrupt(Instruction &inst) {
  // Condition variable.
  Operand cond_op = {};
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
  inst.operands.push_back(cond_op);
}

// Operand representing the fall-through PC, which is the not-taken branch of
// a conditional jump, or the return address for a function call.
static void DecodeFallThroughPC(Instruction &inst,
                                const xed_decoded_inst_t *xedd) {
  auto pc_reg = Is64Bit(inst.arch_name) ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);

  Operand not_taken_op = {};
  not_taken_op.action = Operand::kActionRead;
  not_taken_op.type = Operand::kTypeAddress;
  not_taken_op.size = pc_width;
  not_taken_op.addr.address_size = pc_width;
  not_taken_op.addr.base_reg.name = "PC";
  not_taken_op.addr.base_reg.size = pc_width;
  not_taken_op.addr.displacement = static_cast<int64_t>(inst.NumBytes());
  not_taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(not_taken_op);

  inst.branch_not_taken_pc = inst.next_pc;
}

// Decode a relative branch target.
static void DecodeConditionalBranch(Instruction &inst,
                                    const xed_decoded_inst_t *xedd) {
  auto pc_reg = Is64Bit(inst.arch_name) ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp = static_cast<int64_t>(
      xed_decoded_inst_get_branch_displacement(xedd));

  // Condition variable.
  Operand cond_op = {};
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
  inst.operands.push_back(cond_op);

  // Taken branch.
  Operand taken_op = {};
  taken_op.action = Operand::kActionRead;
  taken_op.type = Operand::kTypeAddress;
  taken_op.size = pc_width;
  taken_op.addr.address_size = pc_width;
  taken_op.addr.base_reg.name = "PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp + static_cast<int64_t>(inst.NumBytes());
  taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(taken_op);

  inst.branch_taken_pc = static_cast<uint64_t>(
      static_cast<int64_t>(inst.next_pc) + disp);

  DecodeFallThroughPC(inst, xedd);
}

// Decode a relative branch target.
static void DecodeRelativeBranch(Instruction &inst,
                                 const xed_decoded_inst_t *xedd) {
  auto pc_reg = Is64Bit(inst.arch_name) ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp = static_cast<int64_t>(
      xed_decoded_inst_get_branch_displacement(xedd));

  // Taken branch.
  Operand taken_op = {};
  taken_op.action = Operand::kActionRead;
  taken_op.type = Operand::kTypeAddress;
  taken_op.size = pc_width;
  taken_op.addr.address_size = pc_width;
  taken_op.addr.base_reg.name = "PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp + static_cast<int64_t>(inst.NumBytes());
  taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(taken_op);

  inst.branch_taken_pc = static_cast<uint64_t>(
      static_cast<int64_t>(inst.next_pc) + disp);
}

// Decodes the opcode byte of this FPU instruction. This is the unique part of
// the first two opcode bytes, and skips over prefix bytes. The FPU opcode is
// the 11 `x`s of the first two non-prefix bytes: `11011xxx xxxxxxxx`.
static uint16_t DecodeFpuOpcode(Instruction &inst) {
  unsigned i = 0;
  auto found_first_opcode_byte = false;
  uint8_t bytes[15] = {};
  for (auto b : inst.bytes) {
    if (0xD8 == (0xF8 & b)) {
      found_first_opcode_byte = true;
    }
    if (found_first_opcode_byte) {
      bytes[i++] = static_cast<uint8_t>(b);
    }
  }

  CHECK(i >= 2)
      << "Failed to find FPU opcode byte for instruction " << inst.Serialize();

  uint16_t opcode = 0;
  opcode |= static_cast<uint16_t>(bytes[0] & 3) << 8;
  opcode |= static_cast<uint16_t>(bytes[1]);

  return opcode;
}

// Add to the instruction operands that will let us get at the last program
// counter and opcode for non-control x87 instructions.
static void DecodeX87LastIpDp(Instruction &inst) {
  auto pc_width = Is64Bit(inst.arch_name) ? 64 : 32;
  Operand pc = {};
  pc.action = Operand::kActionRead;
  pc.type = Operand::kTypeRegister;
  pc.size = pc_width;
  pc.reg.name = "PC";
  pc.reg.size = pc_width;
  inst.operands.push_back(pc);

  Operand fop;
  fop.action = Operand::kActionRead;
  fop.type = Operand::kTypeImmediate;
  fop.size = 16;
  fop.imm.is_signed = false;
  fop.imm.val = static_cast<uint64_t>(DecodeFpuOpcode(inst));
  inst.operands.push_back(fop);
}

// Decode an operand.
static void DecodeOperand(Instruction &inst,
                          const xed_decoded_inst_t *xedd,
                          const xed_operand_t *xedo) {
  switch (auto op_name = xed_operand_name(xedo)) {
    case XED_OPERAND_AGEN:
    case XED_OPERAND_MEM0:
      DecodeMemory(inst, xedd, xedo, 0);
      break;

    case XED_OPERAND_MEM1:
      DecodeMemory(inst, xedd, xedo, 1);
      break;

    case XED_OPERAND_IMM0SIGNED:
    case XED_OPERAND_IMM0:
    case XED_OPERAND_IMM1_BYTES:
    case XED_OPERAND_IMM1:
      DecodeImmediate(inst, xedd, op_name);
      break;

    case XED_OPERAND_PTR:
      CHECK(false)
          << "Unsupported operand type: XED_OPERAND_PTR";
      break;

    case XED_OPERAND_REG:
    case XED_OPERAND_REG0:
    case XED_OPERAND_REG1:
    case XED_OPERAND_REG2:
    case XED_OPERAND_REG3:
    case XED_OPERAND_REG4:
    case XED_OPERAND_REG5:
    case XED_OPERAND_REG6:
    case XED_OPERAND_REG7:
    case XED_OPERAND_REG8:
      DecodeRegister(inst, xedd, xedo, op_name);
      break;

    case XED_OPERAND_RELBR:
      if (Instruction::kCategoryConditionalBranch == inst.category) {
        DecodeConditionalBranch(inst, xedd);
      } else {
        DecodeRelativeBranch(inst, xedd);
      }
      break;

    default:
      LOG(FATAL)
          << "Unexpected operand type "
          << xed_operand_enum_t2str(op_name) << ".";
      return;
  }
}

class X86Arch : public Arch {
 public:
  X86Arch(OSName os_name_, ArchName arch_name_);

  virtual ~X86Arch(void);

  // Decode an instuction.
  bool DecodeInstruction(
      uint64_t address, const std::string &inst_bytes,
      Instruction &inst) const final;

  // Fully decode any control-flow transfer instructions, but only partially
  // decode other instructions. To complete the decoding, call
  // `Instruction::FinalizeDecode`.
  bool LazyDecodeInstruction(
      uint64_t address, const std::string &inst_bytes,
      Instruction &inst) const final;

  // Maximum number of bytes in an instruction.
  uint64_t MaxInstructionSize(void) const final;

  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final;

 private:

  // Decode an instuction.
  bool DecodeInstruction(
      uint64_t address, const std::string &inst_bytes,
      Instruction &inst, bool is_lazy) const;

  X86Arch(void) = delete;
};


X86Arch::X86Arch(OSName os_name_, ArchName arch_name_)
    : Arch(os_name_, arch_name_) {

  static bool xed_is_initialized = false;
  if (!xed_is_initialized) {
    DLOG(INFO) << "Initializing XED tables";
    xed_tables_init();
    xed_is_initialized = true;
  }
}

X86Arch::~X86Arch(void) {}

// Maximum number of bytes in an instruction for this particular architecture.
uint64_t X86Arch::MaxInstructionSize(void) const {
  return 15;
}

// Default calling convention for this architecture.
llvm::CallingConv::ID X86Arch::DefaultCallingConv(void) const {
  if (IsX86()) {
    switch (os_name) {
      case kOSInvalid:
      case kOSmacOS:
      case kOSLinux:
      case kOSWindows:
        return llvm::CallingConv::C;  // cdecl.
    }
  } else {
    switch (os_name) {
      case kOSInvalid:
      case kOSmacOS:
      case kOSLinux:
        return llvm::CallingConv::X86_64_SysV;
      case kOSWindows:
        return llvm::CallingConv::Win64;
    }
  }
}

// Get the LLVM triple for this architecture.
llvm::Triple X86Arch::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
      triple.setArch(llvm::Triple::x86_64);
      break;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
      triple.setArch(llvm::Triple::x86);
      break;
    default:
      LOG(FATAL)
          << "Cannot get triple for non-x86 architecture "
          << GetArchName(arch_name);
  }

  return triple;
}

// Get the LLVM DataLayout for a module.
llvm::DataLayout X86Arch::DataLayout(void) const {
  std::string dl;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
      break;

    case kOSLinux:
      switch (arch_name) {
        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          dl = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          dl = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128";
          break;
        default:
          LOG(FATAL)
              << "Cannot get data layout non-x86 architecture "
              << GetArchName(arch_name);
          break;
      }
      break;

    case kOSmacOS:
      switch (arch_name) {
        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          dl = "e-m:o-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          dl = "e-m:o-p:32:32-f64:32:64-f80:128-n8:16:32-S128";
          break;
        default:
          LOG(FATAL)
              << "Cannot get data layout for non-x86 architecture "
              << GetArchName(arch_name);
      }
      break;

    case kOSWindows:
      switch (arch_name) {
        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          dl = "e-m:w-i64:64-f80:128-n8:16:32:64-S128";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          dl = "e-m:x-p:32:32-i64:64-f80:32-n8:16:32-a:0:32-S32";
          break;
        default:
          LOG(FATAL)
              << "Cannot get data layout for non-x86 architecture "
              << GetArchName(arch_name);
      }
      break;
  }

  return llvm::DataLayout(dl);
}

// Decode an instuction.
bool X86Arch::DecodeInstruction(
    uint64_t address,
    const std::string &inst_bytes,
    Instruction &inst, bool is_lazy) const {

  inst.pc = address;
  inst.arch_name = arch_name;
  inst.category = Instruction::kCategoryInvalid;

  xed_decoded_inst_t xedd_;
  xed_decoded_inst_t *xedd = &xedd_;
  auto mode = 32 == address_size ? &kXEDState32 : &kXEDState64;

  if (!DecodeXED(xedd, mode, inst_bytes, address)) {
    LOG(ERROR) << "DecodeXED() could not decode the following opcodes: " << inst.Serialize();
    return false;
  }

  inst.operand_size = xed_decoded_inst_get_operand_width(xedd);
  inst.bytes = inst_bytes.substr(0, xed_decoded_inst_get_length(xedd));
  inst.category = CreateCategory(xedd);
  inst.next_pc = address + xed_decoded_inst_get_length(xedd);

  // Wrap an instruction in atomic begin/end if it accesses memory with RMW
  // semantics or with a LOCK prefix.
  if (xed_operand_values_get_atomic(xedd) ||
      xed_operand_values_has_lock_prefix(xedd) ||
      XED_CATEGORY_SEMAPHORE == xed_decoded_inst_get_category(xedd)) {
    inst.is_atomic_read_modify_write = true;
  }

  if (Instruction::kCategoryConditionalAsyncHyperCall == inst.category) {
    DecodeConditionalInterrupt(inst);
  }

  auto iform = xed_decoded_inst_get_iform_enum(xedd);

  if (!is_lazy || inst.IsControlFlow()) {
    inst.function = InstructionFunctionName(xedd);

    // Lift the operands. This creates the arguments for us to call the
    // instuction implementation.
    auto xedi = xed_decoded_inst_inst(xedd);
    auto num_operands = xed_decoded_inst_noperands(xedd);
    for (auto i = 0U; i < num_operands; ++i) {
      auto xedo = xed_inst_operand(xedi, i);
      if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
        DecodeOperand(inst, xedd, xedo);
      }
    }

    if (inst.IsFunctionCall()) {
      DecodeFallThroughPC(inst, xedd);
    }

    // All non-control FPU instructions update the last instruction pointer
    // and opcode.
    if (XED_ISA_SET_X87 == xed_decoded_inst_get_isa_set(xedd) ||
        XED_ISA_SET_FCMOV == xed_decoded_inst_get_isa_set(xedd) ||
        XED_CATEGORY_X87_ALU == xed_decoded_inst_get_category(xedd)) {
      auto set_ip_dp = false;
      const auto get_attr = xed_decoded_inst_get_attribute;
      switch (iform) {
        case XED_IFORM_FNOP:
        case XED_IFORM_FINCSTP:
        case XED_IFORM_FDECSTP:
        case XED_IFORM_FFREE_X87:
        case XED_IFORM_FFREEP_X87:
          set_ip_dp = true;
          break;
        default:
          set_ip_dp = !get_attr(xedd, XED_ATTRIBUTE_X87_CONTROL) &&
                      !get_attr(xedd, XED_ATTRIBUTE_X87_MMX_STATE_CW) &&
                      !get_attr(xedd, XED_ATTRIBUTE_X87_MMX_STATE_R) &&
                      !get_attr(xedd, XED_ATTRIBUTE_X87_MMX_STATE_W) &&
                      !get_attr(xedd, XED_ATTRIBUTE_X87_NOWAIT);
          break;
      }

      if (set_ip_dp) {
        DecodeX87LastIpDp(inst);
      }
    }

    if (xed_decoded_inst_is_xacquire(xedd) ||
        xed_decoded_inst_is_xrelease(xedd)) {
      LOG(ERROR)
          << "Ignoring XACQUIRE/XRELEASE prefix at " << std::hex
          << inst.pc << std::dec;
    }
  }

  // Make sure we disallow decoding of AVX instructions when running with non-
  // AVX arch specified. Same thing for AVX512 instructions.
  switch (xed_decoded_inst_get_isa_set(xedd)) {
    case XED_ISA_SET_INVALID:
    case XED_ISA_SET_LAST:
      LOG(ERROR)
          << "Instruction decode of " << xed_iform_enum_t2str(iform)
          << " failed because XED_ISA_SET_LAST.";
      return false;

    case XED_ISA_SET_AVX:
    case XED_ISA_SET_AVX2:
    case XED_ISA_SET_AVX2GATHER:
    case XED_ISA_SET_AVXAES:
    case XED_ISA_SET_AVX_GFNI: {
      auto supp = kArchAMD64 != inst.arch_name &&
                  kArchX86 != inst.arch_name;
      LOG_IF(ERROR, !supp)
          << "Instruction decode of " << xed_iform_enum_t2str(iform)
          << " failed because the current arch is specified "
          << "as " << GetArchName(inst.arch_name) << " but what is needed is "
          << "the _avx or _avx512 variant.";
      return supp;
    }

    case XED_ISA_SET_AVX512BW_128:
    case XED_ISA_SET_AVX512BW_128N:
    case XED_ISA_SET_AVX512BW_256:
    case XED_ISA_SET_AVX512BW_512:
    case XED_ISA_SET_AVX512BW_KOP:
    case XED_ISA_SET_AVX512CD_128:
    case XED_ISA_SET_AVX512CD_256:
    case XED_ISA_SET_AVX512CD_512:
    case XED_ISA_SET_AVX512DQ_128:
    case XED_ISA_SET_AVX512DQ_128N:
    case XED_ISA_SET_AVX512DQ_256:
    case XED_ISA_SET_AVX512DQ_512:
    case XED_ISA_SET_AVX512DQ_KOP:
    case XED_ISA_SET_AVX512DQ_SCALAR:
    case XED_ISA_SET_AVX512ER_512:
    case XED_ISA_SET_AVX512ER_SCALAR:
    case XED_ISA_SET_AVX512F_128:
    case XED_ISA_SET_AVX512F_128N:
    case XED_ISA_SET_AVX512F_256:
    case XED_ISA_SET_AVX512F_512:
    case XED_ISA_SET_AVX512F_KOP:
    case XED_ISA_SET_AVX512F_SCALAR:
    case XED_ISA_SET_AVX512PF_512:
    case XED_ISA_SET_AVX512_4FMAPS_512:
    case XED_ISA_SET_AVX512_4FMAPS_SCALAR:
    case XED_ISA_SET_AVX512_4VNNIW_512:
    case XED_ISA_SET_AVX512_BITALG_128:
    case XED_ISA_SET_AVX512_BITALG_256:
    case XED_ISA_SET_AVX512_BITALG_512:
    case XED_ISA_SET_AVX512_GFNI_128:
    case XED_ISA_SET_AVX512_GFNI_256:
    case XED_ISA_SET_AVX512_GFNI_512:
    case XED_ISA_SET_AVX512_IFMA_128:
    case XED_ISA_SET_AVX512_IFMA_256:
    case XED_ISA_SET_AVX512_IFMA_512:
    case XED_ISA_SET_AVX512_VAES_128:
    case XED_ISA_SET_AVX512_VAES_256:
    case XED_ISA_SET_AVX512_VAES_512:
    case XED_ISA_SET_AVX512_VBMI2_128:
    case XED_ISA_SET_AVX512_VBMI2_256:
    case XED_ISA_SET_AVX512_VBMI2_512:
    case XED_ISA_SET_AVX512_VBMI_128:
    case XED_ISA_SET_AVX512_VBMI_256:
    case XED_ISA_SET_AVX512_VBMI_512:
    case XED_ISA_SET_AVX512_VNNI_128:
    case XED_ISA_SET_AVX512_VNNI_256:
    case XED_ISA_SET_AVX512_VNNI_512:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_128:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_256:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_512:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_128:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_256:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_512: {
      auto supp = kArchAMD64_AVX512 == inst.arch_name ||
                  kArchX86_AVX512 == inst.arch_name;
      LOG_IF(ERROR, !supp)
          << "Instruction decode of " << xed_iform_enum_t2str(iform)
          << " failed because the current arch is specified "
          << "as " << GetArchName(inst.arch_name) << " but what is needed is "
          << "the _avx512 variant.";
      return supp;
    }
    default:
      return true;
  }

  return true;
}

bool X86Arch::DecodeInstruction(
    uint64_t address,
    const std::string &inst_bytes,
    Instruction &inst) const {
  inst.arch_for_decode = nullptr;
  return DecodeInstruction(address, inst_bytes, inst, false);
}

// Fully decode any control-flow transfer instructions, but only partially
// decode other instructions.
bool X86Arch::LazyDecodeInstruction(
    uint64_t address, const std::string &inst_bytes,
    Instruction &inst) const {
  inst.arch_for_decode = nullptr;
  if (DecodeInstruction(address, inst_bytes, inst, true)) {
    if (!inst.IsControlFlow()) {
      inst.arch_for_decode = this;
    }
    return true;
  } else {
    return false;
  }
}

}  // namespace

// TODO(pag): We pretend that these are singletons, but they aren't really!
const Arch *Arch::GetX86(
    OSName os_name_, ArchName arch_name_) {
  return new X86Arch(os_name_, arch_name_);
}

}  // namespace remill
