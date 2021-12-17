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

#include "../Arch.h"  // For `Arch` and `ArchImpl`.

#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "XED.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

// clang-format off
#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 1
#define ADDRESS_SIZE_BITS 64
#define INCLUDED_FROM_REMILL
#include "remill/Arch/X86/Runtime/State.h"

// clang-format on

namespace remill {
namespace {

static const xed_state_t kXEDState32 = {XED_MACHINE_MODE_LONG_COMPAT_32,
                                        XED_ADDRESS_WIDTH_32b};

static const xed_state_t kXEDState64 = {XED_MACHINE_MODE_LONG_64,
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

static bool IsDirectFunctionCallFar(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_CALL_FAR == iclass && XED_OPERAND_PTR == op_name;
}

static bool IsIndirectFunctionCall(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_CALL_NEAR == iclass && XED_OPERAND_RELBR != op_name;
}

static bool IsIndirectFunctionCallFar(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_CALL_FAR == iclass && XED_OPERAND_MEM0 == op_name;
}

static bool IsDirectJump(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR == op_name;
}

static bool IsDirectJumpFar(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_JMP_FAR == iclass && XED_OPERAND_PTR == op_name;
}

static bool IsIndirectJump(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return (XED_ICLASS_JMP == iclass && XED_OPERAND_RELBR != op_name) ||
         XED_ICLASS_XEND == iclass || XED_ICLASS_XABORT == iclass;
}

static bool IsIndirectJumpFar(const xed_decoded_inst_t *xedd) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  return XED_ICLASS_JMP_FAR == iclass && XED_OPERAND_MEM0 == op_name;
}

//It checks if the instruction might fault and uses StopFailure to recover
static bool UsesStopFailure(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
    case XED_ICLASS_XEND:
    case XED_ICLASS_XGETBV: return true;
    default: return false;
  }
}

static bool IsNoOp(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_NOP:
    case XED_CATEGORY_WIDENOP: return true;
    default: return false;
  }
}

static bool IsError(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_iclass(xedd)) {
    case XED_ICLASS_HLT:
    case XED_ICLASS_UD0:
    case XED_ICLASS_UD1:
    case XED_ICLASS_UD2: return true;
    default: return false;
  }
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

  } else if (IsDirectJumpFar(xedd) || IsIndirectJumpFar(xedd) ||
             IsDirectFunctionCallFar(xedd) || IsIndirectFunctionCallFar(xedd)) {
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
    {XED_IFORM_XCHG_MEMv_GPRv, XED_IFORM_XCHG_MEMv_GPRv},
    {XED_IFORM_XCHG_MEMb_GPR8, XED_IFORM_XCHG_MEMb_GPR8},
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

  // Some instructions are "scalable", i.e. there are variants of the
  // instruction for each effective operand size. We represent these in
  // the semantics files with `_<size>`, so we need to look up the correct
  // selection.
  if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_SCALABLE)) {
    ss << "_";
    ss << xed_decoded_inst_get_operand_width(xedd);
  }

  // Suffix the ISEL function name with the segment or control register names,
  // as a runtime may need to perform complex actions that are specific to
  // the register used.
  if (XED_IFORM_MOV_SEG_MEMw == iform || XED_IFORM_MOV_SEG_GPR16 == iform ||
      XED_IFORM_MOV_CR_CR_GPR32 == iform ||
      XED_IFORM_MOV_CR_CR_GPR64 == iform) {
    ss << "_";
    ss << xed_reg_enum_t2str(xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0));
  }

  return ss.str();
}

// Decode an instruction into the XED instuction format.
static bool DecodeXED(xed_decoded_inst_t *xedd, const xed_state_t *mode,
                      std::string_view inst_bytes, uint64_t address) {
  auto num_bytes = inst_bytes.size();
  auto bytes = reinterpret_cast<const uint8_t *>(inst_bytes.data());
  xed_decoded_inst_zero_set_mode(xedd, mode);
  xed_decoded_inst_set_input_chip(xedd, XED_CHIP_INVALID);
  auto err = xed_decode(xedd, bytes, static_cast<uint32_t>(num_bytes));

  if (XED_ERROR_NONE != err) {
    std::stringstream ss;
    for (auto b : inst_bytes) {
      ss << ' ' << std::hex << std::setw(2) << std::setfill('0')
         << (static_cast<unsigned>(b) & 0xFFu);
    }
    DLOG(WARNING)
        << "Unable to decode instruction at " << std::hex << address
        << " with bytes" << ss.str()
        << " and error: " << xed_error_enum_t2str(err) << std::dec;
    return false;
  }

  return true;
}

// Variable operand for a read register.
static Operand::Register RegOp(xed_reg_enum_t reg) {
  Operand::Register reg_op;
  if (XED_REG_INVALID != reg) {
    switch (reg) {
      case XED_REG_ST0: reg_op.name = "ST0"; break;
      case XED_REG_ST1: reg_op.name = "ST1"; break;
      case XED_REG_ST2: reg_op.name = "ST2"; break;
      case XED_REG_ST3: reg_op.name = "ST3"; break;
      case XED_REG_ST4: reg_op.name = "ST4"; break;
      case XED_REG_ST5: reg_op.name = "ST5"; break;
      case XED_REG_ST6: reg_op.name = "ST6"; break;
      case XED_REG_ST7: reg_op.name = "ST7"; break;
      default: reg_op.name = xed_reg_enum_t2str(reg); break;
    }
    if (XED_REG_X87_FIRST <= reg && XED_REG_X87_LAST >= reg) {
      reg_op.size = 64;
    } else {
      reg_op.size = xed_get_register_width_bits64(reg);
    }
  }
  return reg_op;
}

static Operand::Register SegBaseRegOp(xed_reg_enum_t reg, unsigned addr_size) {
  auto op = RegOp(reg);
  if (XED_REG_INVALID != reg) {
    op.name += "BASE";
    op.size = addr_size;
  }
  return op;
}

// Decode a memory operand.
static void DecodeMemory(Instruction &inst, const xed_decoded_inst_t *xedd,
                         const xed_operand_t *xedo, int mem_index) {

  auto iform = xed_decoded_inst_get_iform_enum(xedd);
  auto iclass = xed_decoded_inst_get_iclass(xedd);
  auto op_name = xed_operand_name(xedo);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto base_wide = xed_get_largest_enclosing_register(base);

  // NOTE(pag): This isn't quite right (eg. it's for SCALABALE only), but works
  // mostly right most of the time.
  auto size = xed_decoded_inst_get_operand_width(xedd);
  if (XED_IFORM_MOV_MEMw_SEG == iform) {
    size = 16;
  }

  auto raw_segment_reg = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto deduce_segment = [&](auto segment_reg) {
    // Deduce the implicit segment register if it is absent.
    if (XED_REG_INVALID != segment_reg) {
      return segment_reg;
    }
    if (XED_REG_RSP == base_wide || XED_REG_RBP == base_wide) {
      return XED_REG_SS;
    }
    return XED_REG_DS;
  };
  auto ignore_segment = [&](auto segment_reg) {
    // On AMD64, only the `FS` and `GS` segments are non-zero.
    if (Is64Bit(inst.arch_name) && XED_REG_FS != segment_reg &&
        XED_REG_GS != segment_reg) {
      return XED_REG_INVALID;
    }

    // AGEN operands, e.g. for the `LEA` instuction, can be marked with an
    // explicit segment, but it is ignored.
    if (XED_OPERAND_AGEN == op_name) {
      return XED_REG_INVALID;
    }

    // No need to ignore it
    return segment_reg;
  };
  auto segment_reg = ignore_segment(deduce_segment(raw_segment_reg));

  // Special case: `POP [xSP + ...] uses the value of `xSP` after incrementing
  // it by the stack width. For more reasoning see definition of semantics for POP.
  if (XED_ICLASS_POP == iclass && XED_REG_RSP == base_wide) {
    inst.function = "POP_MEM_XSP_" + std::to_string(size);
  }

  Operand op = {};
  op.size = size;

  op.type = Operand::kTypeAddress;
  op.addr.address_size =
      xed_decoded_inst_get_memop_address_width(xedd, mem_index);

  op.addr.segment_base_reg = SegBaseRegOp(segment_reg, op.addr.address_size);
  op.addr.base_reg = RegOp(base);
  op.addr.index_reg = RegOp(index);
  op.addr.scale = XED_REG_INVALID != index ? static_cast<int64_t>(scale) : 0;
  op.addr.displacement = disp;

  // PC-relative memory accesses are relative to the next PC.
  if (XED_REG_RIP == base_wide) {
    op.addr.base_reg.name = "NEXT_PC";
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
static void DecodeImmediate(Instruction &inst, const xed_decoded_inst_t *xedd,
                            xed_operand_enum_t op_name) {
  auto val = 0ULL;
  auto is_signed = false;
  auto operand_size = xed_decoded_inst_get_operand_width(xedd);

  Operand op = {};
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;

  if (XED_OPERAND_PTR == op_name) {
    auto ptr_size = xed_decoded_inst_get_branch_displacement_width_bits(xedd);
    CHECK(ptr_size <= operand_size)
        << "Pointer size is greater than effective operand size at " << std::hex
        << inst.pc << ".";
    op.size = ptr_size;

    val = static_cast<uint64_t>(xed_decoded_inst_get_branch_displacement(xedd));
  } else {
    auto imm_size = xed_decoded_inst_get_immediate_width_bits(xedd);
    CHECK(imm_size <= operand_size)
        << "Immediate size is greater than effective operand size at "
        << std::hex << inst.pc << ".";
    op.size = imm_size;

    if (XED_OPERAND_IMM0SIGNED == op_name ||
        xed_operand_values_get_immediate_is_signed(xedd)) {
      val = static_cast<uint64_t>(
          static_cast<int64_t>(xed_decoded_inst_get_signed_immediate(xedd)));
      is_signed = true;

    } else if (XED_OPERAND_IMM0 == op_name) {
      val =
          static_cast<uint64_t>(xed_decoded_inst_get_unsigned_immediate(xedd));

    } else if (XED_OPERAND_IMM1_BYTES == op_name ||
               XED_OPERAND_IMM1 == op_name) {
      val = static_cast<uint64_t>(xed_decoded_inst_get_second_immediate(xedd));

    } else {
      CHECK(false) << "Unexpected immediate type "
                   << xed_operand_enum_t2str(op_name) << ".";
    }
  }

  op.imm.is_signed = is_signed;
  op.imm.val = val;
  inst.operands.push_back(op);
}

// Decode a register operand.
static void DecodeRegister(Instruction &inst, const xed_decoded_inst_t *xedd,
                           const xed_operand_t *xedo,
                           xed_operand_enum_t op_name) {
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  CHECK(XED_REG_INVALID != reg) << "Cannot get name of invalid register.";

  Operand op = {};
  op.type = Operand::kTypeRegister;
  op.reg = RegOp(reg);
  op.size = op.reg.size;

  // Pass the register by reference.
  if (xed_operand_written(xedo)) {
    op.action = Operand::kActionWrite;

    if (Is64Bit(inst.arch_name)) {
      if (XED_REG_GPR32_FIRST <= reg && XED_REG_GPR32_LAST >= reg) {
        op.reg = RegOp(xed_get_largest_enclosing_register(reg));
        op.size = op.reg.size;

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

// Condition variable.
static void DecodeConditionalInterrupt(Instruction &inst) {
  inst.operands.emplace_back();
  auto &cond_op = inst.operands.back();

  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
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
  not_taken_op.addr.base_reg.name = "NEXT_PC";
  not_taken_op.addr.base_reg.size = pc_width;
  not_taken_op.addr.displacement = 0;
  not_taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(not_taken_op);

  inst.branch_not_taken_pc = inst.next_pc;
}

// Decode a relative branch target.
static void DecodeConditionalBranch(Instruction &inst,
                                    const xed_decoded_inst_t *xedd) {
  auto pc_reg = Is64Bit(inst.arch_name) ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp =
      static_cast<int64_t>(xed_decoded_inst_get_branch_displacement(xedd));

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
  taken_op.addr.base_reg.name = "NEXT_PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp;
  taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(taken_op);

  inst.branch_taken_pc =
      static_cast<uint64_t>(static_cast<int64_t>(inst.next_pc) + disp);

  DecodeFallThroughPC(inst, xedd);
}

// Decode a relative branch target.
static void DecodeRelativeBranch(Instruction &inst,
                                 const xed_decoded_inst_t *xedd) {
  auto pc_reg = Is64Bit(inst.arch_name) ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp =
      static_cast<int64_t>(xed_decoded_inst_get_branch_displacement(xedd));

  // Taken branch.
  Operand taken_op = {};
  taken_op.action = Operand::kActionRead;
  taken_op.type = Operand::kTypeAddress;
  taken_op.size = pc_width;
  taken_op.addr.address_size = pc_width;
  taken_op.addr.base_reg.name = "NEXT_PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp;
  taken_op.addr.kind = Operand::Address::kControlFlowTarget;
  inst.operands.push_back(taken_op);

  inst.branch_taken_pc =
      static_cast<uint64_t>(static_cast<int64_t>(inst.next_pc) + disp);
  inst.branch_not_taken_pc = inst.next_pc;
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

  CHECK(i >= 2) << "Failed to find FPU opcode byte for instruction "
                << inst.Serialize();

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
static void DecodeOperand(Instruction &inst, const xed_decoded_inst_t *xedd,
                          const xed_operand_t *xedo) {
  switch (auto op_name = xed_operand_name(xedo)) {
    case XED_OPERAND_AGEN:
    case XED_OPERAND_MEM0: DecodeMemory(inst, xedd, xedo, 0); break;

    case XED_OPERAND_MEM1: DecodeMemory(inst, xedd, xedo, 1); break;

    case XED_OPERAND_IMM0SIGNED:
    case XED_OPERAND_IMM0:
    case XED_OPERAND_IMM1_BYTES:
    case XED_OPERAND_IMM1:
    case XED_OPERAND_PTR: DecodeImmediate(inst, xedd, op_name); break;

    case XED_OPERAND_REG:
    case XED_OPERAND_REG0:
    case XED_OPERAND_REG1:
    case XED_OPERAND_REG2:
    case XED_OPERAND_REG3:
    case XED_OPERAND_REG4:
    case XED_OPERAND_REG5:
    case XED_OPERAND_REG6:
    case XED_OPERAND_REG7:
    case XED_OPERAND_REG8: DecodeRegister(inst, xedd, xedo, op_name); break;

    case XED_OPERAND_RELBR:
      if (Instruction::kCategoryConditionalBranch == inst.category) {
        DecodeConditionalBranch(inst, xedd);
      } else {
        DecodeRelativeBranch(inst, xedd);
      }
      break;

    default:
      LOG(FATAL) << "Unexpected operand type "
                 << xed_operand_enum_t2str(op_name) << ".";
      return;
  }
}

class X86Arch final : public Arch {
 public:
  X86Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  virtual ~X86Arch(void);

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void) const final;

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void) const final;

  // Decode an instruction.
  bool DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                         Instruction &inst) const final;

  // Maximum number of bytes in an instruction.
  uint64_t MinInstructionAlign(void) const final;
  uint64_t MinInstructionSize(void) const final;
  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const final;

  llvm::Triple Triple(void) const final;
  llvm::DataLayout DataLayout(void) const final;

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final;

  // Populate the table of register information.
  void PopulateRegisterTable(void) const final;

  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void FinishLiftedFunctionInitialization(
      llvm::Module *module, llvm::Function *bb_func) const final;

 private:
  X86Arch(void) = delete;
};

X86Arch::X86Arch(llvm::LLVMContext *context_, OSName os_name_,
                 ArchName arch_name_)
    : Arch(context_, os_name_, arch_name_) {

  static bool xed_is_initialized = false;
  if (!xed_is_initialized) {
    DLOG(INFO) << "Initializing XED tables";
    xed_tables_init();
    xed_is_initialized = true;
  }
}

X86Arch::~X86Arch(void) {}

uint64_t X86Arch::MinInstructionAlign(void) const {
  return 1;
}

uint64_t X86Arch::MinInstructionSize(void) const {
  return 1;
}

// Maximum number of bytes in an instruction for this particular architecture.
uint64_t X86Arch::MaxInstructionSize(bool) const {
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
      case kOSSolaris: return llvm::CallingConv::C;  // cdecl.
    }
  } else {
    switch (os_name) {
      case kOSInvalid:
      case kOSmacOS:
      case kOSLinux:
      case kOSSolaris: return llvm::CallingConv::X86_64_SysV;
      case kOSWindows: return llvm::CallingConv::Win64;
    }
  }
}

// Get the LLVM triple for this architecture.
llvm::Triple X86Arch::Triple(void) const {
  auto triple = BasicTriple();
  switch (arch_name) {
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512: triple.setArch(llvm::Triple::x86_64); break;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512: triple.setArch(llvm::Triple::x86); break;
    default:
      LOG(FATAL) << "Cannot get triple for non-x86 architecture "
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
    case kOSSolaris:  // Probably.
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
          LOG(FATAL) << "Cannot get data layout non-x86 architecture "
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
          LOG(FATAL) << "Cannot get data layout for non-x86 architecture "
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
          LOG(FATAL) << "Cannot get data layout for non-x86 architecture "
                     << GetArchName(arch_name);
      }
      break;
  }

  return llvm::DataLayout(dl);
}

static bool IsAVX(xed_isa_set_enum_t isa_set, xed_category_enum_t category) {
  switch (isa_set) {
    case XED_ISA_SET_AVX:
    case XED_ISA_SET_AVX2:
    case XED_ISA_SET_AVX2GATHER:
    case XED_ISA_SET_AVXAES:
    case XED_ISA_SET_AVX_GFNI:
    case XED_ISA_SET_AVX_VNNI:
      return true;
    default:
      break;
  }
  switch (category) {
    case XED_CATEGORY_AVX:
    case XED_CATEGORY_AVX2:
    case XED_CATEGORY_AVX2GATHER:
      return true;
    default:
      return false;
  }
}

static bool IsAVX512(xed_isa_set_enum_t isa_set, xed_category_enum_t category) {
  switch (isa_set) {
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
    case XED_ISA_SET_AVX512_BF16_128:
    case XED_ISA_SET_AVX512_BF16_256:
    case XED_ISA_SET_AVX512_BF16_512:
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
    case XED_ISA_SET_AVX512_VP2INTERSECT_128:
    case XED_ISA_SET_AVX512_VP2INTERSECT_256:
    case XED_ISA_SET_AVX512_VP2INTERSECT_512:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_128:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_256:
    case XED_ISA_SET_AVX512_VPCLMULQDQ_512:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_128:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_256:
    case XED_ISA_SET_AVX512_VPOPCNTDQ_512:
      return true;
    default:
      break;
  }
  switch (category) {
    case XED_CATEGORY_AVX512:
    case XED_CATEGORY_AVX512_4FMAPS:
    case XED_CATEGORY_AVX512_4VNNIW:
    case XED_CATEGORY_AVX512_BITALG:
    case XED_CATEGORY_AVX512_VBMI:
    case XED_CATEGORY_AVX512_VP2INTERSECT:
      return true;
    default:
      return false;
  }
}

// Decode the destination register of a `pop <reg>`, where `byte` is the only
// byte of a 1-byte opcode. On 64-bit, the same decoded by maps to a 64-bit
// register. We apply a fixup below in `FillFusedCallPopRegOperands` to account
// for upgrading the register.
static const char *FusablePopReg32(char byte) {
  switch (static_cast<uint8_t>(byte)) {
    case 0x58: return "EAX";
    case 0x59: return "ECX";
    case 0x5a: return "EDX";
    case 0x5b: return "EBX";
    // NOTE(pag): We ignore `0x5c`, which is `pop rsp`, as that has funny
    //            semantics and would be unusual to fuse.
    case 0x5d: return "EBP";
    case 0x5e: return "ESI";
    case 0x5f: return "EDI";

    default: return nullptr;
  }
}

// Decode the destination register of a `pop r8` through `pop r10`, assuming
// that we've already decoded the `0x41` prefix, and `byte` is the second byte
// of the two-byte opcode.
static const char *FusablePopReg64(char byte) {
  switch (static_cast<uint8_t>(byte)) {
    case 0x58: return "R8";
    case 0x59: return "R9";
    case 0x5a: return "R10";
    case 0x5b: return "R11";
    case 0x5c: return "R12";
    case 0x5d: return "R13";
    case 0x5e: return "R14";
    case 0x5f: return "R15";
    default: return nullptr;
  }
}

// Fill in the operands for a fused `call+pop` pair. This ends up acting like
// a `mov` variant, and the semantic is located in `DATAXFER`. Fusing of this
// pair is beneficial to avoid downstream users from treating the initial call
// as semantically being a function call, when really this is more of a move
// instruction. Downstream users like McSema and Anvill benefit from seeing this
// as a MOV-variant because of how they identify cross-references related to
// uses of the program counter (`PC`) register.
static void FillFusedCallPopRegOperands(Instruction &inst,
                                        unsigned address_size,
                                        const char *dest_reg_name,
                                        unsigned call_inst_len) {
  inst.operands.resize(2);
  auto &dest = inst.operands[0];
  auto &src = inst.operands[1];

  dest.type = Operand::kTypeRegister;
  dest.reg.name = dest_reg_name;
  dest.reg.size = address_size;
  dest.size = address_size;
  dest.action = Operand::kActionWrite;

  src.type = Operand::kTypeAddress;
  src.size = address_size;
  src.action = Operand::kActionRead;
  src.addr.address_size = address_size;
  src.addr.base_reg.name = "PC";
  src.addr.base_reg.size = address_size;
  src.addr.displacement = static_cast<int64_t>(call_inst_len);
  src.addr.kind = Operand::Address::kAddressCalculation;

  if (32 == address_size) {
    inst.function = "CALL_POP_FUSED_32";

  } else {
    inst.function = "CALL_POP_FUSED_64";

    // Rename the register to be a 64-bit register. `pop eax` when decoded as
    // a 32-bit instruction, and `pop rax` when decoded as a 64-bit instruction,
    // both have the same binary representation. So for these cases, we store
    // a 32-bit register name, such as `EAX` in `dest_reg_name`. If we're doing
    // a fuse on 64-bit, then we want to upgrade the destination register to
    // its `R`-prefixed variant, lest we accidentally discard the high 32 bits.
    //
    // For the case of `pop r8` et al. on 64 bit, `dest_reg_name` contains the
    // 64-bit register name, and so the injection of `R` acts as a no-op.
    //
    // NOTE(pag): See `FusablePopReg32` and `FusablePopReg64`.
    dest.reg.name[0] = 'R';
  }
}

// Decode an instuction.
bool X86Arch::DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                                Instruction &inst) const {

  inst.pc = address;
  inst.arch = this;
  inst.arch_name = arch_name;
  inst.sub_arch_name = kArchInvalid;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();

  xed_decoded_inst_t xedd_;
  xed_decoded_inst_t *xedd = &xedd_;
  const auto mode = 32 == address_size ? &kXEDState32 : &kXEDState64;
  if (!DecodeXED(xedd, mode, inst_bytes, address)) {
    return false;
  }

  auto len = xed_decoded_inst_get_length(xedd);
  auto extra_len = 0u;  // From fusing.
  const auto iform = xed_decoded_inst_get_iform_enum(xedd);
  const auto xedi = xed_decoded_inst_inst(xedd);
  const auto num_operands = xed_decoded_inst_noperands(xedd);
  const auto xedv = xed_decoded_inst_operands_const(xedd);
  const auto isa_set = xed_decoded_inst_get_isa_set(xedd);
  const auto category = xed_decoded_inst_get_category(xedd);

  // Re-classify this instruction to its sub-architecture.
  if (IsAVX512(isa_set, category)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX512 : kArchAMD64_AVX512;
  } else if (IsAVX(isa_set, category)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX : kArchAMD64_AVX;
  } else if (xed_classify_avx512(xedd) || xed_classify_avx512_maskop(xedd)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX512 : kArchAMD64_AVX512;
  } else if (xed_classify_avx(xedd)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX : kArchAMD64_AVX;
  } else {
    inst.sub_arch_name = 32 == address_size ? kArchX86 : kArchAMD64;
  }

  // Make sure we know about
  if (static_cast<unsigned>(inst.arch_name) <
      static_cast<unsigned>(inst.sub_arch_name)) {
    LOG(ERROR)
        << "Instruction decode of " << xed_iform_enum_t2str(iform)
        << " requires the " << GetArchName(inst.sub_arch_name)
        << " architecture semantics to lift but was decoded using the "
        << GetArchName(inst.arch_name) << " architecture";

    inst.Reset();
    inst.category = Instruction::kCategoryInvalid;
    return false;
  }

  // Look for instruction fusing opportunities. For now, just `call; pop`.
  const char *is_fused_call_pop = nullptr;
  if (len < inst_bytes.size() &&
      (iform == XED_IFORM_CALL_NEAR_RELBRd ||
       iform == XED_IFORM_CALL_NEAR_RELBRz) &&
      !xed_decoded_inst_get_branch_displacement(xedd)) {
    is_fused_call_pop = FusablePopReg32(inst_bytes[len]);

    // Change the instruction length (to influence `next_pc` calculation) and
    // the instruction category, so that users no longer interpret this
    // instruction as semantically being a call.
    if (is_fused_call_pop) {
      extra_len = 1u;
      inst.category = Instruction::kCategoryNormal;

    // Look for `pop r8` et al.
    } else if (64 == address_size &&
               (2 + len) <= inst_bytes.size() &&
               inst_bytes[len] == 0x41) {
      is_fused_call_pop = FusablePopReg64(inst_bytes[len + 1]);
      if (is_fused_call_pop) {
        extra_len = 2u;
        inst.category = Instruction::kCategoryNormal;
      }
    }
  }

  inst.category = CreateCategory(xedd);
  inst.next_pc = address + len + extra_len;

  // Fiddle with the size of the bytes.
  if (!inst.bytes.empty() && inst.bytes.data() == inst_bytes.data()) {
    CHECK_LE(len + extra_len, inst.bytes.size());
    inst.bytes.resize(len + extra_len);
  } else {
    inst.bytes = inst_bytes.substr(0, len + extra_len);
  }

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

  // Lift the operands. This creates the arguments for us to call the
  // instuction implementation.
  if (xed_operand_values_has_segment_prefix(xedv)) {
    auto reg_name = xed_reg_enum_t2str(xed_operand_values_segment_prefix(xedv));
    inst.segment_override = RegisterByName(reg_name);
  }

  if (is_fused_call_pop) {
    FillFusedCallPopRegOperands(inst, address_size, is_fused_call_pop,
                                len);

  } else {
    inst.function = InstructionFunctionName(xedd);
    for (auto i = 0U; i < num_operands; ++i) {
      auto xedo = xed_inst_operand(xedi, i);
      if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
        DecodeOperand(inst, xedd, xedo);
      }
    }
  }

  // Control flow operands update the next program counter.
  if (inst.IsControlFlow()) {
    inst.operands.emplace_back();
    auto &dst_ret_pc = inst.operands.back();
    dst_ret_pc.type = Operand::kTypeRegister;
    dst_ret_pc.action = Operand::kActionWrite;
    dst_ret_pc.size = address_size;
    dst_ret_pc.reg.name = "NEXT_PC";
    dst_ret_pc.reg.size = address_size;
  }

  if (inst.IsFunctionCall()) {
    DecodeFallThroughPC(inst, xedd);

    // The semantics will store the return address in `RETURN_PC`. This is to
    // help synchronize program counters when lifting instructions on an ISA
    // with delay slots.
    inst.operands.emplace_back();
    auto &dst_ret_pc = inst.operands.back();
    dst_ret_pc.type = Operand::kTypeRegister;
    dst_ret_pc.action = Operand::kActionWrite;
    dst_ret_pc.size = address_size;
    dst_ret_pc.reg.name = "RETURN_PC";
    dst_ret_pc.reg.size = address_size;
  }

  if (UsesStopFailure(xedd)) {

    // These instructions might fault and uses the StopFailure to recover.
    // The new operand `next_pc` is added and the REG_PC is set to next_pc
    // before calling the StopFailure

    inst.operands.emplace_back();
    auto &next_pc = inst.operands.back();
    next_pc.type = Operand::kTypeRegister;
    next_pc.action = Operand::kActionRead;
    next_pc.size = address_size;
    next_pc.reg.name = "NEXT_PC";
    next_pc.reg.size = address_size;
  }

  // All non-control FPU instructions update the last instruction pointer
  // and opcode.
  if (XED_ISA_SET_X87 == isa_set || XED_ISA_SET_FCMOV == isa_set ||
      XED_CATEGORY_X87_ALU == category) {
    auto set_ip_dp = false;
    const auto get_attr = xed_decoded_inst_get_attribute;
    switch (iform) {
      case XED_IFORM_FNOP:
      case XED_IFORM_FINCSTP:
      case XED_IFORM_FDECSTP:
      case XED_IFORM_FFREE_X87:
      case XED_IFORM_FFREEP_X87: set_ip_dp = true; break;
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
    LOG(WARNING)
        << "Ignoring XACQUIRE/XRELEASE prefix at " << std::hex << inst.pc
        << std::dec;
  }

  return true;
}

static const std::string_view kSPNames[] = {"RSP", "ESP"};
static const std::string_view kPCNames[] = {"RIP", "EIP"};

// Returns the name of the stack pointer register.
std::string_view X86Arch::StackPointerRegisterName(void) const {
  return kSPNames[IsX86()];
}

// Returns the name of the program counter register.
std::string_view X86Arch::ProgramCounterRegisterName(void) const {
  return kPCNames[IsX86()];
}

// Populate the table of register information.
void X86Arch::PopulateRegisterTable(void) const {

  impl->reg_by_offset.resize(sizeof(X86State));

  CHECK_NOTNULL(context);

  bool has_avx = false;
  bool has_avx512 = false;
  switch (arch_name) {
    case kArchX86_AVX:
    case kArchAMD64_AVX: has_avx = true; break;
    case kArchX86_AVX512:
    case kArchAMD64_AVX512:
      has_avx = true;
      has_avx512 = true;
      break;
    default: break;
  }

  auto u8 = llvm::Type::getInt8Ty(*context);
  auto u16 = llvm::Type::getInt16Ty(*context);
  auto u32 = llvm::Type::getInt32Ty(*context);
  auto u64 = llvm::Type::getInt64Ty(*context);
  auto f80 = llvm::Type::getX86_FP80Ty(*context);
  auto v128 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 128u / 8u);
  auto v256 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 256u / 8u);
  auto v512 = llvm::ArrayType::get(llvm::Type::getInt8Ty(*context), 512u / 8u);
  auto addr = llvm::Type::getIntNTy(*context, address_size);

#define OFFSET_OF(type, access) \
  (reinterpret_cast<uintptr_t>(&reinterpret_cast<const volatile char &>( \
      static_cast<type *>(nullptr)->access)))

#define REG(name, access, type) \
  AddRegister(#name, type, OFFSET_OF(X86State, access), nullptr)

#define SUB_REG(name, access, type, parent_reg_name) \
  AddRegister(#name, type, OFFSET_OF(X86State, access), #parent_reg_name)

#define SUB_REG64(name, access, type, parent_reg_name) \
  if (64 == address_size) { \
    SUB_REG(name, access, type, parent_reg_name); \
  } else { \
    REG(name, access, type); \
  }

#define SUB_REGAVX512(name, access, type, parent_reg_name) \
  if (has_avx512) { \
    SUB_REG(name, access, type, parent_reg_name); \
  } else { \
    REG(name, access, type); \
  }

#define SUB_REGAVX(name, access, type, parent_reg_name) \
  if (has_avx) { \
    SUB_REG(name, access, type, parent_reg_name); \
  } else { \
    REG(name, access, type); \
  }

  if (64 == address_size) {
    REG(RAX, gpr.rax.qword, u64);
    REG(RBX, gpr.rbx.qword, u64);
    REG(RCX, gpr.rcx.qword, u64);
    REG(RDX, gpr.rdx.qword, u64);
    REG(RSI, gpr.rsi.qword, u64);
    REG(RDI, gpr.rdi.qword, u64);
    REG(RSP, gpr.rsp.qword, u64);
    REG(RBP, gpr.rbp.qword, u64);
    REG(RIP, gpr.rip.qword, u64);

    REG(R8, gpr.r8.qword, u64);
    REG(R9, gpr.r9.qword, u64);
    REG(R10, gpr.r10.qword, u64);
    REG(R11, gpr.r11.qword, u64);
    REG(R12, gpr.r12.qword, u64);
    REG(R13, gpr.r13.qword, u64);
    REG(R14, gpr.r14.qword, u64);
    REG(R15, gpr.r15.qword, u64);

    SUB_REG(R8D, gpr.r8.dword, u32, R8);
    SUB_REG(R9D, gpr.r9.dword, u32, R9);
    SUB_REG(R10D, gpr.r10.dword, u32, R10);
    SUB_REG(R11D, gpr.r11.dword, u32, R11);
    SUB_REG(R12D, gpr.r12.dword, u32, R12);
    SUB_REG(R13D, gpr.r13.dword, u32, R13);
    SUB_REG(R14D, gpr.r14.dword, u32, R14);
    SUB_REG(R15D, gpr.r15.dword, u32, R15);

    SUB_REG(R8W, gpr.r8.word, u16, R8D);
    SUB_REG(R9W, gpr.r9.word, u16, R9D);
    SUB_REG(R10W, gpr.r10.word, u16, R10D);
    SUB_REG(R11W, gpr.r11.word, u16, R11D);
    SUB_REG(R12W, gpr.r12.word, u16, R12D);
    SUB_REG(R13W, gpr.r13.word, u16, R13D);
    SUB_REG(R14W, gpr.r14.word, u16, R14D);
    SUB_REG(R15W, gpr.r15.word, u16, R15D);
  }

  SUB_REG64(EAX, gpr.rax.dword, u32, RAX);
  SUB_REG64(EBX, gpr.rbx.dword, u32, RBX);
  SUB_REG64(ECX, gpr.rcx.dword, u32, RCX);
  SUB_REG64(EDX, gpr.rdx.dword, u32, RDX);
  SUB_REG64(ESI, gpr.rsi.dword, u32, RSI);
  SUB_REG64(EDI, gpr.rdi.dword, u32, RDI);
  SUB_REG64(ESP, gpr.rsp.dword, u32, RSP);
  SUB_REG64(EBP, gpr.rbp.dword, u32, RBP);
  SUB_REG64(EIP, gpr.rip.dword, u32, RIP);

  SUB_REG(AX, gpr.rax.word, u16, EAX);
  SUB_REG(BX, gpr.rbx.word, u16, EBX);
  SUB_REG(CX, gpr.rcx.word, u16, ECX);
  SUB_REG(DX, gpr.rdx.word, u16, EDX);
  SUB_REG(SI, gpr.rsi.word, u16, ESI);
  SUB_REG(DI, gpr.rdi.word, u16, EDI);
  SUB_REG(SP, gpr.rsp.word, u16, ESP);
  SUB_REG(BP, gpr.rbp.word, u16, EBP);
  SUB_REG(IP, gpr.rip.word, u16, EIP);
  SUB_REG(AH, gpr.rax.byte.high, u8, AX);
  SUB_REG(BH, gpr.rbx.byte.high, u8, BX);
  SUB_REG(CH, gpr.rcx.byte.high, u8, CX);
  SUB_REG(DH, gpr.rdx.byte.high, u8, DX);
  SUB_REG(AL, gpr.rax.byte.low, u8, AX);
  SUB_REG(BL, gpr.rbx.byte.low, u8, BX);
  SUB_REG(CL, gpr.rcx.byte.low, u8, CX);
  SUB_REG(DL, gpr.rdx.byte.low, u8, DX);

  if (64 == address_size) {
    SUB_REG(SIL, gpr.rsi.byte.low, u8, SI);
    SUB_REG(DIL, gpr.rdi.byte.low, u8, DI);
    SUB_REG(SPL, gpr.rsp.byte.low, u8, SP);
    SUB_REG(BPL, gpr.rbp.byte.low, u8, BP);
    SUB_REG(R8B, gpr.r8.byte.low, u8, R8W);
    SUB_REG(R9B, gpr.r9.byte.low, u8, R9W);
    SUB_REG(R10B, gpr.r10.byte.low, u8, R10W);
    SUB_REG(R11B, gpr.r11.byte.low, u8, R11W);
    SUB_REG(R12B, gpr.r12.byte.low, u8, R12W);
    SUB_REG(R13B, gpr.r13.byte.low, u8, R13W);
    SUB_REG(R14B, gpr.r14.byte.low, u8, R14W);
    SUB_REG(R15B, gpr.r15.byte.low, u8, R15W);
  }

  if (64 == address_size) {
    SUB_REG(PC, gpr.rip.qword, u64, RIP);
  } else {
    SUB_REG(PC, gpr.rip.dword, u32, EIP);
  }

  REG(SS, seg.ss.flat, u16);
  REG(ES, seg.es.flat, u16);
  REG(GS, seg.gs.flat, u16);
  REG(FS, seg.fs.flat, u16);
  REG(DS, seg.ds.flat, u16);
  REG(CS, seg.cs.flat, u16);

  if (64 == address_size) {
    REG(GSBASE, addr.gs_base.qword, addr);
    REG(FSBASE, addr.fs_base.qword, addr);

  } else {
    REG(SSBASE, addr.ss_base.dword, addr);
    REG(ESBASE, addr.es_base.dword, addr);
    REG(DSBASE, addr.ds_base.dword, addr);
    REG(GSBASE, addr.gs_base.dword, addr);
    REG(FSBASE, addr.fs_base.dword, addr);
  }

  if (has_avx) {
    if (has_avx512) {
      REG(ZMM0, vec[0].zmm, v512);
      REG(ZMM1, vec[1].zmm, v512);
      REG(ZMM2, vec[2].zmm, v512);
      REG(ZMM3, vec[3].zmm, v512);
      REG(ZMM4, vec[4].zmm, v512);
      REG(ZMM5, vec[5].zmm, v512);
      REG(ZMM6, vec[6].zmm, v512);
      REG(ZMM7, vec[7].zmm, v512);
      REG(ZMM8, vec[8].zmm, v512);
      REG(ZMM9, vec[9].zmm, v512);
      REG(ZMM10, vec[10].zmm, v512);
      REG(ZMM11, vec[11].zmm, v512);
      REG(ZMM12, vec[12].zmm, v512);
      REG(ZMM13, vec[13].zmm, v512);
      REG(ZMM14, vec[14].zmm, v512);
      REG(ZMM15, vec[15].zmm, v512);
      REG(ZMM16, vec[16].zmm, v512);
      REG(ZMM17, vec[17].zmm, v512);
      REG(ZMM18, vec[18].zmm, v512);
      REG(ZMM19, vec[19].zmm, v512);
      REG(ZMM20, vec[20].zmm, v512);
      REG(ZMM21, vec[21].zmm, v512);
      REG(ZMM22, vec[22].zmm, v512);
      REG(ZMM23, vec[23].zmm, v512);
      REG(ZMM24, vec[24].zmm, v512);
      REG(ZMM25, vec[25].zmm, v512);
      REG(ZMM26, vec[26].zmm, v512);
      REG(ZMM27, vec[27].zmm, v512);
      REG(ZMM28, vec[28].zmm, v512);
      REG(ZMM29, vec[29].zmm, v512);
      REG(ZMM30, vec[30].zmm, v512);
      REG(ZMM31, vec[31].zmm, v512);
    }

    SUB_REGAVX512(YMM0, vec[0].ymm, v256, ZMM0);
    SUB_REGAVX512(YMM1, vec[1].ymm, v256, ZMM1);
    SUB_REGAVX512(YMM2, vec[2].ymm, v256, ZMM2);
    SUB_REGAVX512(YMM3, vec[3].ymm, v256, ZMM3);
    SUB_REGAVX512(YMM4, vec[4].ymm, v256, ZMM4);
    SUB_REGAVX512(YMM5, vec[5].ymm, v256, ZMM5);
    SUB_REGAVX512(YMM6, vec[6].ymm, v256, ZMM6);
    SUB_REGAVX512(YMM7, vec[7].ymm, v256, ZMM7);

    if (64 == address_size || has_avx512) {
      SUB_REGAVX512(YMM8, vec[8].ymm, v256, ZMM8);
      SUB_REGAVX512(YMM9, vec[9].ymm, v256, ZMM9);
      SUB_REGAVX512(YMM10, vec[10].ymm, v256, ZMM10);
      SUB_REGAVX512(YMM11, vec[11].ymm, v256, ZMM11);
      SUB_REGAVX512(YMM12, vec[12].ymm, v256, ZMM12);
      SUB_REGAVX512(YMM13, vec[13].ymm, v256, ZMM13);
      SUB_REGAVX512(YMM14, vec[14].ymm, v256, ZMM14);
      SUB_REGAVX512(YMM15, vec[15].ymm, v256, ZMM15);
    }

    if (has_avx512) {
      SUB_REGAVX512(YMM16, vec[16].ymm, v256, ZMM16);
      SUB_REGAVX512(YMM17, vec[17].ymm, v256, ZMM17);
      SUB_REGAVX512(YMM18, vec[18].ymm, v256, ZMM18);
      SUB_REGAVX512(YMM19, vec[19].ymm, v256, ZMM19);
      SUB_REGAVX512(YMM20, vec[20].ymm, v256, ZMM20);
      SUB_REGAVX512(YMM21, vec[21].ymm, v256, ZMM21);
      SUB_REGAVX512(YMM22, vec[22].ymm, v256, ZMM22);
      SUB_REGAVX512(YMM23, vec[23].ymm, v256, ZMM23);
      SUB_REGAVX512(YMM24, vec[24].ymm, v256, ZMM24);
      SUB_REGAVX512(YMM25, vec[25].ymm, v256, ZMM25);
      SUB_REGAVX512(YMM26, vec[26].ymm, v256, ZMM26);
      SUB_REGAVX512(YMM27, vec[27].ymm, v256, ZMM27);
      SUB_REGAVX512(YMM28, vec[28].ymm, v256, ZMM28);
      SUB_REGAVX512(YMM29, vec[29].ymm, v256, ZMM29);
      SUB_REGAVX512(YMM30, vec[30].ymm, v256, ZMM30);
      SUB_REGAVX512(YMM31, vec[31].ymm, v256, ZMM31);
    }
  }

  SUB_REGAVX(XMM0, vec[0].xmm, v128, YMM0);
  SUB_REGAVX(XMM1, vec[1].xmm, v128, YMM1);
  SUB_REGAVX(XMM2, vec[2].xmm, v128, YMM2);
  SUB_REGAVX(XMM3, vec[3].xmm, v128, YMM3);
  SUB_REGAVX(XMM4, vec[4].xmm, v128, YMM4);
  SUB_REGAVX(XMM5, vec[5].xmm, v128, YMM5);
  SUB_REGAVX(XMM6, vec[6].xmm, v128, YMM6);
  SUB_REGAVX(XMM7, vec[7].xmm, v128, YMM7);

  if (has_avx || 64 == address_size) {
    SUB_REGAVX(XMM8, vec[8].xmm, v128, YMM8);
    SUB_REGAVX(XMM9, vec[9].xmm, v128, YMM9);
    SUB_REGAVX(XMM10, vec[10].xmm, v128, YMM10);
    SUB_REGAVX(XMM11, vec[11].xmm, v128, YMM11);
    SUB_REGAVX(XMM12, vec[12].xmm, v128, YMM12);
    SUB_REGAVX(XMM13, vec[13].xmm, v128, YMM13);
    SUB_REGAVX(XMM14, vec[14].xmm, v128, YMM14);
    SUB_REGAVX(XMM15, vec[15].xmm, v128, YMM15);
  }

  if (has_avx512) {
    SUB_REG(XMM16, vec[16].xmm, v128, YMM16);
    SUB_REG(XMM17, vec[17].xmm, v128, YMM17);
    SUB_REG(XMM18, vec[18].xmm, v128, YMM18);
    SUB_REG(XMM19, vec[19].xmm, v128, YMM19);
    SUB_REG(XMM20, vec[20].xmm, v128, YMM20);
    SUB_REG(XMM21, vec[21].xmm, v128, YMM21);
    SUB_REG(XMM22, vec[22].xmm, v128, YMM22);
    SUB_REG(XMM23, vec[23].xmm, v128, YMM23);
    SUB_REG(XMM24, vec[24].xmm, v128, YMM24);
    SUB_REG(XMM25, vec[25].xmm, v128, YMM25);
    SUB_REG(XMM26, vec[26].xmm, v128, YMM26);
    SUB_REG(XMM27, vec[27].xmm, v128, YMM27);
    SUB_REG(XMM28, vec[28].xmm, v128, YMM28);
    SUB_REG(XMM29, vec[29].xmm, v128, YMM29);
    SUB_REG(XMM30, vec[30].xmm, v128, YMM30);
    SUB_REG(XMM31, vec[31].xmm, v128, YMM31);
  }

  REG(ST0, st.elems[0].val, f80);
  REG(ST1, st.elems[1].val, f80);
  REG(ST2, st.elems[2].val, f80);
  REG(ST3, st.elems[3].val, f80);
  REG(ST4, st.elems[4].val, f80);
  REG(ST5, st.elems[5].val, f80);
  REG(ST6, st.elems[6].val, f80);
  REG(ST7, st.elems[7].val, f80);

#if 0  // TODO(pag): Don't emulate directly for now.
  if (32 == address_size) {
    REG(FPU_LASTIP, fpu.u.x86.ip);
    REG(FPU_LASTIP, fpu.u.x86.ip);
    REG(FPU_LASTCS, fpu.u.x86.cs);
    REG(FPU_LASTCS, fpu.u.x86.cs);
    REG(FPU_LASTDP, fpu.u.x86.dp);
    REG(FPU_LASTDP, fpu.u.x86.dp);
    REG(FPU_LASTDS, fpu.u.x86.ds);
    REG(FPU_LASTDS, fpu.u.x86.ds);
  } else {
    REG(FPU_LASTIP, fpu.u.amd64.ip);
    REG(FPU_LASTIP, fpu.u.amd64.ip);
    REG(FPU_LASTDP, fpu.u.amd64.dp);
    REG(FPU_LASTDP, fpu.u.amd64.dp);
  }
#endif

  // MMX technology registers. For simplicity, these are implemented separately
  // from the FPU stack, and so they do not alias. This makes some things
  // easier and some things harder. Marshaling native/lifted state becomes
  // harder, but generating and optimizing bitcode becomes simpler. The trade-
  // off is that analysis and native states will diverge in strange ways
  // with code that mixes the two (X87 FPU ops, MMX ops).
  REG(MM0, mmx.elems[0].val.qwords.elems[0], u64);
  REG(MM1, mmx.elems[1].val.qwords.elems[0], u64);
  REG(MM2, mmx.elems[2].val.qwords.elems[0], u64);
  REG(MM3, mmx.elems[3].val.qwords.elems[0], u64);
  REG(MM4, mmx.elems[4].val.qwords.elems[0], u64);
  REG(MM5, mmx.elems[5].val.qwords.elems[0], u64);
  REG(MM6, mmx.elems[6].val.qwords.elems[0], u64);
  REG(MM7, mmx.elems[7].val.qwords.elems[0], u64);

  if (has_avx512) {
    REG(K0, k_reg.elems[0].val, u64);
    REG(K1, k_reg.elems[1].val, u64);
    REG(K2, k_reg.elems[2].val, u64);
    REG(K3, k_reg.elems[3].val, u64);
    REG(K4, k_reg.elems[4].val, u64);
    REG(K5, k_reg.elems[5].val, u64);
    REG(K6, k_reg.elems[6].val, u64);
    REG(K7, k_reg.elems[7].val, u64);
  }

  // Arithmetic flags. Data-flow analyses will clear these out ;-)
  REG(AF, aflag.af, u8);
  REG(CF, aflag.cf, u8);
  REG(DF, aflag.df, u8);
  REG(OF, aflag.of, u8);
  REG(PF, aflag.pf, u8);
  REG(SF, aflag.sf, u8);
  REG(ZF, aflag.zf, u8);

  //  // Debug registers. No-ops keep them from being stripped off the module.
  //  DR0
  //  DR1
  //  DR2
  //  DR3
  //  DR4
  //  DR5
  //  DR6
  //  DR7

  //  REG(CR0, lat);
  //  REG(CR1, lat);
  //  REG(CR2, lat);
  //  REG(CR3, lat);
  //  REG(CR4, lat);
  //#if 64 == ADDRESS_SIZE_BITS
  //  REG(CR8, lat);
  //#endif
}

// Populate a just-initialized lifted function function with architecture-
// specific variables.
void X86Arch::FinishLiftedFunctionInitialization(
    llvm::Module *module, llvm::Function *bb_func) const {
  const auto &dl = module->getDataLayout();
  CHECK_EQ(sizeof(State), dl.getTypeAllocSize(StateStructType()))
      << "Mismatch between size of State type for x86/amd64 and what is in "
      << "the bitcode module";

  auto &context = module->getContext();
  auto addr = llvm::Type::getIntNTy(context, address_size);
  auto zero_addr_val = llvm::Constant::getNullValue(addr);

  const auto entry_block = &bb_func->getEntryBlock();
  llvm::IRBuilder<> ir(entry_block);

  const auto pc_arg = NthArgument(bb_func, kPCArgNum);
  const auto state_ptr_arg = NthArgument(bb_func, kStatePointerArgNum);
  ir.CreateStore(pc_arg, ir.CreateAlloca(addr, nullptr, "NEXT_PC"));

  (void) this->RegisterByName("PC")->AddressOf(state_ptr_arg, ir);

  ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "CSBASE"));

  if (64 == address_size) {
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "SSBASE"));
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "ESBASE"));
    ir.CreateStore(zero_addr_val, ir.CreateAlloca(addr, nullptr, "DSBASE"));
  }
}

}  // namespace

// TODO(pag): We pretend that these are singletons, but they aren't really!
Arch::ArchPtr Arch::GetX86(llvm::LLVMContext *context_, OSName os_name_,
                           ArchName arch_name_) {
  return std::make_unique<X86Arch>(context_, os_name_, arch_name_);
}

}  // namespace remill
