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
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/ArchBase.h>  // For `Arch` and `ArchImpl`.
#include <remill/Arch/X86/X86Base.h>

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

  // Enable LZCNT/TZCNT instructions (required for XED v2025+)
  // in reference the made in this 
  // commit: https://github.com/intelxed/xed/commit/1bdc793f5f64cf207f6776f4c0e442e39fa47903
  // - Backward compatibility for decoder initialization of several ISA features has
  // been deprecated. Previously default-on features like `P4` (PAUSE), `LZCNT`
  // (replacing BSR), and `TZCNT` (replacing BSF) are now disabled by default unless
  // explicitly enabled by users through the raw XED setter APIs or the
  // chip/chip-features APIs.
   xed3_operand_set_lzcnt(xedd, 1);
   xed3_operand_set_tzcnt(xedd, 1);
   xed3_operand_set_p4(xedd, 1);  // Enable PAUSE as well

  auto err = xed_decode(xedd, bytes, static_cast<uint32_t>(num_bytes));

  if (XED_ERROR_NONE != err) {
    std::stringstream ss;
    for (auto b : inst_bytes) {
      ss << ' ' << std::hex << std::setw(2) << std::setfill('0')
         << (static_cast<unsigned>(b) & 0xFFu);
    }
    DLOG(WARNING) << "Unable to decode instruction at " << std::hex << address
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

  inst.branch_taken_arch_name = inst.arch_name;
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

  inst.branch_taken_arch_name = inst.arch_name;
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

class X86Arch final : public X86ArchBase, public DefaultContextAndLifter {
 public:
  X86Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  virtual ~X86Arch(void);

  // Decode an instruction.
  bool ArchDecodeInstruction(uint64_t address, std::string_view inst_bytes,
                             Instruction &inst) const final;


 private:
  X86Arch(void) = delete;
};

X86Arch::X86Arch(llvm::LLVMContext *context_, OSName os_name_,
                 ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      X86ArchBase(context_, os_name_, arch_name_),
      DefaultContextAndLifter(context_, os_name_, arch_name_) {

  static bool xed_is_initialized = false;
  if (!xed_is_initialized) {
    DLOG(INFO) << "Initializing XED tables";
    xed_tables_init();
    xed_is_initialized = true;
  }
}

X86Arch::~X86Arch(void) {}


static bool IsAVX(xed_isa_set_enum_t isa_set, xed_category_enum_t category) {
  switch (isa_set) {
    case XED_ISA_SET_AVX:
    case XED_ISA_SET_AVX2:
    case XED_ISA_SET_AVX2GATHER:
    case XED_ISA_SET_AVXAES:
    case XED_ISA_SET_AVX_GFNI:
    case XED_ISA_SET_AVX_VNNI: return true;
    default: break;
  }
  switch (category) {
    case XED_CATEGORY_AVX:
    case XED_CATEGORY_AVX2:
    case XED_CATEGORY_AVX2GATHER: return true;
    default: return false;
  }
}

static bool IsAVX512(xed_isa_set_enum_t isa_set, xed_category_enum_t category) {
  switch (isa_set) {
    case XED_ISA_SET_AVX512BW_128:
    case XED_ISA_SET_AVX512BW_128N:
    case XED_ISA_SET_AVX512BW_256:
    case XED_ISA_SET_AVX512BW_512:
    case XED_ISA_SET_AVX512BW_KOPD:
    case XED_ISA_SET_AVX512BW_KOPQ:
    case XED_ISA_SET_AVX512CD_128:
    case XED_ISA_SET_AVX512CD_256:
    case XED_ISA_SET_AVX512CD_512:
    case XED_ISA_SET_AVX512DQ_128:
    case XED_ISA_SET_AVX512DQ_128N:
    case XED_ISA_SET_AVX512DQ_256:
    case XED_ISA_SET_AVX512DQ_512:
    case XED_ISA_SET_AVX512DQ_KOPB:
    case XED_ISA_SET_AVX512DQ_KOPW:
    case XED_ISA_SET_AVX512DQ_SCALAR:
    case XED_ISA_SET_AVX512ER_512:
    case XED_ISA_SET_AVX512ER_SCALAR:
    case XED_ISA_SET_AVX512F_128:
    case XED_ISA_SET_AVX512F_128N:
    case XED_ISA_SET_AVX512F_256:
    case XED_ISA_SET_AVX512F_512:
    case XED_ISA_SET_AVX512F_KOPW:
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
    case XED_ISA_SET_AVX512_VPOPCNTDQ_512: return true;
    default: break;
  }
  switch (category) {
    case XED_CATEGORY_AVX512:
    case XED_CATEGORY_AVX512_4FMAPS:
    case XED_CATEGORY_AVX512_4VNNIW:
    case XED_CATEGORY_AVX512_BITALG:
    case XED_CATEGORY_AVX512_VBMI:
    case XED_CATEGORY_AVX512_VP2INTERSECT: return true;
    default: return false;
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
static void
FillFusedCallPopRegOperands(Instruction &inst, unsigned address_size,
                            const char *dest_reg_name, unsigned call_inst_len) {
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
bool X86Arch::ArchDecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst) const {

  inst.pc = address;
  inst.arch = this;
  inst.arch_name = arch_name;
  inst.sub_arch_name = kArchInvalid;
  inst.branch_taken_arch_name = arch_name;
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
    inst.sub_arch_name =
        32 == address_size ? kArchX86_AVX512 : kArchAMD64_AVX512;
  } else if (IsAVX(isa_set, category)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX : kArchAMD64_AVX;
  } else if (xed_classify_avx512(xedd) || xed_classify_avx512_maskop(xedd)) {
    inst.sub_arch_name =
        32 == address_size ? kArchX86_AVX512 : kArchAMD64_AVX512;
  } else if (xed_classify_avx(xedd)) {
    inst.sub_arch_name = 32 == address_size ? kArchX86_AVX : kArchAMD64_AVX;
  } else {
    inst.sub_arch_name = 32 == address_size ? kArchX86 : kArchAMD64;
  }

  // Make sure we know about
  if (static_cast<unsigned>(inst.arch_name) <
      static_cast<unsigned>(inst.sub_arch_name)) {
    LOG(ERROR) << "Instruction decode of " << xed_iform_enum_t2str(iform)
               << " requires the " << GetArchName(inst.sub_arch_name)
               << " architecture semantics to lift but was decoded using the "
               << GetArchName(inst.arch_name) << " architecture";

    inst.Reset();
    inst.category = Instruction::kCategoryInvalid;
    return false;
  }

  inst.category = CreateCategory(xedd);

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
    } else if (64 == address_size && (2 + len) <= inst_bytes.size() &&
               inst_bytes[len] == 0x41) {
      is_fused_call_pop = FusablePopReg64(inst_bytes[len + 1]);
      if (is_fused_call_pop) {
        extra_len = 2u;
        inst.category = Instruction::kCategoryNormal;
      }
    }
  }

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
    FillFusedCallPopRegOperands(inst, address_size, is_fused_call_pop, len);

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
    LOG(WARNING) << "Ignoring XACQUIRE/XRELEASE prefix at " << std::hex
                 << inst.pc << std::dec;
  }

  return true;
}
}  // namespace

// TODO(pag): We pretend that these are singletons, but they aren't really!
Arch::ArchPtr Arch::GetX86(llvm::LLVMContext *context_, OSName os_name_,
                           ArchName arch_name_) {
  return std::make_unique<X86Arch>(context_, os_name_, arch_name_);
}

}  // namespace remill
