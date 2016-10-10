/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>
#include <string>

#include <llvm/IR/Module.h>

#include "remill/Arch/Instruction.h"

#include "remill/Arch/X86/Arch.h"
#include "remill/Arch/X86/XED.h"

namespace remill {
namespace {

static const xed_state_t kXEDState32 = {
    XED_MACHINE_MODE_LONG_COMPAT_32,
    XED_ADDRESS_WIDTH_32b};

static const xed_state_t kXEDState64 = {
    XED_MACHINE_MODE_LONG_64,
    XED_ADDRESS_WIDTH_64b};

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
  return XED_ICLASS_HLT == iclass || XED_ICLASS_UD2 == iclass ||
         XED_ICLASS_INVALID == iclass;
}

static bool IsReadCPUFeatures(const xed_decoded_inst_t *xedd) {
  return XED_ICLASS_CPUID == xed_decoded_inst_get_iclass(xedd);
}

// Return the category of this instruction.
static Instruction::Category CreateCategory(const xed_decoded_inst_t *xedd) {
  if (IsError(xedd)) {
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
    return Instruction::kCategorySystemCall;

  } else if (IsSystemReturn(xedd)) {
    return Instruction::kCategorySystemReturn;

  // Instruction implementation handles syscall (x86, x32) emulation. This is
  // invoked even for conditional interrupt, where a special flag is used to
  // denote that the interrupt should happen.
  } else if (IsInterruptCall(xedd)) {
    return Instruction::kCategoryInterruptCall;

  } else if (IsConditionalInterruptCall(xedd)) {
    return Instruction::kCategoryConditionalInterruptCall;

  } else if (IsInterruptReturn(xedd)) {
    return Instruction::kCategoryInterruptReturn;

  } else if (IsNoOp(xedd)) {
    return Instruction::kCategoryNoOp;

  // CPUID. Lets a runtime or static analyzer decide what this means.
  } else if (IsReadCPUFeatures(xedd)) {
    return Instruction::kCategoryReadCPUFeatures;

  } else {
    return Instruction::kCategoryNormal;
  }
}


// Name of this instruction function.
static std::string InstructionFunctionName(const xed_decoded_inst_t *xedd) {
  std::stringstream ss;
  std::string iform_name = xed_iform_enum_t2str(
      xed_decoded_inst_get_iform_enum(xedd));

  // All `LOCK` versions of instructions have their own iform, but ideally
  // we want to express the (non-)atomic versions of instructions uniformly.
  // For locked instructions, we inject calls to atomic intrinsics before/after
  // the lifted instructions.
  if (xed_operand_values_has_lock_prefix(xedd)) {
    const std::string lock = "LOCK_";
    const auto idx = iform_name.find(lock);
    if (std::string::npos != idx) {
      iform_name.erase(idx, lock.size());
    }
  }

  ss << iform_name;

  // Some instructions are "scalable", i.e. there are variants of the
  // instruction for each effective operand size. We represent these in
  // the semantics files with `_<size>`, so we need to look up the correct
  // selection.
  if (xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_SCALABLE)) {
    ss << "_";
    ss << xed_decoded_inst_get_operand_width(xedd);
  }

  return ss.str();
}

// Decode an instruction into the XED instruction format.
static void DecodeXED(xed_decoded_inst_t *xedd,
                      const xed_state_t *mode,
                      const std::string &instr_bytes,
                      uint64_t address) {
  auto num_bytes = instr_bytes.size();
  auto bytes = reinterpret_cast<const uint8_t *>(instr_bytes.data());
  xed_decoded_inst_zero_set_mode(xedd, mode);
  xed_decoded_inst_set_input_chip(xedd, XED_CHIP_INVALID);
  auto err = xed_decode(xedd, bytes, static_cast<uint32_t>(num_bytes));

  CHECK(XED_ERROR_NONE == err)
      << "Unable to decode instruction at " << std::hex << address
      << " with error: " << xed_error_enum_t2str(err) << ".";

  CHECK(xed_decoded_inst_get_length(xedd) == num_bytes)
      << "Size of decoded instruction at " << std::hex << address <<
      "(" << std::dec << xed_decoded_inst_get_length(xedd)
      << ") doesn't match input instruction size (" << num_bytes << ").";
}

// Returns true if this instruction is part of the SSE instruction
// set extensions.
static bool IsSSE(const xed_decoded_inst_t *xedd) {
  switch (xed_decoded_inst_get_extension(xedd)) {
    case XED_EXTENSION_SSE:
    case XED_EXTENSION_SSE2:
    case XED_EXTENSION_SSE3:
    case XED_EXTENSION_SSE4:
    case XED_EXTENSION_SSE4A:
    case XED_EXTENSION_SSSE3:
      return true;
    default:
      return false;
  }
}

// Variable name for a read register. This needs to correspond to something
// in the X86-runtime implementation of `__remill_basic_block`.
static std::string ReadRegName(xed_reg_enum_t reg) {
  if (XED_REG_INVALID == reg) {
    return "";
  } else {
    return std::string(xed_reg_enum_t2str(reg)) + "_read";
  }
}

// Variable name for a write register. This needs to correspond to something
// in the X86-runtime implementation of `__remill_basic_block`.
static std::string WriteRegName(xed_reg_enum_t reg) {
  if (XED_REG_INVALID == reg) {
    return "";
  } else {
    return std::string(xed_reg_enum_t2str(reg)) + "_write";
  }
}

// Variable operand for a read register.
static Operand::Register ReadReg(xed_reg_enum_t reg) {
  Operand::Register reg_op;
  reg_op.name = ReadRegName(reg);
  if (XED_REG_X87_FIRST <= reg && XED_REG_X87_LAST >= reg) {
    reg_op.size = 64;
  } else {
    reg_op.size = xed_get_register_width_bits64(reg);
  }
  return reg_op;
}

// Variable operand for a write register.
static Operand::Register WriteReg(xed_reg_enum_t reg) {
  Operand::Register reg_op;
  reg_op.name = WriteRegName(reg);
  if (XED_REG_X87_FIRST <= reg && XED_REG_X87_LAST >= reg) {
    reg_op.size = 64;
  } else {
    reg_op.size = xed_get_register_width_bits64(reg);
  }
  return reg_op;
}

// Decode a memory operand.
static void DecodeMemory(Instruction *instr,
                         const xed_decoded_inst_t *xedd,
                         const xed_operand_t *xedo,
                         int mem_index) {

  auto iclass = xed_decoded_inst_get_iclass(xedd);
  auto op_name = xed_operand_name(xedo);
  auto segment = xed_decoded_inst_get_seg_reg(xedd, mem_index);
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  auto disp = xed_decoded_inst_get_memory_displacement(xedd, mem_index);
  auto scale = xed_decoded_inst_get_scale(xedd, mem_index);
  auto base_wide = xed_get_largest_enclosing_register(base);
  auto size = xed_decoded_inst_get_operand_width(xedd);
  auto instr_size = static_cast<int64_t>(xed_decoded_inst_get_length(xedd));

  // PC-relative memory accesses are relative to the next PC.
  if (XED_REG_RIP == base_wide) {
    disp += static_cast<int64_t>(instr_size);

  // Address is in the displacement. Take the absolute address and turn it
  // into a PC-relative address.
  } else if (XED_REG_INVALID == base && XED_REG_INVALID == index) {
    base = kArchAMD64 == instr->arch_name ? XED_REG_RIP : XED_REG_EIP;
    disp -= static_cast<int64_t>(instr->next_pc);
    base_wide = XED_REG_RIP;
  }

  // Deduce the implicit segment register if it is absent.
  if (XED_REG_INVALID == segment) {
    segment = XED_REG_DS;
    if (XED_REG_RSP == base_wide || XED_REG_RBP == base_wide) {
      segment = XED_REG_SS;
    }
  }

  // On AMD64, only the `FS` and `GS` segments are non-zero.
  if (kArchAMD64 == instr->arch_name &&
      XED_REG_FS != segment &&
      XED_REG_GS != segment) {
    segment = XED_REG_INVALID;

  // AGEN operands, e.g. for the `LEA` instruction, can be marked with an
  // explicit segment, but it is ignored.
  } else if (XED_OPERAND_AGEN == op_name) {
    segment = XED_REG_INVALID;
  }

  // Special case: `POP [xSP + ...] uses the value of `xSP` after incrementing
  // it by the stack width.
  if (XED_ICLASS_POP == iclass && XED_REG_RSP == base_wide) {
    disp += static_cast<int64_t>(size / 8);
  }

  Operand op;
  op.size = size;

  op.type = Operand::kTypeAddress;
  op.addr.address_size = xed_decoded_inst_get_memop_address_width(
      xedd, mem_index);

  op.addr.segment_reg = ReadReg(segment);
  op.addr.base_reg = ReadReg(base);
  op.addr.index_reg = ReadReg(index);
  op.addr.scale = static_cast<int64_t>(scale);
  op.addr.displacement = disp;

  // Rename the base register to use `NEXT_PC` as the register name.
  if (XED_REG_RIP == base_wide) {
    op.addr.base_reg.name = "NEXT_PC";
  }

  // We always pass destination operands first, then sources. Memory operands
  // are represented by their addresses, and in the instruction implementations,
  // accessed via intrinsics.
  if (xed_operand_written(xedo)) {
    op.action = Operand::kActionWrite;
    instr->operands.push_back(op);
  }

  if (xed_operand_read(xedo)) {
    op.action = Operand::kActionRead;
    instr->operands.push_back(op);
  }
}

// Decode an immediate constant.
static void DecodeImmediate(Instruction *instr,
                            const xed_decoded_inst_t *xedd,
                            xed_operand_enum_t op_name) {
  auto val = 0ULL;
  auto is_signed = false;
  auto imm_size = xed_decoded_inst_get_immediate_width_bits(xedd);

  CHECK(imm_size <= instr->operand_size)
      << "Immediate size is greater than effective operand size at "
      << std::hex << instr->pc << ".";

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

  Operand op;
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;
  op.size = imm_size;
  op.imm.is_signed = is_signed;
  op.imm.val = val;
  instr->operands.push_back(op);
}

// Decode a register operand.
static void DecodeRegister(Instruction *instr,
                           const xed_decoded_inst_t *xedd,
                           const xed_operand_t *xedo,
                           xed_operand_enum_t op_name) {
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);

  Operand op;
  op.type = Operand::kTypeRegister;
  op.size = xed_get_register_width_bits64(reg);

  // In remill, we represent X87 floating point registers using `double`s.
  if (XED_REG_X87_FIRST <= reg && XED_REG_X87_LAST >= reg) {
    op.size = 64;
  }

  // Pass the register by reference.
  if (xed_operand_written(xedo)) {

    op.action = Operand::kActionWrite;
    op.reg = WriteReg(reg);

    // XMM registers have different behavior when using SSE vs. using AVX. SSE
    // instructions operating on XMM registers on a machine with AVX will not
    // cause zeroing of the high bits of the YMM/ZMM registers. If AVX-specific
    // versions of the same instructions (usually prefixed with a `V`) are used
    // then writing to an XMM register will kill the high bits of a YMM/ZMM
    // register, thus breaking data dependencies (sort of like how writing to
    // a 32-bit register on a 64-bit system zeroes the high bits).
    if (XED_REG_CLASS_XMM == xed_reg_class(reg) && IsSSE(xedd)) {
      op.reg.name += "_legacy";
    }

    // Note:  In `BasicBlock.cpp`, we alias things like `EAX_write` into
    //        `RAX_write` on 64-bit builds, so we just want to notify that
    //        the operand size is 64 bits, but the register's width itself
    //        is still 32.
    if (XED_REG_GPR32_FIRST <= reg && XED_REG_GPR32_LAST > reg) {
      if (kArchAMD64 == instr->arch_name) {
        op.reg.name[0] = 'R';  // Convert things like `EAX` into `RAX`.
        op.size = 64;
        op.reg.size = 64;
      }
    }

    instr->operands.push_back(op);
  }

  if (xed_operand_read(xedo)) {
    op.action = Operand::kActionRead;
    op.size = xed_get_register_width_bits64(reg);
    op.reg = ReadReg(reg);
    instr->operands.push_back(op);
  }
}

static void DecodeConditionalInterrupt(Instruction *instr) {
  // Condition variable.
  Operand cond_op;
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
  instr->operands.push_back(cond_op);
}

// Decode a relative branch target.
static void DecodeConditionalBranch(Instruction *instr,
                                    const xed_decoded_inst_t *xedd) {
  auto pc_reg = kArchAMD64 == instr->arch_name ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp = static_cast<int64_t>(
      xed_decoded_inst_get_branch_displacement(xedd));

  // Condition variable.
  Operand cond_op;
  cond_op.action = Operand::kActionWrite;
  cond_op.type = Operand::kTypeRegister;
  cond_op.reg.name = "BRANCH_TAKEN";
  cond_op.reg.size = 8;
  cond_op.size = 8;
  instr->operands.push_back(cond_op);

  // Taken branch.
  Operand taken_op;
  taken_op.action = Operand::kActionRead;
  taken_op.type = Operand::kTypeAddress;
  taken_op.size = pc_width;
  taken_op.addr.base_reg.name = "NEXT_PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp;
  instr->operands.push_back(taken_op);

  instr->branch_taken_pc = static_cast<uint64_t>(
      static_cast<int64_t>(instr->next_pc) + disp);

  // Not taken branch.
  Operand not_taken_op;
  not_taken_op.action = Operand::kActionRead;
  not_taken_op.type = Operand::kTypeRegister;
  not_taken_op.size = pc_width;
  not_taken_op.reg.name = "NEXT_PC";
  not_taken_op.reg.size = pc_width;
  instr->operands.push_back(not_taken_op);

  instr->branch_not_taken_pc = instr->next_pc;
}

// Decode a relative branch target.
static void DecodeRelativeBranch(Instruction *instr,
                                 const xed_decoded_inst_t *xedd) {
  auto pc_reg = kArchAMD64 == instr->arch_name ? XED_REG_RIP : XED_REG_EIP;
  auto pc_width = xed_get_register_width_bits64(pc_reg);
  auto disp = static_cast<int64_t>(
      xed_decoded_inst_get_branch_displacement(xedd));

  // Taken branch.
  Operand taken_op;
  taken_op.action = Operand::kActionRead;
  taken_op.type = Operand::kTypeAddress;
  taken_op.size = pc_width;
  taken_op.addr.base_reg.name = "NEXT_PC";
  taken_op.addr.base_reg.size = pc_width;
  taken_op.addr.displacement = disp;
  instr->operands.push_back(taken_op);

  instr->branch_taken_pc = static_cast<uint64_t>(
      static_cast<int64_t>(instr->next_pc) + disp);
}

// Decode an operand.
static void DecodeOperand(Instruction *instr,
                          const xed_decoded_inst_t *xedd,
                          const xed_operand_t *xedo) {
  switch (auto op_name = xed_operand_name(xedo)) {
    case XED_OPERAND_AGEN:
    case XED_OPERAND_MEM0:
      DecodeMemory(instr, xedd, xedo, 0);
      break;

    case XED_OPERAND_MEM1:
      DecodeMemory(instr, xedd, xedo, 1);
      break;

    case XED_OPERAND_IMM0SIGNED:
    case XED_OPERAND_IMM0:
    case XED_OPERAND_IMM1_BYTES:
    case XED_OPERAND_IMM1:
      DecodeImmediate(instr, xedd, op_name);
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
      DecodeRegister(instr, xedd, xedo, op_name);
      break;

    case XED_OPERAND_RELBR:
      if (Instruction::kCategoryConditionalBranch == instr->category) {
        DecodeConditionalBranch(instr, xedd);
      } else {
        DecodeRelativeBranch(instr, xedd);
      }
      break;

    default:
      LOG(FATAL)
          << "Unexpected operand type "
          << xed_operand_enum_t2str(op_name) << ".";
      return;
  }
}

}  // namespace

const Arch *Arch::CreateX86(
    OSName os_name_, ArchName arch_name_, unsigned address_size_) {
  return new X86Arch(os_name_, arch_name_, address_size_);
}

X86Arch::X86Arch(OSName os_name_, ArchName arch_name_, unsigned address_size_)
    : Arch(os_name_, arch_name_, address_size_) {

  static bool xed_is_initialized = false;
  if (!xed_is_initialized) {
    DLOG(INFO) << "Initializing XED tables";
    xed_tables_init();
    xed_is_initialized = true;
  }
}

X86Arch::~X86Arch(void) {}

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
void X86Arch::PrepareModule(llvm::Module *mod) const {
  std::string dl;
  std::string triple;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot convert module for an unrecognized OS.";
      break;
    case kOSLinux:
      switch (arch_name) {
        case kArchInvalid:
          LOG(FATAL)
              << "Cannot convert module for an unrecognized architecture.";
            break;

        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          dl = "e-m:e-i64:64-f80:128-n8:16:32:64-S128";
          triple = "x86_64-pc-linux-gnu";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          dl = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128";
          triple = "i386-pc-linux-gnu";
          break;
      }
      break;

    case kOSmacOS:
      switch (arch_name) {
        case kArchInvalid:
          LOG(FATAL)
              << "Cannot convert module for an unrecognized architecture.";
          break;

        case kArchAMD64:
        case kArchAMD64_AVX:
        case kArchAMD64_AVX512:
          dl = "e-m:o-i64:64-f80:128-n8:16:32:64-S128";
          triple = "x86_64-apple-macosx10.10.0";
          break;
        case kArchX86:
        case kArchX86_AVX:
        case kArchX86_AVX512:
          dl = "e-m:o-p:32:32-f64:32:64-f80:128-n8:16:32-S128";
          triple = "i386-apple-macosx10.10.0";
          break;
      }
      break;
  }
  mod->setDataLayout(dl);
  mod->setTargetTriple(triple);
}

// Decode an instruction.
Instruction *X86Arch::DecodeInstruction(
    uint64_t address,
    const std::string &instr_bytes) const {
  xed_decoded_inst_t xedd_;
  xed_decoded_inst_t *xedd = &xedd_;
  auto mode = 32 == address_size ? &kXEDState32 : &kXEDState64;

  DecodeXED(xedd, mode, instr_bytes, address);

  auto instr = new Instruction;
  instr->arch_name = arch_name;
  instr->operand_size = xed_decoded_inst_get_operand_width(xedd);
  instr->function = InstructionFunctionName(xedd);
  instr->category = CreateCategory(xedd);
  instr->pc = address;
  instr->next_pc = address + instr_bytes.size();

  // Wrap an instruction in atomic begin/end if it accesses memory with RMW
  // semantics or with a LOCK prefix.
  if (xed_operand_values_get_atomic(xedd) ||
      xed_operand_values_has_lock_prefix(xedd)) {
    instr->is_atomic_read_modify_write = true;
  }

  if (Instruction::kCategoryConditionalInterruptCall == instr->category) {
    DecodeConditionalInterrupt(instr);
  }

  // Lift the operands. This creates the arguments for us to call the
  // instruction implementation.
  auto xedi = xed_decoded_inst_inst(xedd);
  auto num_operands = xed_decoded_inst_noperands(xedd);
  for (auto i = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    if (XED_OPVIS_SUPPRESSED != xed_operand_operand_visibility(xedo)) {
      DecodeOperand(instr, xedd, xedo);
    }
  }

#ifndef NDEBUG

  char buffer[256] = {'\0'};
  xed_print_info_t info;
  info.blen = 256;
  info.buf = &(buffer[0]);
  info.context = nullptr;
  info.disassembly_callback = nullptr;
  info.format_options_valid = 0;
  info.p = xedd;
  info.runtime_address = instr->pc;
  info.syntax = XED_SYNTAX_INTEL;
  if (xed_format_generic(&info)) {
    instr->disassembly.assign(&(buffer[0]));
  }

#endif  // NDEBUG

  return instr;
}

}  // namespace remill
