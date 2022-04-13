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

#pragma once

#include <string>
#include <variant>
#include <vector>

namespace llvm {
class Constant;
class Type;
}  // namespace llvm

namespace remill {

class Arch;
struct Register;
class OperandExpression;

enum ArchName : unsigned;

struct LLVMOpExpr {
  unsigned llvm_opcode;
  OperandExpression *op1;
  OperandExpression *op2;
};


class OperandExpression : public std::variant<LLVMOpExpr, const Register *,
                                              llvm::Constant *, std::string> {
 public:
  std::string Serialize(void) const;
  llvm::Type *type{nullptr};
};

// Generic instruction operand.
class Operand {
 public:
  Operand(void);
  ~Operand(void) = default;

  enum Type {
    kTypeInvalid,
    kTypeRegister,
    kTypeShiftRegister,
    kTypeImmediate,
    kTypeAddress,
    kTypeExpression,
    kTypeRegisterExpression,
    kTypeImmediateExpression,
    kTypeAddressExpression,
  } type;

  enum Action { kActionInvalid, kActionRead, kActionWrite } action;

  // Size of this operand, in bits.
  uint64_t size;

  // kTypeRegister.
  class Register {
   public:
    Register(void);
    ~Register(void) = default;

    std::string name;
    uint64_t size;  // In bits.
  } reg;

  class ShiftRegister {
   public:
    ShiftRegister(void);

    Register reg;
    uint64_t shift_size;
    uint64_t extract_size;
    bool shift_first;
    bool can_shift_op_size{false};

    enum Shift : uint8_t {
      kShiftInvalid,
      kShiftLeftWithZeroes,  // Shift left, filling low order bits with zero.
      kShiftLeftWithOnes,  // Shift left, filling low order bits with one.
      kShiftUnsignedRight,  // Also know as logical shift right.
      kShiftSignedRight,  // Also know as arithmetic shift right.
      kShiftLeftAround,  // Rotate left.
      kShiftRightAround  // Rotate right.
    } shift_op;

    enum Extend : uint8_t {
      kExtendInvalid,
      kExtendUnsigned,
      kExtendSigned,
    } extend_op;

  } shift_reg;

  // kTypeImmediate.
  class Immediate {
   public:
    Immediate(void);
    ~Immediate(void) = default;

    uint64_t val;
    bool is_signed;
  } imm;

  // kTypeAddress.
  struct Address {
    enum Kind {
      kInvalid,
      kMemoryRead,
      kMemoryWrite,
      kAddressCalculation,
      kControlFlowTarget
    };

    Address(void);
    ~Address(void) = default;

    Register segment_base_reg;
    Register base_reg;
    Register index_reg;
    int64_t scale;
    int64_t displacement;  // In bytes.
    uint64_t address_size;  // In bits.
    Kind kind;

    inline bool IsMemoryAccess(void) const {
      return kMemoryRead == kind || kMemoryWrite == kind;
    }

    inline bool IsAddressCalculation(void) const {
      return kAddressCalculation == kind;
    }

    inline bool IsControlFlowTarget(void) const {
      return kControlFlowTarget == kind;
    }
  } addr;

  OperandExpression *expr;

  std::string Serialize(void) const;
};

class Condition {
 public:
  enum Kind {
    kTypeTrue,
    kTypeIsOne,
    kTypeIsZero,
    kTypeIsEqual,
  } kind;

  Operand::Register lhs_reg;
  Operand::Register rhs_reg;

  std::string Serialize(void) const;
};

// Generic instruction type.
class Instruction {
 public:
  ~Instruction(void) = default;
  Instruction(void);

  void Reset(void);

  // Name of semantics function that implements this instruction.
  std::string function;

  // The decoded bytes of the instruction.
  std::string bytes;

  // Program counter for this instruction and the next instruction.
  uint64_t pc;
  uint64_t next_pc;

  // Program counter of the delayed instruction for taken/not-taken paths.
  uint64_t delayed_pc;

  // Used to tell higher levels about direct/conditional branch
  // targets.
  uint64_t branch_taken_pc;
  uint64_t branch_not_taken_pc;

  // Name of the architecture used to decode this instruction.
  ArchName arch_name;

  // Name of the minimum instruction set associated with this instruction.
  // Remill's semantics are versioned by sub-architecture, and this tells us
  // what the minimum such sub-architecture is needed to support the semantics
  // of this instruction. This information permits higher-level tools to then
  // figure out the minimum architecture needed in order to lift some set
  // of instructions.
  ArchName sub_arch_name;

  // Name of the architecture of the branch taken target.
  ArchName branch_taken_arch_name;

  // Pointer to the `remill::Arch` used to complete the decoding of this
  // instruction.
  const Arch *arch;

  // Does the instruction require the use of the `__remill_atomic_begin` and
  // `__remill_atomic_end`?
  bool is_atomic_read_modify_write;

  // Does this instruction have a delay slot.
  bool has_branch_taken_delay_slot;
  bool has_branch_not_taken_delay_slot;

  // Is this instruction decoded within the context of a delay slot?
  bool in_delay_slot;

  // For x86 it is possible to specify a prefix that overrides the default
  // segment register. This attribute by itself is currently not used directly
  // by the lifter - it is expeted `Operand`s will include segment reg where appropriate
  // but it can be used in different applications.
  const Register *segment_override = nullptr;

  enum Category {
    kCategoryInvalid,
    kCategoryNormal,
    kCategoryNoOp,
    kCategoryError,
    kCategoryDirectJump,
    kCategoryIndirectJump,
    kCategoryConditionalIndirectJump,
    kCategoryDirectFunctionCall,
    kCategoryConditionalDirectFunctionCall,
    kCategoryIndirectFunctionCall,
    kCategoryConditionalIndirectFunctionCall,
    kCategoryFunctionReturn,
    kCategoryConditionalFunctionReturn,
    kCategoryConditionalBranch,
    kCategoryAsyncHyperCall,
    kCategoryConditionalAsyncHyperCall,
  } category;

  std::vector<Operand> operands;

  std::string Serialize(void) const;

  inline bool IsControlFlow(void) const {
    switch (category) {
      case kCategoryInvalid:
      case kCategoryNormal:
      case kCategoryNoOp: return false;
      default: return true;
    }
  }

  inline bool IsDirectControlFlow(void) const {
    switch (category) {
      case kCategoryDirectFunctionCall:
      case kCategoryDirectJump:
      case kCategoryConditionalBranch: return true;
      default: return false;
    }
  }

  inline bool IsIndirectControlFlow(void) const {
    switch (category) {
      case kCategoryIndirectFunctionCall:
      case kCategoryConditionalIndirectFunctionCall:
      case kCategoryIndirectJump:
      case kCategoryConditionalIndirectJump:
      case kCategoryAsyncHyperCall:
      case kCategoryConditionalAsyncHyperCall:
      case kCategoryFunctionReturn:
      case kCategoryConditionalFunctionReturn: return true;
      default: return false;
    }
  }

  inline bool IsConditionalBranch(void) const {
    switch (category) {
      case kCategoryConditionalDirectFunctionCall:
      case kCategoryConditionalBranch:
      case kCategoryConditionalIndirectJump:
      case kCategoryConditionalAsyncHyperCall:
      case kCategoryConditionalFunctionReturn: return true;
      default: return false;
    }
  }

  inline bool IsFunctionCall(void) const {
    switch (category) {
      case kCategoryDirectFunctionCall:
      case kCategoryConditionalDirectFunctionCall:
      case kCategoryConditionalIndirectFunctionCall:
      case kCategoryIndirectFunctionCall: return true;
      default: return false;
    }
  }

  inline bool IsFunctionReturn(void) const {
    return kCategoryFunctionReturn == category ||
           kCategoryConditionalFunctionReturn == category;
  }

  inline bool IsValid(void) const {
    return kCategoryInvalid != category;
  }

  // Returns `true` if this instruction results in a runtime error. An example
  // of this is a `HLT`- or `UD2`-like instruction from x86.
  inline bool IsError(void) const {
    return kCategoryError == category;
  }

  // Length, in bytes, of the instruction.
  inline uint64_t NumBytes(void) const {
    return bytes.size();
  }

  inline bool IsNoOp(void) const {
    return kCategoryNoOp == category;
  }

  // This allocates an OperandExpression
  OperandExpression *AllocateExpression(void);
  OperandExpression *EmplaceRegister(const Register *);
  OperandExpression *EmplaceRegister(std::string_view reg_name);
  OperandExpression *EmplaceConstant(llvm::Constant *);
  OperandExpression *EmplaceVariable(std::string_view, llvm::Type *);
  OperandExpression *EmplaceBinaryOp(unsigned opcode, OperandExpression *op1,
                                     OperandExpression *op2);
  OperandExpression *EmplaceUnaryOp(unsigned opcode, OperandExpression *op1,
                                    llvm::Type *);

  Operand &EmplaceOperand(const Operand::Register &op);
  Operand &EmplaceOperand(const Operand::Immediate &op);
  Operand &EmplaceOperand(const Operand::ShiftRegister &op);
  Operand &EmplaceOperand(const Operand::Address &op);

 private:
  static constexpr auto kMaxNumExpr = 64u;
  OperandExpression exprs[kMaxNumExpr];
  unsigned next_expr_index{0};
};

}  // namespace remill
