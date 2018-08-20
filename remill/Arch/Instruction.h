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
#include <vector>

namespace remill {

class Arch;

enum ArchName : unsigned;

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
    kTypeAddress
  } type;

  enum Action {
    kActionInvalid,
    kActionRead,
    kActionWrite
  } action;

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

    enum Shift : unsigned {
      kShiftInvalid,
      kShiftLeftWithZeroes,  // Shift left, filling low order bits with zero.
      kShiftLeftWithOnes,  // Shift left, filling low order bits with one.
      kShiftUnsignedRight,  // Also know as logical shift right.
      kShiftSignedRight,  // Also know as arithmetic shift right.
      kShiftLeftAround,  // Rotate left.
      kShiftRightAround  // Rotate right.
    } shift_op;

    enum Extend : unsigned {
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

  std::string Serialize(void) const;
};

// Generic instruction type.
class Instruction {
 public:
  ~Instruction(void) = default;
  Instruction(void);

  void Reset(void);

  bool FinalizeDecode(void);

  // Name of semantics function that implements this instruction.
  std::string function;

  // The decoded bytes of the instruction.
  std::string bytes;

  // Program counter for this instruction and the next instruction.
  uint64_t pc;
  uint64_t next_pc;

  // Used to tell higher levels about direct/conditional branch
  // targets.
  uint64_t branch_taken_pc;
  uint64_t branch_not_taken_pc;

  // Name of this instruction's architecture.
  ArchName arch_name;

  // Pointer to the `remill::Arch` used to complete the decoding of this
  // instruction.
  const Arch *arch_for_decode;

  // Does the instruction require the use of the `__remill_atomic_begin` and
  // `__remill_atomic_end`?
  bool is_atomic_read_modify_write;

  enum Category {
    kCategoryInvalid,
    kCategoryNormal,
    kCategoryNoOp,
    kCategoryError,
    kCategoryDirectJump,
    kCategoryIndirectJump,
    kCategoryDirectFunctionCall,
    kCategoryIndirectFunctionCall,
    kCategoryFunctionReturn,
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
      case kCategoryNoOp:
        return false;
      default:
        return true;
    }
  }

  inline bool IsDirectControlFlow(void) const {
    switch (category) {
      case kCategoryDirectFunctionCall:
      case kCategoryDirectJump:
      case kCategoryConditionalBranch:
        return true;
      default:
        return false;
    }
  }

  inline bool IsIndirectControlFlow(void) const {
    switch (category) {
      case kCategoryIndirectFunctionCall:
      case kCategoryIndirectJump:
      case kCategoryConditionalBranch:
      case kCategoryAsyncHyperCall:
      case kCategoryConditionalAsyncHyperCall:
      case kCategoryFunctionReturn:
        return true;
      default:
        return false;
    }
  }

  inline bool IsConditionalBranch(void) const {
    return kCategoryConditionalBranch == category;
  }

  inline bool IsFunctionCall(void) const {
    switch (category) {
      case kCategoryDirectFunctionCall:
      case kCategoryIndirectFunctionCall:
        return true;
      default:
        return false;
    }
  }

  inline bool IsFunctionReturn(void) const {
    return kCategoryFunctionReturn == category;
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
    return next_pc - pc;
  }

  inline bool IsNoOp(void) const {
    return kCategoryNoOp == category;
  }
};

}  // namespace remill
