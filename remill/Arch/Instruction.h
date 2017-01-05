/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_INSTRUCTION_H_
#define REMILL_ARCH_INSTRUCTION_H_

#include <string>
#include <vector>

namespace remill {

class Arch;
class X86Arch;

enum ArchName : unsigned;

// Generic instruction operand.
class Operand {
 public:
  Operand(void);
  ~Operand(void) = default;

  enum Type {
    kTypeInvalid,
    kTypeRegister,
    kTypeImmediate,
    kTypeAddress
  } type;

  enum Action {
    kActionInvalid,
    kActionRead,
    kActionWrite
  } action;

  // Size of this operand, in bits.
  size_t size;

  // kTypeRegister.
  class Register {
   public:
    Register(void);
    ~Register(void) = default;

    std::string name;
    size_t size;
  } reg;

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
    Address(void);
    ~Address(void) = default;

    Register segment_base_reg;
    Register base_reg;
    Register index_reg;
    int64_t scale;
    int64_t displacement;
    uint64_t address_size;
  } addr;

  std::string Debug(void) const;
};

// Generic instruction type.
class Instruction {
 public:
  ~Instruction(void) = default;

  // Name of semantics function that implements this instruction.
  std::string function;

  // The disassembly of this instruction.
  std::string disassembly;

  // Program counter for this instruction and the next instruction.
  uint64_t pc;
  uint64_t next_pc;

  // Used to tell higher levels about direct/conditional branch
  // targets.
  uint64_t branch_taken_pc;
  uint64_t branch_not_taken_pc;

  // Name of this instruction's architecture.
  ArchName arch_name;

  // The effective size of the operand, in bits.
  size_t operand_size;

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

  inline bool IsFunctionCall(void) const {
    switch (category) {
      case kCategoryDirectFunctionCall:
      case kCategoryIndirectFunctionCall:
        return true;
      default:
        return false;
    }
  }

  inline bool IsValid(void) const {
    return kCategoryInvalid != category;
  }

  // Length, in bytes, of the instruction.
  inline uint64_t NumBytes(void) const {
    return next_pc - pc;
  }

  inline bool IsNoOp(void) const {
    return kCategoryNoOp == category;
  }

 private:
  friend class X86Arch;

  Instruction(void);
};

}  // namespace remill


#endif  // REMILL_ARCH_INSTRUCTION_H_
