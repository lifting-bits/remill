#pragma once
#include <remill/Arch/Instruction.h>

namespace remill {
// A pure virtual class that describes the properties
// of an architecture or a set of arches
class MachineSemantics {
 public:
  // Get the LLVM DataLayout for this architecture group.
  virtual llvm::DataLayout DataLayout(void) const = 0;

  // Return the type of the state structure.
  virtual llvm::StructType *StateStructType(void) const = 0;

  // Pointer to a state structure type.
  virtual llvm::PointerType *StatePointerType(void) const = 0;

  // The type of memory.
  virtual llvm::PointerType *MemoryPointerType(void) const = 0;

  // Return the type of a lifted function.
  virtual llvm::FunctionType *LiftedFunctionType(void) const = 0;

  // Returns the type of the register window. If the architecture doesn't have a register window, a
  // null pointer will be returned.
  virtual llvm::StructType *RegisterWindowType(void) const = 0;


  virtual unsigned RegMdID(void) const = 0;

  // Apply `cb` to every register.
  virtual void
  ForEachRegister(std::function<void(const Register *)> cb) const = 0;

  // Return information about the register at offset `offset` in the `State`
  // structure.
  virtual const Register *RegisterAtStateOffset(uint64_t offset) const = 0;

  // Return information about a register, given its name.
  virtual const Register *RegisterByName(std::string_view name) const = 0;

  // Returns the name of the stack pointer register.
  virtual std::string_view StackPointerRegisterName(void) const = 0;

  // Returns the name of the program counter register.
  virtual std::string_view ProgramCounterRegisterName(void) const = 0;

  // Minimum alignment of an instruction for this particular architecture.
  virtual uint64_t MinInstructionAlign(void) const = 0;

  // Minimum number of bytes in an instruction for this particular architecture.
  virtual uint64_t MinInstructionSize(void) const = 0;

  // Maximum number of bytes in an instruction for this particular architecture.
  //
  // `permit_fuse_idioms` is `true` if Remill is allowed to decode multiple
  // instructions at a time and look for instruction fusing idioms that are
  // common to this architecture.
  virtual uint64_t MaxInstructionSize(bool permit_fuse_idioms = true) const = 0;

  // Default calling convention for this architecture.
  virtual llvm::CallingConv::ID DefaultCallingConv(void) const = 0;

  // Get the LLVM triple for this architecture.
  virtual llvm::Triple Triple(void) const = 0;
};
}  // namespace remill