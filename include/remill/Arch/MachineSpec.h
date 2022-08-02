#pragma once

#include <remill/Arch/Arch.h>

#include <unordered_map>

namespace remill {
// Defines properties that should be shared between arches in an arch group
// These are intialized
class MachineSpec {
 private:
  // State type. Initially this is `nullptr` because we can construct and arch
  // without loading in a semantics module. When we load a semantics module, we
  // learn about the LLVM type of the state structure, and so we need to be
  // able to update this in-place.
  llvm::StructType *state_type;

  // Memory pointer type.
  llvm::PointerType *memory_type;

  // Lifted function type.
  llvm::FunctionType *lifted_function_type;

  // Register window type.
  mutable llvm::StructType *register_window_type{nullptr};

  // Metadata type ID for remill registers.
  mutable unsigned reg_md_id{0};

  mutable std::vector<std::unique_ptr<Register>> registers;
  mutable std::vector<const Register *> reg_by_offset;
  mutable std::unordered_map<std::string, const Register *> reg_by_name;


 public:
  MachineSpec(llvm::Module *module);

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void);

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void);

  llvm::DataLayout DataLayout(void) const;

  const Register *RegisterByName(std::string_view name) const;

  llvm::PointerType *MemoryPointerType(void) const;

  llvm::PointerType *StatePointerType(void) const;

  uint64_t address_size;
};
}  // namespace remill