#pragma once

#include <remill/Arch/Arch.h>
#include <remill/Arch/MachineSemantics.h>

#include <memory>
#include <unordered_map>
#include <utility>

namespace remill {

class ArchLifter {
 private:
  InstructionLifter::LifterPtr lifter;
  Arch::ArchPtr arch;

 public:
  ArchLifter(InstructionLifter::LifterPtr lifter, Arch::ArchPtr arch);


  InstructionLifter::LifterPtr &GetLifter();
  Arch::ArchPtr &GetArch();
};


class ArchGroup : public MachineSemantics {
 private:
  std::unordered_map<ArchName, ArchLifter> arches;
  std::unique_ptr<llvm::LLVMContext> context;

  ArchGroup(std::unordered_map<ArchName, ArchLifter> arches,
            std::unique_ptr<llvm::LLVMContext> context);

 public:
  remill::OSName GetOS() const;
  llvm::LLVMContext &GetContext() const;

  bool DecodeInstruction(ArchName arch, uint64_t address,
                         std::string_view instr_bytes, Instruction &inst);

  static std::pair<ArchGroup, std::unique_ptr<llvm::Module>>
  Create(llvm::ArrayRef<ArchName> arches, remill::OSName os);


  static std::pair<ArchGroup, std::unique_ptr<llvm::Module>>
  GetModuleArchGroup(const llvm::Module &mod);

  // Get the LLVM DataLayout for this architecture group.
  llvm::DataLayout DataLayout(void) const override;

  // Return the type of the state structure.
  llvm::StructType *StateStructType(void) const override;

  // Pointer to a state structure type.
  virtual llvm::PointerType *StatePointerType(void) const override;

  // The type of memory.
  virtual llvm::PointerType *MemoryPointerType(void) const override;

  // Return the type of a lifted function.
  virtual llvm::FunctionType *LiftedFunctionType(void) const override;

  // Returns the type of the register window. If the architecture doesn't have a register window, a
  // null pointer will be returned.
  virtual llvm::StructType *RegisterWindowType(void) const override;


  virtual unsigned RegMdID(void) const override;

  // Apply `cb` to every register.
  virtual void
  ForEachRegister(std::function<void(const Register *)> cb) const override;

  // Return information about the register at offset `offset` in the `State`
  // structure.
  virtual const Register *RegisterAtStateOffset(uint64_t offset) const override;

  // Return information about a register, given its name.
  virtual const Register *RegisterByName(std::string_view name) const override;

  // Returns the name of the stack pointer register.
  virtual std::string_view StackPointerRegisterName(void) const override;

  // Returns the name of the program counter register.
  virtual std::string_view ProgramCounterRegisterName(void) const override;

  // Minimum alignment of an instruction for this particular architecture.
  virtual uint64_t MinInstructionAlign(void) const override;

  // Minimum number of bytes in an instruction for this particular architecture.
  virtual uint64_t MinInstructionSize(void) const override;

  // Maximum number of bytes in an instruction for this particular architecture.
  //
  // `permit_fuse_idioms` is `true` if Remill is allowed to decode multiple
  // instructions at a time and look for instruction fusing idioms that are
  // common to this architecture.
  virtual uint64_t
  MaxInstructionSize(bool permit_fuse_idioms = true) const override;

  // Default calling convention for this architecture.
  virtual llvm::CallingConv::ID DefaultCallingConv(void) const override;

  // Get the LLVM triple for this architecture.
  virtual llvm::Triple Triple(void) const override;


  std::set<ArchName> ArchNames() const;
};

}  // namespace remill