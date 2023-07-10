#pragma once
#include <remill/Arch/Arch.h>
#include <remill/Arch/ArchBase.h>

#include <remill/Arch/SPARC32/Runtime/State.h>

namespace remill {

class SPARC32ArchBase : public virtual ArchBase {
 public:
  SPARC32ArchBase(llvm::LLVMContext *context_, OSName os_name_,
                   ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_) {}

  virtual std::string_view StackPointerRegisterName(void) const override;

  std::string_view ProgramCounterRegisterName(void) const override;

  llvm::CallingConv::ID DefaultCallingConv(void) const override;
  llvm::DataLayout DataLayout(void) const override;
  llvm::Triple Triple(void) const override;

  // Align/Minimum/Maximum number of bytes in an instruction.
  uint64_t MinInstructionAlign(const DecodingContext &) const override;
  uint64_t MinInstructionSize(const DecodingContext &) const override;
  uint64_t MaxInstructionSize(const DecodingContext &,
                              bool permit_fuse_idioms) const override;
  bool MemoryAccessIsLittleEndian(void) const override;
  // Returns `true` if a given instruction might have a delay slot.
  bool MayHaveDelaySlot(const Instruction &inst) const override;
  // Returns `true` if we should lift the semantics of `next_inst` as a delay
  // slot of `inst`. The `branch_taken_path` tells us whether we are in the
  // context of the taken path of a branch or the not-taken path of a branch.
  virtual bool NextInstructionIsDelayed(const Instruction &inst,
                                        const Instruction &next_inst,
                                        bool branch_taken_path) const final;
  void PopulateRegisterTable(void) const override;
  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override;
  virtual ~SPARC32ArchBase(void) = default;
};

}  // namespace remill
