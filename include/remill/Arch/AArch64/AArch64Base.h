
#pragma once
#include <remill/Arch/Arch.h>
#include <remill/Arch/ArchBase.h>


// clang-format off
#define ADDRESS_SIZE 64
#include <remill/Arch/AArch64/Runtime/State.h>
// clang-format on

#include <string>
namespace remill {

class AArch64ArchBase : public virtual ArchBase {
 public:
  AArch64ArchBase(llvm::LLVMContext *context_, OSName os_name_,
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


  void PopulateRegisterTable(void) const override;
  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void
  FinishLiftedFunctionInitialization(llvm::Module *module,
                                     llvm::Function *bb_func) const override;
  virtual ~AArch64ArchBase(void) = default;
};
}  // namespace remill