
#pragma once
#include <remill/Arch/Arch.h>
#include <remill/Arch/ArchBase.h>
// clang-format off
#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 1
#define ADDRESS_SIZE_BITS 64
#define INCLUDED_FROM_REMILL
#include <remill/Arch/X86/Runtime/State.h>
// clang-format on

#include <string>
namespace remill {
/// Class to derive from to handle x86 addregs
class X86ArchBase : public virtual ArchBase {
 public:
  X86ArchBase(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
      : ArchBase(context_, os_name_, arch_name_) {}

  virtual std::string_view StackPointerRegisterName(void) const;

  std::string_view ProgramCounterRegisterName(void) const;
  uint64_t MinInstructionAlign(void) const;


  uint64_t MinInstructionSize(void) const;

  uint64_t MaxInstructionSize(bool) const;
  llvm::CallingConv::ID DefaultCallingConv(void) const;

  llvm::DataLayout DataLayout(void) const;

  llvm::Triple Triple(void) const;


  void PopulateRegisterTable(void) const;
  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void FinishLiftedFunctionInitialization(llvm::Module *module,
                                          llvm::Function *bb_func) const;
  virtual ~X86ArchBase(void) = default;
};
}  // namespace remill