#pragma once

#include <remill/Arch/Arch.h>
#include <remill/Arch/ArchBase.h>
#include <remill/Arch/MachineSpec.h>

#include <memory>
#include <unordered_map>
#include <utility>

namespace remill {
class ArchGroup {
 private:
  std::unordered_map<ArchName, Arch::ArchPtr> arches;
  //remill::OSName curr_os;
  std::unique_ptr<llvm::LLVMContext> context;
  MachineSpec spec;

  ArchGroup(MachineSpec spec,
            std::unordered_map<ArchName, Arch::ArchPtr> arches,
            std::unique_ptr<llvm::LLVMContext> context);

 public:
  bool DecodeInstruction(ArchName arch, uint64_t address,
                         std::string_view instr_bytes, Instruction &inst);

  const MachineSpec &GetSpec() const;

  static std::pair<ArchGroup, std::unique_ptr<llvm::Module>>
  Create(llvm::ArrayRef<ArchName> arches, remill::OSName os);


  // Get the LLVM DataLayout for this architecture group.
  llvm::DataLayout DataLayout(void) const;
};

}  // namespace remill