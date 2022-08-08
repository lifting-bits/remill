#include <glog/logging.h>
#include <remill/Arch/ArchGroup.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Annotate.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include <algorithm>

namespace remill {
ArchGroup::ArchGroup(std::unordered_map<ArchName, ArchLifter> arches_,
                     std::unique_ptr<llvm::LLVMContext> context_)
    : arches(std::move(arches_)),
      context(std::move(context_)) {}

InstructionLifter::LifterPtr &ArchLifter::GetLifter() {
  return this->lifter;
}

Arch::ArchPtr &ArchLifter::GetArch() {
  return this->arch;
}

bool ArchGroup::DecodeInstruction(ArchName arch, uint64_t address,
                                  std::string_view instr_bytes,
                                  Instruction &inst) {
  if (this->arches.find(arch) == this->arches.end()) {
    throw std::runtime_error(
        "Attempting to decode with unsupported arch in this group");
  }

  return this->arches.find(arch)->second.GetArch()->DecodeInstruction(
      address, instr_bytes, inst);
}


// Lift a single instruction into a basic block. `is_delayed` signifies that
// this instruction will execute within the delay slot of another instruction.
/*
LiftStatus ArchGroup::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                    bool is_delayed = false) {
  if (this->arches.find(inst.arch) == this->arches.end()) {
    throw std::runtime_error(
        "Attempting to lift with unsupported arch in this group");
  }

  return this->arches.find(inst.arch)->second->Lif(address, instr_bytes, inst);
}

// Load the address of a register.
std::pair<llvm::Value *, llvm::Type *>
ArchGroup::LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                          std::string_view reg_name) const {
  // It ought not to matter which arch we call to load a register address
}

// Load the value of a register.
llvm::Value *ArchGroup::LoadRegValue(llvm::BasicBlock *block,
                                     llvm::Value *state_ptr,
                                     std::string_view reg_name) const {
  // It ought not to matter which arch we call to load a register
}*/

std::pair<ArchGroup, std::unique_ptr<llvm::Module>>
ArchGroup::Create(llvm::ArrayRef<ArchName> arches, remill::OSName os) {
  if (arches.empty()) {
    throw std::runtime_error("Cannot create empty arch group");
  }

  std::set<ArchName> arch_set(arches.begin(), arches.end());


  auto name = arches.size() == 1 ? GetArchNameOpt(arches[0])
                                 : GetArchGroupName(arch_set);
  if (!name) {
    throw std::runtime_error("No arch group for set of arches");
  }
  auto context = std::make_unique<llvm::LLVMContext>();
  std::unordered_map<ArchName, Arch::ArchPtr> built_arches;
  for (auto nm : arches) {
    auto child_arch = Arch::Get(*context, os, nm);
    if (!child_arch) {
      std::stringstream ss;
      ss << "Could not build arch with name: " << GetArchName(nm);
      throw std::runtime_error(ss.str());
    }
    built_arches.emplace(nm, std::move(child_arch));
  }

  // If `sem_dirs` does not contain the dir, fallback to compiled in paths.
  auto path = FindSemanticsBitcodeFile(*name, {}, true);

  if (!path)
    LOG(FATAL) << "Cannot find path to " << *name << " semantics bitcode file.";

  DLOG(INFO) << "Loading " << *name << " semantics from file " << *path;

  auto module = LoadModuleFromFile(context.get(), *path);
  auto &first = built_arches[arches[0]];
  first->PrepareModule(module);

  for (auto &kv : built_arches) {
    kv.second->InitFromSemanticsModule(module.get());
  }


  for (auto &func : *module) {
    Annotate<remill::Semantics>(&func);
  }

  IntrinsicTable intrinsic_table(module.get());

  std::unordered_map<ArchName, ArchLifter> lifters;
  std::transform(
      built_arches.begin(), built_arches.end(),
      std::inserter(lifters, lifters.end()),
      [&intrinsic_table](
          std::unordered_map<ArchName, Arch::ArchPtr>::value_type &aptr)
          -> std::pair<ArchName, ArchLifter> {
        auto lifter = aptr.second->DefaultLifter(intrinsic_table);
        return {aptr.first,
                ArchLifter(std::move(lifter), std::move(aptr.second))};
      });


  return std::make_pair(ArchGroup(std::move(lifters), std::move(context)),
                        std::move(module));
}

std::set<ArchName> ArchGroup::ArchNames() const {
  std::set<ArchName> archs;
  std::transform(
      arches.begin(), arches.end(), std::inserter(archs, archs.begin()),
      [](const std::unordered_map<ArchName, ArchLifter>::value_type &pr) {
        return pr.first;
      });

  return archs;
}

llvm::LLVMContext &ArchGroup::GetContext() const {
  return *this->context;
}

}  // namespace remill