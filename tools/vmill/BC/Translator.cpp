/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Optimizer.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/BC/Translator.h"

DECLARE_string(arch);
DECLARE_string(workspace);

DEFINE_uint64(bitcode_save_interval, 256,
              "How many new functions need to be lifted into the bitcode "
              "file before it is cached to disk.");

DEFINE_bool(delete_old_saved_bitcode, false,
            "Should stale cached bitcode files be deleted from disk?");

DEFINE_bool(disable_optimizer, false,
            "Should the lifted bitcode optimizer be disabled?");

namespace remill {
namespace vmill {
namespace {

// Get the path to the code version-specific bitcode cache directory. If the
// file doesn't exist, or is empty, then use the semantics bitcode file
// instead.
static std::string GetBitcodeFile(CodeVersion code_version) {
  std::stringstream ss;
  ss << FLAGS_workspace << "/bitcode.cache";
  CHECK(TryCreateDirectory(ss.str()))
      << "Unable to create the " << ss.str() << " directory.";

  ss << "/" << code_version << ".bc";
  auto file_name = ss.str();

  if (!FileExists(file_name) || !FileSize(file_name)) {
    auto sem_path = FindSemanticsBitcodeFile("", FLAGS_arch);
    auto sem_fd = open(sem_path.c_str(), O_RDONLY);
    auto bc_fd = open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    auto sem_file_size = FileSize(sem_path);
    CHECK(-1 != sendfile(bc_fd, sem_fd, nullptr, sem_file_size))
        << "Unable to copy semantics bitcode file " << sem_path
        << " to " << sem_path << ": " << strerror(errno);
    close(sem_fd);
    close(bc_fd);
  }

  return file_name;
}
}  // namespace

// Handles translating binary code to bitcode, and caching that bitcode.
class TE final : public Translator {
 public:
  explicit TE(CodeVersion code_version_, const Arch *source_arch_);

  virtual ~TE(void);

  void LiftCFG(const cfg::Module *cfg) override;

  // Run a callback on the lifted module code.
  void VisitModule(LiftedModuleCallback callback) override;

 private:
  // Path to our cached bitcode file.
  const std::string bitcode_file_path;

  // Context in which all translated code modules are stored.
  llvm::LLVMContext * const context;

  // Module containing lifted code and/or semantics.
  llvm::Module * const module;

  // Remill's CFG to bitcode lifter.
  Lifter lifter;

  Optimizer * const optimizer;

  // Number of functions in the bitcode module when we last saved to disk.
  size_t last_serialize_count;
};

Translator::Translator(CodeVersion code_version_, const Arch *source_arch_)
    : code_version(code_version_),
      source_arch(source_arch_) {}

Translator::~Translator(void) {}

// Create a new translation engine for a given version of the code in
// memory. Code version changes happen due to self-modifying code, or
// runtime code loading.
Translator *Translator::Create(CodeVersion code_version_,
                               const Arch *source_arch_) {
  DLOG(INFO)
      << "Creating machine code to bitcode translator.";
  return new TE(code_version_, source_arch_);
}

// Initialize the translation engine.
TE::TE(CodeVersion code_version_, const Arch *source_arch_)
    : Translator(code_version_, source_arch_),
      bitcode_file_path(GetBitcodeFile(code_version)),
      context(new llvm::LLVMContext),
      module(LoadModuleFromFile(context, bitcode_file_path)),
      lifter(source_arch, module),
      optimizer(Optimizer::Create(module)),
      last_serialize_count(module->getFunctionList().size()) {
  source_arch->PrepareModule(module);
}

// Destroy the translation engine.
TE::~TE(void) {

  delete optimizer;

  // TODO(pag): This isn't all that nice. The native executor's JIT compiler
  //            marks private functions as externally available to prevent
  //            recompilation.
  for (auto &func : *module) {
    if (func.hasAvailableExternallyLinkage()) {
      func.setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  // TODO(pag): This isn't all that nice. The native executor's JIT compiler
  //            marks externally available globals with initializers as having
  //            available externally linkage to prevent recompilation.
  for (auto &global : module->globals()) {
    if (global.hasAvailableExternallyLinkage()) {
      global.setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }

  StoreModuleToFile(module, bitcode_file_path);
  delete module;
  delete context;
}

void TE::LiftCFG(const cfg::Module *cfg) {
  // The native executor uses `AvailableExternallyLinkage` to avoid recompiling
  // the same code twice, but that will play havoc with the optimizer, so
  // we need to undo some of that here, then re-do it :-/
  std::unordered_set<llvm::GlobalValue *> externs;
  for (auto &func : *module) {
    if (func.hasAvailableExternallyLinkage()) {
      externs.insert(&func);
      func.setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  for (auto &global : module->globals()) {
    if (global.hasAvailableExternallyLinkage()) {
      externs.insert(&global);
      global.setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }
  auto start_lift = time(nullptr);
  // Lift and optimize.
  lifter.LiftCFG(cfg);

  auto start_opt = time(nullptr);
  LOG(INFO)
      << "Spent " << (start_opt - start_lift) << "s lifting.";

  if (!FLAGS_disable_optimizer) {
    optimizer->Optimize();
    auto end_opt = time(nullptr);
    LOG(INFO)
        << "Spent " << (end_opt - start_opt) << "s optimizing.";
  }

  // Cache the module to disk if we've added enough new things to it since
  // our last save.
  auto new_num_funcs = module->getFunctionList().size();
  if ((new_num_funcs - last_serialize_count) >= FLAGS_bitcode_save_interval) {
    DLOG(INFO)
        << "Serializing " << module->getModuleIdentifier() << " to disk.";
    last_serialize_count = new_num_funcs;

    std::stringstream ss;
    ss << bitcode_file_path << "." << new_num_funcs;
    auto temp_path = ss.str();

    StoreModuleToFile(module, temp_path);
    HardLinkOrCopy(temp_path, bitcode_file_path);

    if (FLAGS_delete_old_saved_bitcode) {
      RemoveFile(temp_path);
    }
  }

  // Undo the above changes. We can't operate directly on what's in the set
  // because some of those entries may have been removed.

  for (auto &func : *module) {
    if (externs.count(&func)) {
      func.setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
    }
  }

  for (auto &global : module->globals()) {
    if (externs.count(&global)) {
      global.setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
    }
  }
}

// Run a callback on the lifted module code.
void TE::VisitModule(LiftedModuleCallback callback) {
  callback(module);
}

}  // namespace vmill
}  // namespace remill
