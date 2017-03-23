/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
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

#ifndef BUILD_RUNTIME_DIR
# define BUILD_RUNTIME_DIR
#endif  // BUILD_RUNTIME_DIR

#ifndef INSTALL_RUNTIME_DIR
# define INSTALL_RUNTIME_DIR
#endif  // INSTALL_RUNTIME_DIR

DEFINE_bool(disable_optimizer, false,
            "Should the lifted bitcode optimizer be disabled?");

namespace remill {
namespace vmill {
namespace {

}  // namespace

// Handles translating binary code to bitcode, and caching that bitcode.
class TE final : public Translator {
 public:
  explicit TE(llvm::Module *module_);

  virtual ~TE(void);

  void LiftCFG(const cfg::Module *cfg) override;

 private:
  // Module containing lifted code and/or semantics.
  llvm::Module * const module;

  // Remill's CFG to bitcode lifter.
  Lifter lifter;

  const std::unique_ptr<Optimizer> optimizer;
};

Translator::Translator(void)
    : source_arch(GetGlobalArch()) {}

Translator::~Translator(void) {}

// Create a new translation engine for a given version of the code in
// memory. Code version changes happen due to self-modifying code, or
// runtime code loading.
std::unique_ptr<Translator> Translator::Create(llvm::Module *module_) {
  DLOG(INFO)
      << "Creating machine code to bitcode translator.";
  return std::unique_ptr<Translator>(new TE(module_));
}

// Initialize the translation engine.
TE::TE(llvm::Module *module_)
    : Translator(),
      module(module_),
      lifter(source_arch, module),
      optimizer(Optimizer::Create(module)) {
  source_arch->PrepareModule(module);
}

// Destroy the translation engine.
TE::~TE(void) {}

void TE::LiftCFG(const cfg::Module *cfg) {

  auto start_lift = time(nullptr);
  lifter.LiftCFG(cfg);

  auto start_opt = time(nullptr);
  DLOG(INFO)
      << "Spent " << (start_opt - start_lift) << "s lifting.";

  if (!FLAGS_disable_optimizer) {
    optimizer->Optimize();
    auto end_opt = time(nullptr);
    DLOG(INFO)
        << "Spent " << (end_opt - start_opt) << "s optimizing.";
  }
}

}  // namespace vmill
}  // namespace remill
