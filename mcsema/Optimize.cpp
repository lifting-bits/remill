/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "McSema2Optimizer"

#include <iostream>
#include <set>
#include <vector>

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>

namespace mcsema {

// Implements the deferred inlining optimization. McSema2 uses a special
// `__mcsema_defer_inlining` intrinsic to mark functions as needing to be
// "late" inlined. The idea is that we want some functions to be optimized
// away (flag computation functions), but the ones that stick around should
// then be inlined into their callers for further optimization.
class DeferredInlineOptimizer : public llvm::ModulePass {
 public:
  DeferredInlineOptimizer(void);
  ~DeferredInlineOptimizer(void);

  virtual const char *getPassName(void) const override;
  virtual bool runOnModule(llvm::Module &M) override;

  static char ID;

 private:
};

DeferredInlineOptimizer::DeferredInlineOptimizer(void)
    : llvm::ModulePass(ID) {}

DeferredInlineOptimizer::~DeferredInlineOptimizer(void) {}

const char *DeferredInlineOptimizer::getPassName(void) const {
  return "DeferredInlineOptimizer";
}

bool DeferredInlineOptimizer::runOnModule(llvm::Module &M) {
  auto F = M.getFunction("__mcsema_defer_inlining");
  if (!F) {
    return false;
  }

  std::vector<llvm::CallInst *> Cs;
  std::set<llvm::Function *> Fs;

  // Find all calls to the inline defer intrinsic.
  for (auto U : F->users()) {
    if (auto C = llvm::dyn_cast_or_null<llvm::CallInst>(U)) {
      Cs.push_back(C);
    }
  }

  // Remove the calls to the inline defer intrinsic, and mark the functions
  // containing those calls as inlinable.
  auto changed = false;
  for (auto C : Cs) {
    auto B = C->getParent();
    auto F = B->getParent();

    Fs.insert(F);

    F->setCallingConv(llvm::CallingConv::Fast);

    F->removeFnAttr(llvm::Attribute::NoInline);
    F->addFnAttr(llvm::Attribute::AlwaysInline);
    F->addFnAttr(llvm::Attribute::InlineHint);

    C->replaceAllUsesWith(llvm::UndefValue::get(C->getType()));
    C->eraseFromParent();
    changed = true;
  }

  // Emulate the `flatten` attribute by finding all calls to functions that
  // containing the inline defer intrinsic, and mark the call instructions
  // as requiring inlining.
  for (auto F : Fs) {
    for (auto U : F->users()) {
      if (auto C = llvm::dyn_cast_or_null<llvm::CallInst>(U)) {
        C->addAttribute(llvm::AttributeSet::FunctionIndex,
                        llvm::Attribute::AlwaysInline);
      }
    }
  }

  return changed;
}

char DeferredInlineOptimizer::ID = 0;

static llvm::RegisterPass<DeferredInlineOptimizer> X(
    "deferred_inliner",
    "Optimizes `__mcsema_defer_inlining` intrinsics.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.


}  // namespace mcsema
