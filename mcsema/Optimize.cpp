/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "IntrinsicOptimizer"

#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>

#include <llvm/Transforms/Utils/Local.h>

namespace mcsema {
namespace {

// Looks for a function by name. If we can't find it, try to find an underscore
// prefixed version, just in case this is Mac or Windows.
static llvm::Function *GetFunction(llvm::Module &M, const char *name) {
  if (auto F = M.getFunction(name)) {
    return F;
  } else {
    std::stringstream ss;
    ss << "_" << name;
    return M.getFunction(ss.str());
  }
}

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceIntrinsic(llvm::Module &M, const char *name, unsigned N) {
  if (auto F = GetFunction(M, name)) {
    std::vector<llvm::CallInst *> Cs;
    for (auto U : F->users()) {
      if (auto C = llvm::dyn_cast<llvm::CallInst>(U)) {
        Cs.push_back(C);
      }
    }

    // Eliminate calls
    auto Undef = llvm::UndefValue::get(
        llvm::Type::getIntNTy(F->getContext(), N));
    for (auto C : Cs) {
      C->replaceAllUsesWith(Undef);
      C->removeFromParent();
      delete C;
    }
  }
}

// Remove calls to the undefined intrinsics. The goal here is to improve dead
// store elimination by peppering the instruction semantics with assignments
// to the return values of special `__mcsema_undefined_*` intrinsics. It's hard
// to reliably produce an `undef` LLVM value from C/C++, so we use our trick
// of declaring (but never defining) a special "intrinsic" and then we replace
// all such uses with `undef` values.
void RemoveUndefinedIntrinsics(llvm::Module &M) {
  ReplaceIntrinsic(M, "__mcsema_undefined_bool", 1);
  ReplaceIntrinsic(M, "__mcsema_undefined_8", 8);
  ReplaceIntrinsic(M, "__mcsema_undefined_16", 16);
  ReplaceIntrinsic(M, "__mcsema_undefined_32", 32);
  ReplaceIntrinsic(M, "__mcsema_undefined_64", 64);

  // Eliminate stores of undefined values.
  for (auto &F : M) {
    std::vector<llvm::Instruction *> dead_insts;
    for (auto &B : F) {
      for (auto &I : B) {
        if (auto S = llvm::dyn_cast<llvm::StoreInst>(&I)) {
          if (llvm::isa<llvm::UndefValue>(S->getValueOperand())) {
            dead_insts.push_back(S);
          }
        }
      }
    }

    // Eliminate dead code.
    while (!dead_insts.empty()) {
      auto D = dead_insts.back();
      dead_insts.pop_back();

      for (auto i = 0U; i < D->getNumOperands(); ++i) {
        auto O = D->getOperand(i);
        D->setOperand(i, nullptr);
        if (O->use_empty()) {
          if (auto I = llvm::dyn_cast<llvm::Instruction>(O)) {
            if (llvm::isInstructionTriviallyDead(I)) {
              dead_insts.push_back(I);
            }
          }
        }
      }
      D->removeFromParent();
    }
  }
}

}  // namespace

// Implements the deferred inlining optimization. McSema2 uses a special
// `__mcsema_defer_inlining` intrinsic to mark functions as needing to be
// "late" inlined. The idea is that we want some functions to be optimized
// away (flag computation functions), but the ones that stick around should
// then be inlined into their callers for further optimization.
class IntrinsicOptimizer : public llvm::ModulePass {
 public:
  IntrinsicOptimizer(void);
  ~IntrinsicOptimizer(void);

  virtual const char *getPassName(void) const override;
  virtual bool runOnModule(llvm::Module &M) override;

  static char ID;

 private:
};

IntrinsicOptimizer::IntrinsicOptimizer(void)
    : llvm::ModulePass(ID) {}

IntrinsicOptimizer::~IntrinsicOptimizer(void) {}

const char *IntrinsicOptimizer::getPassName(void) const {
  return "IntrinsicOptimizer";
}

bool IntrinsicOptimizer::runOnModule(llvm::Module &M) {
  RemoveUndefinedIntrinsics(M);

  auto F = GetFunction(M, "__mcsema_defer_inlining");
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

char IntrinsicOptimizer::ID = 0;

static llvm::RegisterPass<IntrinsicOptimizer> X(
    "intrinsic_optimizer",
    "Removes `__mcsema_defer_inlining` and `__mcsema_undefined_*` intrinsics.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.


}  // namespace mcsema
