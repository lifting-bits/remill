/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "remill_finalize"

#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>

#include <llvm/Transforms/Utils/Local.h>

namespace remill {
namespace {

static llvm::Function *GetFunction(llvm::Module &module, const char *name) {
  if (auto func = module.getFunction(name)) {
    return func;
  } else {
    std::stringstream ss;
    ss << "_" << name;
    return module.getFunction(ss.str());
  }
}

static void RemoveFunction(llvm::Function *function) {
  if (!function->hasNUsesOrMore(1)) {
    function->removeFromParent();
    delete function;
  }
}

static void RemoveFunction(llvm::Module &module, const char *name) {
  if (auto function = GetFunction(module, name)) {
    RemoveFunction(function);
  }
}

//static void RemoveNakedAttribute(llvm::Function &function) {
//  auto naked_attr = llvm::Attribute::get(function.getContext(),
//                                         llvm::Attribute::Naked);
//
//  function.removeFnAttr(llvm::Attribute::Naked);
//  for (auto &block : function) {
//    for (auto &inst : block) {
//      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
//        if (call_inst->hasFnAttr(llvm::Attribute::Naked)) {
//          call_inst->removeAttribute(llvm::AttributeSet::FunctionIndex,
//                                     naked_attr);
//        }
//      }
//    }
//  }
//}

}  // namespace

class FinalizeModulePass : public llvm::ModulePass {
 public:
  FinalizeModulePass(void);
  ~FinalizeModulePass(void);

  virtual const char *getPassName(void) const override;
  virtual bool runOnModule(llvm::Module &) override;

  static char ID;
};

FinalizeModulePass::FinalizeModulePass(void)
    : llvm::ModulePass(ID) {}

FinalizeModulePass::~FinalizeModulePass(void) {}

const char *FinalizeModulePass::getPassName(void) const {
  return DEBUG_TYPE;
}

bool FinalizeModulePass::runOnModule(llvm::Module &module) {
//  for (llvm::Function &function : module) {
//    RemoveNakedAttribute(function);
//  }
  RemoveFunction(module, "__remill_intrinsics");
  RemoveFunction(module, "__remill_mark_as_used");
  RemoveFunction(module, "__remill_defer_inlining");
  return true;
}

char FinalizeModulePass::ID = 0;

static llvm::RegisterPass<FinalizeModulePass> X(
    DEBUG_TYPE,
    "Makes the bitcode more usable for analysis and compilation.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.


}  // namespace remill
