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


// Create a tail-call from one lifted function to another.
static void AddTerminatingTailCall(llvm::Function *source_func,
                                   llvm::Function *dest_func) {
  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(
      source_func->getContext(), "", source_func));

  std::vector<llvm::Value *> args;
  for (auto &arg : source_func->args()) {
    args.push_back(&arg);
  }

  llvm::CallInst *call_target_instr = ir.CreateCall(dest_func, args);
  call_target_instr->setAttributes(dest_func->getAttributes());

  // Make sure we tail-call from one block method to another.
  call_target_instr->setTailCallKind(llvm::CallInst::TCK_MustTail);
  call_target_instr->setCallingConv(llvm::CallingConv::Fast);
  ir.CreateRetVoid();
}

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
  auto detach = module.getFunction("__remill_detach");
  for (llvm::Function &function : module) {
    if (function.isDeclaration() &&
        function.getName().startswith("__remill_sub")) {
      AddTerminatingTailCall(&function, detach);
    }
  }
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
