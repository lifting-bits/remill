/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "mcsema_finalize"

#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>

#include <llvm/Transforms/Utils/Local.h>

namespace mcsema {

// Removes the `naked` attribute from all the things.
class NakedRemover : public llvm::ModulePass {
 public:
  NakedRemover(void);
  ~NakedRemover(void);

  virtual const char *getPassName(void) const override;
  virtual bool runOnModule(llvm::Module &) override;

  static char ID;

 private:
};

NakedRemover::NakedRemover(void)
    : llvm::ModulePass(ID) {}

NakedRemover::~NakedRemover(void) {}

const char *NakedRemover::getPassName(void) const {
  return DEBUG_TYPE;
}

bool NakedRemover::runOnModule(llvm::Module &module) {
  for (auto &function : module) {
    function.removeFnAttr(llvm::Attribute::Naked);
  }
  return true;
}

char NakedRemover::ID = 0;

static llvm::RegisterPass<NakedRemover> X(
    DEBUG_TYPE,
    "Removes extraneous `naked` attributes.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.


}  // namespace mcsema
