/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "mcsema/BC/Util.h"

DECLARE_string(os);

namespace mcsema {

llvm::Function *&BlockMap::operator[](uintptr_t pc) {
  return this->std::unordered_map<uintptr_t, llvm::Function *>::operator[](pc);
}

llvm::Function *BlockMap::operator[](uintptr_t pc) const {
  const auto block_it = this->find(pc);
  if (this->end() == block_it) {
    LOG(WARNING) << "No block associated with PC " << pc;
    return nullptr;
  } else {
    return block_it->second;
  }
}

void InitFunctionAttributes(llvm::Function *F) {
  F->removeFnAttr(llvm::Attribute::NoReturn);
  F->addFnAttr(llvm::Attribute::NoUnwind);
  F->removeFnAttr(llvm::Attribute::UWTable);
  F->setCallingConv(llvm::CallingConv::Fast);
  F->setAlignment(0);
}

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *From, llvm::Function *To) {
  if (From->isDeclaration()) {
    llvm::BasicBlock::Create(From->getContext(), "entry", From);
  }
  AddTerminatingTailCall(&(From->back()), To);
}

void AddTerminatingTailCall(llvm::BasicBlock *B, llvm::Function *To) {
  LOG_IF(ERROR, B->getTerminator() || B->getTerminatingMustTailCall())
      << "Block already has a terminator; not adding fall-through call to: "
      << (To ? To->getName().str() : "<unreachable>");

  llvm::IRBuilder<> ir(B);
  if (!To) {
    LOG(WARNING) << "Target block does not exist!";
    ir.CreateUnreachable();
  } else {
    llvm::Function *F = B->getParent();
    llvm::Argument *SP = &*F->getArgumentList().begin();  // Machine state ptr.
    llvm::CallInst *C = ir.CreateCall(To, {SP});
    C->setTailCallKind(llvm::CallInst::TCK_MustTail);
    C->setCallingConv(llvm::CallingConv::Fast);
    ir.CreateRetVoid();
  }
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *F, std::string name) {
  for (auto &I : F->getEntryBlock()) {
    if (I.getName() == name) {
      return &I;
    }
  }
  LOG(FATAL) << "Could not find variable " << name << " in function "
             << F->getName().str();
  return nullptr;
}

// Return a pointer to the block method template.
llvm::Function *BlockMethod(llvm::Module *M) {
  if (FLAGS_os == "linux") {
    return M->getFunction("_ZN5State11BlockMethodEv");
  } else {
    LOG(FATAL) << "Missing block method for OS: " << FLAGS_os;
    return nullptr;
  }
}

// Return a pointer to the indirect branch method.
llvm::Function *IndirectBranchMethod(llvm::Module *M) {
  if (FLAGS_os == "linux") {
    return M->getFunction("_ZN5State20IndirectBranchMethodEv");
  } else {
    LOG(FATAL) << "Missing indirect branch method for OS: " << FLAGS_os;
    return nullptr;
  }
}

}  // namespace mcsema
