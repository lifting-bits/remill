/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>
#include <system_error>

#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>

#include "mcsema/BC/Util.h"

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

// Initialize the attributes for a lifted function.
void InitFunctionAttributes(llvm::Function *F) {
  // This affects code generation. The key thing here is to disallow dead
  // argument elimination in LLVM's optimizer.
  F->addFnAttr(llvm::Attribute::Naked);

  // Make sure functions are treated as if they return. LLVM doesn't like
  // mixing must-tail-calls with no-return.
  F->removeFnAttr(llvm::Attribute::NoReturn);

  // Don't use any exception stuff.
  F->addFnAttr(llvm::Attribute::NoUnwind);
  F->removeFnAttr(llvm::Attribute::UWTable);

  // To use must-tail-calls everywhere we need to use the `fast` calling
  // convention, where it's up the LLVM to decide how to pass arguments.
  F->setCallingConv(llvm::CallingConv::Fast);

  // Mark everything for inlining, but don't require it.
  F->addFnAttr(llvm::Attribute::InlineHint);
}

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *From, llvm::Function *To,
                            uintptr_t addr) {
  if (From->isDeclaration()) {
    std::stringstream ss;
    ss << "0x" << std::hex << addr;
    llvm::BasicBlock::Create(From->getContext(), ss.str(), From);
  }
  AddTerminatingTailCall(&(From->back()), To, addr);
}

void AddTerminatingTailCall(llvm::BasicBlock *B, llvm::Function *To,
                            uintptr_t addr) {
  LOG_IF(FATAL, !To)
      << "Target function/block does not exist!";

  auto ToTy = To->getFunctionType();

  LOG_IF(FATAL, 2 != ToTy->getNumParams())
      << "Expected one argument for call to: "
      << (To ? To->getName().str() : "<unreachable>");

  auto Arg2Ty = ToTy->getParamType(1);
  if (auto IntPtrTy = llvm::dyn_cast<llvm::IntegerType>(Arg2Ty)) {
    AddTerminatingTailCall(
        B, To, llvm::ConstantInt::get(IntPtrTy, addr, false));
  } else {
    LOG(FATAL)
        << "Expected second parameter to function " << To->getName().str()
        << " to be an integral type.";
  }
}

void AddTerminatingTailCall(llvm::BasicBlock *B, llvm::Function *To,
                            llvm::Value *addr) {
  LOG_IF(FATAL, !To)
      << "Target function/block does not exist!";

  LOG_IF(ERROR, B->getTerminator() || B->getTerminatingMustTailCall())
      << "Block already has a terminator; not adding fall-through call to: "
      << (To ? To->getName().str() : "<unreachable>");

  LOG_IF(FATAL, 2 != To->getFunctionType()->getNumParams())
      << "Expected two arguments for call to: "
      << (To ? To->getName().str() : "<unreachable>");

  llvm::IRBuilder<> ir(B);
  llvm::Function *F = B->getParent();
  std::vector<llvm::Value *> args;
  args.push_back(FindStatePointer(F));
  args.push_back(addr);
  llvm::CallInst *C = ir.CreateCall(To, args);
  C->setAttributes(To->getAttributes());

  // Make sure we tail-call from one block method to another.
  C->setTailCallKind(llvm::CallInst::TCK_MustTail);
  C->setCallingConv(llvm::CallingConv::Fast);
  ir.CreateRetVoid();
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *F, std::string name,
                               bool allow_failure) {
  for (auto &I : F->getEntryBlock()) {
    if (I.getName() == name) {
      return &I;
    }
  }
  LOG_IF(FATAL, !allow_failure)
    << "Could not find variable " << name << " in function "
    << F->getName().str();
  return nullptr;
}

// Find the machine state pointer.
llvm::Value *FindStatePointer(llvm::Function *F) {
  if (auto state = FindVarInFunction(F, "state", true)) {
    return state;
  }
  return &*F->getArgumentList().begin();
}

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *M, std::string name) {
  return M->getFunction(name);
}

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(const llvm::Module *M,
                                        std::string name) {
  return M->getGlobalVariable(name);
}

// Reads an LLVM module from a file.
llvm::Module *LoadModuleFromFile(std::string file_name) {
  llvm::SMDiagnostic err;
  auto mod_ptr = llvm::parseIRFile(file_name, err, llvm::getGlobalContext());
  auto module = mod_ptr.get();
  mod_ptr.release();

  CHECK(nullptr != module) << "Unable to parse module file: " << file_name;

  module->materializeAll();  // Just in case.
  return module;
}

// Store an LLVM module into a file.
void StoreModuleToFile(llvm::Module *M, std::string file_name) {
  std::string error;
  llvm::raw_string_ostream error_stream(error);

  if (llvm::verifyModule(*M, &error_stream)) {
    LOG(FATAL)
        << "Error writing module to file " << file_name << ". " << error;
  }

  std::error_code ec;
  llvm::tool_output_file bc(file_name.c_str(), ec, llvm::sys::fs::F_None);

  CHECK(!ec)
      << "Unable to open output bitcode file for writing: " << file_name;

  llvm::WriteBitcodeToFile(M, bc.os());
  bc.keep();

  CHECK(!ec)
      << "Error writing bitcode to file: " << file_name;
}

}  // namespace mcsema
