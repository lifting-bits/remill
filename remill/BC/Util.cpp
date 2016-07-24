/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

namespace remill {

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
void InitFunctionAttributes(llvm::Function *function) {

  // Make sure functions are treated as if they return. LLVM doesn't like
  // mixing must-tail-calls with no-return.
  function->removeFnAttr(llvm::Attribute::NoReturn);

  // Don't use any exception stuff.
  function->addFnAttr(llvm::Attribute::NoUnwind);
  function->removeFnAttr(llvm::Attribute::UWTable);

  // To use must-tail-calls everywhere we need to use the `fast` calling
  // convention, where it's up the LLVM to decide how to pass arguments.
  function->setCallingConv(llvm::CallingConv::Fast);

  // Mark everything for inlining, but don't require it.
  function->addFnAttr(llvm::Attribute::InlineHint);
}

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *source_func,
                            llvm::Function *dest_func) {
  CHECK(source_func->arg_size() == dest_func->arg_size());

  if (source_func->isDeclaration()) {
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

  } else {
    AddTerminatingTailCall(&(source_func->back()), dest_func);
  }
}

void AddTerminatingTailCall(llvm::BasicBlock *source_block,
                            llvm::Function *dest_func) {
  CHECK(nullptr != dest_func)
      << "Target function/block does not exist!";

  LOG_IF(ERROR, source_block->getTerminator() ||
                source_block->getTerminatingMustTailCall())
      << "Block already has a terminator; not adding fall-through call to: "
      << (dest_func ? dest_func->getName().str() : "<unreachable>");

  CHECK(kNumBlockArgs == dest_func->getFunctionType()->getNumParams())
      << "Expected " << size_t(kNumBlockArgs) << " arguments for call to: "
      << (dest_func ? dest_func->getName().str() : "<unreachable>");

  llvm::IRBuilder<> ir(source_block);

  // Set up arguments according to our ABI.
  std::vector<llvm::Value *> args;
  args.resize(kNumBlockArgs);
  args[kStatePointerArgNum] = LoadStatePointer(source_block);
  args[kMemoryPointerArgNum] = LoadMemoryPointer(source_block);
  args[kPCArgNum] = LoadProgramCounter(source_block);

  llvm::CallInst *call_target_instr = ir.CreateCall(dest_func, args);
  call_target_instr->setAttributes(dest_func->getAttributes());

  // Make sure we tail-call from one block method to another.
  call_target_instr->setTailCallKind(llvm::CallInst::TCK_MustTail);
  call_target_instr->setCallingConv(llvm::CallingConv::Fast);
  ir.CreateRetVoid();
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *function, std::string name,
                               bool allow_failure) {
  for (auto &instr : function->getEntryBlock()) {
    if (instr.getName() == name) {
      return &instr;
    }
  }
  function->dump();
  CHECK(allow_failure)
    << "Could not find variable " << name << " in function "
    << function->getName().str();
  return nullptr;
}

// Find the machine state pointer.
llvm::Value *LoadStatePointer(llvm::Function *function) {
  CHECK(kNumBlockArgs == function->arg_size())
      << "Invalid block-like function. Expected two arguments: state "
      << "pointer and program counter in function "
      << function->getName().str();

  auto curr_arg_num = 0;
  for (llvm::Argument &arg : function->getArgumentList()) {
    if (kStatePointerArgNum == curr_arg_num++) {
      return &arg;
    }
  }

  return nullptr;
}

llvm::Value *LoadStatePointer(llvm::BasicBlock *block) {
  return LoadStatePointer(block->getParent());
}

// Return the current program counter.
llvm::Value *LoadProgramCounter(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(ir.CreateLoad(FindVarInFunction(
      block->getParent(), "PC")));
}

// Return the pointer to the current value of the memory pointer.
llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(FindVarInFunction(
      block->getParent(), "MEMORY"));
}

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *module, std::string name) {
  return module->getFunction(name);
}

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(const llvm::Module *module,
                                        std::string name) {
  return module->getGlobalVariable(name);
}

// Reads an LLVM module from a file.
llvm::Module *LoadModuleFromFile(std::string file_name) {
  llvm::SMDiagnostic err;
  auto mod_ptr = llvm::parseIRFile(file_name, err, llvm::getGlobalContext());
  auto module = mod_ptr.get();
  mod_ptr.release();

  CHECK(nullptr != module)
      << "Unable to parse module file: " << file_name;

  module->materializeAll();  // Just in case.
  return module;
}

// Store an LLVM module into a file.
void StoreModuleToFile(llvm::Module *module, std::string file_name) {
  std::string error;
  llvm::raw_string_ostream error_stream(error);

  if (llvm::verifyModule(*module, &error_stream)) {
    LOG(FATAL)
        << "Error writing module to file " << file_name << ". " << error;
  }

  std::error_code ec;
  llvm::tool_output_file bc(file_name.c_str(), ec, llvm::sys::fs::F_RW);

  CHECK(!ec)
      << "Unable to open output bitcode file for writing: " << file_name;

  llvm::WriteBitcodeToFile(module, bc.os());
  bc.keep();

  CHECK(!ec)
      << "Error writing bitcode to file: " << file_name;
}

}  // namespace remill
