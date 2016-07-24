/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_UTIL_H_
#define REMILL_BC_UTIL_H_

#include <string>
#include <unordered_map>

namespace llvm {
class BasicBlock;
class Function;
class GlobalVariable;
class Module;
class Value;
}  // namespace llvm
namespace remill {

using FunctionMap = std::unordered_map<std::string, llvm::Function *>;
using SymbolMap = std::unordered_map<std::string, llvm::GlobalVariable *>;

class BlockMap : public std::unordered_map<uintptr_t, llvm::Function *> {
 public:
  llvm::Function *&operator[](uintptr_t key);
  llvm::Function *operator[](uintptr_t key) const;
};

// Initialize the attributes for a lifted function.
void InitFunctionAttributes(llvm::Function *F);

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *source_func,
                            llvm::Function *dest_func);
void AddTerminatingTailCall(llvm::BasicBlock *source_block,
                            llvm::Function *dest_func);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *F, std::string name,
                               bool allow_failure=false);

// Find the machine state pointer. The machine state pointer is, by convention,
// passed as the first argument to every lifted function.
llvm::Value *LoadStatePointer(llvm::Function *function);
llvm::Value *LoadStatePointer(llvm::BasicBlock *block);

// Return the current program counter.
llvm::Value *LoadProgramCounter(llvm::BasicBlock *block);

// Return the pointer to the current value of the memory pointer.
llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block);

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *M, std::string name);

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(const llvm::Module *M,
                                        std::string name);

// Parses and loads a bitcode file into memory.
llvm::Module *LoadModuleFromFile(std::string file_name);

// Store an LLVM module into a file.
void StoreModuleToFile(llvm::Module *module, std::string file_name);

}  // namespace remill

#endif  // REMILL_BC_UTIL_H_
