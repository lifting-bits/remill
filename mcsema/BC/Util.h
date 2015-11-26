/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_BC_UTIL_H_
#define MCSEMA_BC_UTIL_H_

#include <unordered_map>

namespace llvm {
class Function;
class GlobalVariable;
}  // namespace llvm
namespace mcsema {

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
void AddTerminatingTailCall(llvm::Function *From, llvm::Function *To);
void AddTerminatingTailCall(llvm::BasicBlock *From, llvm::Function *To);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *F, std::string name);

// Find the machine state pointer. The machine state pointer is, by convention,
// passed as the first argument to every lifted function.
llvm::Value *FindStatePointer(llvm::Function *F);

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *M, const char *name);

}  // namespace mcsema

#endif  // MCSEMA_BC_UTIL_H_
