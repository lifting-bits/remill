/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_UTIL_H_
#define REMILL_BC_UTIL_H_

#include <functional>
#include <string>

#include <llvm/Support/raw_ostream.h>

namespace llvm {
class Argument;
class BasicBlock;
class Function;
class GlobalObject;
class GlobalVariable;
class Module;
class Value;
class LLVMContext;
}  // namespace llvm

namespace remill {

// Initialize the attributes for a lifted function.
void InitFunctionAttributes(llvm::Function *F);

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *source_func,
                            llvm::Value *dest_func);

void AddTerminatingTailCall(llvm::BasicBlock *source_block,
                            llvm::Value *dest_func);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::BasicBlock *block,
                               std::string name,
                               bool allow_failure=false);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *func,
                               std::string name,
                               bool allow_failure=false);

// Find the machine state pointer. The machine state pointer is, by convention,
// passed as the first argument to every lifted function.
llvm::Value *LoadStatePointer(llvm::Function *function);
llvm::Value *LoadStatePointer(llvm::BasicBlock *block);

// Return the current program counter.
llvm::Value *LoadProgramCounter(llvm::BasicBlock *block);

// Return a reference to the current program counter.
llvm::Value *LoadProgramCounterRef(llvm::BasicBlock *block);

// Return the current memory pointer.
llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block);

// Return a reference to the memory pointer.
llvm::Value *LoadMemoryPointerRef(llvm::BasicBlock *block);

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *M, std::string name);

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(const llvm::Module *M,
                                        std::string name);

// Parses and loads a bitcode file into memory.
llvm::Module *LoadModuleFromFile(llvm::LLVMContext *context,
                                 std::string file_name);

// Store an LLVM module into a file.
void StoreModuleToFile(llvm::Module *module, std::string file_name);

// Find the path to the semantics bitcode file.
std::string FindSemanticsBitcodeFile(const std::string &path,
                                     const std::string &arch);

// Return a pointer to the Nth argument (N=0 is the first argument).
llvm::Argument *NthArgument(llvm::Function *func, size_t index);

// Convert an LLVM thing (e.g. `llvm::Value` or `llvm::Type`) into
// a `std::string`.
template <typename T>
inline static std::string LLVMThingToString(T *thing) {
  if (thing) {
    std::string str;
    llvm::raw_string_ostream str_stream(str);
    thing->print(str_stream);
    return str;
  } else {
    return "(null)";
  }
}

using BlockCallback = std::function<void(uint64_t, uint64_t, llvm::Function *)>;

// Run a callback function for every indirect block entry in a remill-lifted
// bitcode module.
void ForEachBlock(llvm::Module *module, BlockCallback callback);

// Clone function `source_func` into `dest_func`. This will strip out debug
// info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func);

// Try to get the address of a block.
bool TryGetBlockPC(llvm::GlobalObject *func, uint64_t &pc);

// Try to get the ID of this block. This may be the same as the block's PC.
bool TryGetBlockId(llvm::GlobalObject *func, uint64_t &id);

// Try to get the ID of this block. This may be the same as the block's PC.
bool TryGetBlockName(llvm::Function *func, std::string &name);

// Set the PC of a block.
void SetBlockPC(llvm::GlobalObject *func, uint64_t pc);

// Set the ID of a block.
void SetBlockId(llvm::GlobalObject *func, uint64_t id);

// Set the name of a block. This associates some high-level name, e.g. `malloc`
// with the metadata of some block function.
void SetBlockName(llvm::Function *func, const std::string &name);

// Make `func` a clone of the `__remill_basic_block` function.
void CloneBlockFunctionInto(llvm::Function *func);

}  // namespace remill

#endif  // REMILL_BC_UTIL_H_
