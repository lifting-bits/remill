/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef REMILL_BC_UTIL_H_
#define REMILL_BC_UTIL_H_

#include <functional>
#include <string>

#include <llvm/Support/raw_ostream.h>

namespace llvm {
class Argument;
class BasicBlock;
class CallInst;
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
llvm::CallInst *AddTerminatingTailCall(llvm::Function *source_func,
                                       llvm::Value *dest_func);

llvm::CallInst *AddTerminatingTailCall(llvm::BasicBlock *source_block,
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

// Return an `llvm::Value *` that is an `i1` (bool type) representing whether
// or not a conditional branch is taken.
llvm::Value *LoadBranchTaken(llvm::BasicBlock *block);

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(llvm::Module *M, std::string name);

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(llvm::Module *M, std::string name);

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

// Serialize an LLVM object into a string.
std::string LLVMThingToString(llvm::Value *thing);
std::string LLVMThingToString(llvm::Type *thing);

//// Apply a callback function to every semantics bitcode function.
//using SemCallback = std::function<void(llvm::Function *)>;
//void ForEachSem(llvm::Module *module, SemCallback callback);
//
//// Apply a callback function to every instruction selection function.
//using IselCallback = std::function<
//    void(const std::string &, llvm::GlobalVariable *, llvm::Function *)>;
//void ForEachIsel(llvm::Module *module, IselCallback callback);

// Declare a lifted function of the correct type.
llvm::Function *DeclareLiftedFunction(llvm::Module *module,
                                      const std::string &name);

// Clone function `source_func` into `dest_func`. This will strip out debug
// info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func);

// Make `func` a clone of the `__remill_basic_block` function.
void CloneBlockFunctionInto(llvm::Function *func);

}  // namespace remill

#endif  // REMILL_BC_UTIL_H_
