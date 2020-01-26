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

#pragma once

#include <functional>
#include <string>
#include <memory>
#include <unordered_map>
#include <vector>

namespace llvm {
class Argument;
class BasicBlock;
class CallInst;
class Function;
class FunctionType;
class GlobalObject;
class GlobalVariable;
class IntegerType;
class Module;
class PointerType;
class Type;
class Value;
class LLVMContext;
}  // namespace llvm

namespace remill {

class Arch;
class IntrinsicTable;

// Initialize the attributes for a lifted function.
void InitFunctionAttributes(llvm::Function *F);

// Create a call from one lifted function to another.
llvm::CallInst *AddCall(llvm::BasicBlock *source_block,
                        llvm::Value *dest_func);

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

// Update the program counter in the state struct with a hard-coded value.
void StoreProgramCounter(llvm::BasicBlock *block, uint64_t pc);

// Update the program counter in the state struct with a new value.
void StoreProgramCounter(llvm::BasicBlock *block, llvm::Value *pc);

// Return the memory pointer argument.
llvm::Value *LoadMemoryPointerArg(llvm::Function *func);

// Return the program counter argument.
llvm::Value *LoadProgramCounterArg(llvm::Function *function);

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

// Try to verify a module.
bool VerifyModule(llvm::Module *module);

// Parses and loads a bitcode file into memory.
std::unique_ptr<llvm::Module> LoadModuleFromFile(llvm::LLVMContext *context,
                                                 std::string file_name,
                                                 bool allow_failure=false);

// Loads the semantics for the "host" machine, i.e. the machine that this
// remill is compiled on.
std::unique_ptr<llvm::Module> LoadHostSemantics(llvm::LLVMContext &context);

// Loads the semantics for the "target" machine, i.e. the machine of the
// code that we want to lift.
std::unique_ptr<llvm::Module> LoadTargetSemantics(llvm::LLVMContext &context);

// Loads the semantics for the `arch`-specific machine, i.e. the machine of the
// code that we want to lift.
std::unique_ptr<llvm::Module> LoadArchSemantics(const Arch *arch);

// Store an LLVM module into a file.
bool StoreModuleToFile(llvm::Module *module, std::string file_name,
                       bool allow_failure=false);

// Store a module, serialized to LLVM IR, into a file.
bool StoreModuleIRToFile(llvm::Module *module, std::string file_name,
                         bool allow_failure=false);

// Find a semantics fitcode file for the architecture `arch`.
std::string FindSemanticsBitcodeFile(const std::string &arch);

// Return a pointer to the Nth argument (N=0 is the first argument).
llvm::Argument *NthArgument(llvm::Function *func, size_t index);

// Returns a pointer to the `__remill_basic_block` function.
llvm::Function *BasicBlockFunction(llvm::Module *module);

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(llvm::Module *module);

// Return a vector of arguments to pass to a lifted function, where the
// arguments are derived from `block`.
std::vector<llvm::Value *> LiftedFunctionArgs(llvm::BasicBlock *block);

// Serialize an LLVM object into a string.
std::string LLVMThingToString(llvm::Value *thing);
std::string LLVMThingToString(llvm::Type *thing);

// Apply a callback function to every semantics bitcode function.
using ISelCallback = std::function<
    void(llvm::GlobalVariable *, llvm::Function *)>;
void ForEachISel(llvm::Module *module, ISelCallback callback);

// Declare a lifted function of the correct type.
llvm::Function *DeclareLiftedFunction(llvm::Module *module,
                                      const std::string &name);

// Returns the type of a state pointer.
llvm::PointerType *StatePointerType(llvm::Module *module);

// Returns the type of a state pointer.
llvm::PointerType *MemoryPointerType(llvm::Module *module);

// Returns the type of an address (addr_t in the State.h).
llvm::IntegerType *AddressType(llvm::Module *module);

using ValueMap = std::unordered_map<llvm::Value *, llvm::Value *>;

// Clone function `source_func` into `dest_func`, using `value_map` to map over
// values. This will strip out debug info during the clone. This will strip out
// debug info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func,
                       llvm::Function *dest_func,
                       ValueMap &value_map);

// Clone function `source_func` into `dest_func`. This will strip out debug
// info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func);

// Make `func` a clone of the `__remill_basic_block` function.
void CloneBlockFunctionInto(llvm::Function *func);

// Returns a list of callers of a specific function.
std::vector<llvm::CallInst *> CallersOf(llvm::Function *func);

// Returns the name of a module.
std::string ModuleName(llvm::Module *module);
std::string ModuleName(const std::unique_ptr<llvm::Module> &module);

// Move a function from one module into another module.
void MoveFunctionIntoModule(llvm::Function *func, llvm::Module *dest_module);

// Get an instance of `type` that belongs to `context`.
llvm::Type *RecontextualizeType(llvm::Type *type, llvm::LLVMContext &context);

// Produce a sequence of instructions that will load values from
// memory, building up the correct type. This will invoke the various
// memory read intrinsics in order to match the right type, or
// recursively build up the right type.
//
// Returns the loaded value.
llvm::Value *LoadFromMemory(
    const IntrinsicTable &intrinsics,
    llvm::BasicBlock *block,
    llvm::Type *type,
    llvm::Value *mem_ptr,
    llvm::Value *addr);

// Produce a sequence of instructions that will store a value to
// memory. This will invoke the various memory write intrinsics
// in order to match the right type, or recursively destructure
// the type into components which can be written to memory.
//
// Returns the new value of the memory pointer.
llvm::Value *StoreToMemory(
    const IntrinsicTable &intrinsics,
    llvm::BasicBlock *block,
    llvm::Value *val_to_store,
    llvm::Value *mem_ptr,
    llvm::Value *addr);

}  // namespace remill
