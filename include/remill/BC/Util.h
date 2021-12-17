/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

// clang-format off
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <remill/BC/Compat/CTypes.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>
#pragma clang diagnostic pop

// clang-format on

#include <array>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <remill/BC/ABI.h>

namespace llvm {
class Argument;
class BasicBlock;
class CallInst;
class Constant;
class Function;
class FunctionType;
class GlobalObject;
class GlobalVariable;
class IntegerType;
class Metadata;
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
llvm::CallInst *AddCall(llvm::BasicBlock *source_block, llvm::Value *dest_func);

// Create a tail-call from one lifted function to another.
llvm::CallInst *AddTerminatingTailCall(llvm::Function *source_func,
                                       llvm::Value *dest_func);

llvm::CallInst *AddTerminatingTailCall(llvm::BasicBlock *source_block,
                                       llvm::Value *dest_func);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::BasicBlock *block, std::string_view name,
                               bool allow_failure = false);

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *func, std::string_view name,
                               bool allow_failure = false);

// Find the machine state pointer. The machine state pointer is, by convention,
// passed as the first argument to every lifted function.
llvm::Value *LoadStatePointer(llvm::Function *function);
llvm::Value *LoadStatePointer(llvm::BasicBlock *block);

// Return the current program counter.
llvm::Value *LoadProgramCounter(llvm::BasicBlock *block);

// Return the next program counter.
llvm::Value *LoadNextProgramCounter(llvm::BasicBlock *block);

// Return a reference to the current program counter.
llvm::Value *LoadProgramCounterRef(llvm::BasicBlock *block);

// Return a reference to the next program counter.
llvm::Value *LoadNextProgramCounterRef(llvm::BasicBlock *block);

// Return a reference to the return program counter.
llvm::Value *LoadReturnProgramCounterRef(llvm::BasicBlock *block);

// Update the program counter in the state struct with a hard-coded value.
void StoreProgramCounter(llvm::BasicBlock *block, uint64_t pc);

// Update the program counter in the state struct with a new value.
void StoreProgramCounter(llvm::BasicBlock *block, llvm::Value *pc);

// Update the next program counter in the state struct with a new value.
void StoreNextProgramCounter(llvm::BasicBlock *block, llvm::Value *pc);

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

llvm::Value *LoadBranchTakenRef(llvm::BasicBlock *block);

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(llvm::Module *M, std::string_view name);

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(llvm::Module *M, std::string_view name);

// Try to verify a module.
bool VerifyModule(llvm::Module *module);

// Parses and loads a bitcode file into memory.
std::unique_ptr<llvm::Module> LoadModuleFromFile(llvm::LLVMContext *context,
                                                 std::string_view file_name,
                                                 bool allow_failure = false);

// Loads the semantics for the `arch`-specific machine, i.e. the machine of the
// code that we want to lift.
std::unique_ptr<llvm::Module> LoadArchSemantics(const Arch *arch);

inline std::unique_ptr<llvm::Module>
LoadArchSemantics(const std::unique_ptr<const Arch> &arch) {
  return LoadArchSemantics(arch.get());
}

// Store an LLVM module into a file.
bool StoreModuleToFile(llvm::Module *module, std::string_view file_name,
                       bool allow_failure = false);

// Store a module, serialized to LLVM IR, into a file.
bool StoreModuleIRToFile(llvm::Module *module, std::string_view file_name,
                         bool allow_failure = false);

// Find the path to the semantics bitcode file associated with `FLAGS_arch`.
std::string FindTargetSemanticsBitcodeFile(void) __attribute__((deprecated));

// Find the path to the semantics bitcode file associated with `REMILL_ARCH`,
// the architecture on which remill is compiled.
std::string FindHostSemanticsBitcodeFile(void) __attribute__((deprecated));

// Find a semantics bitcode file for the architecture `arch`.
std::string FindSemanticsBitcodeFile(std::string_view arch);

// Return a pointer to the Nth argument (N=0 is the first argument).
llvm::Argument *NthArgument(llvm::Function *func, size_t index);

// Return a vector of arguments to pass to a lifted function, where the
// arguments are derived from `block`.
std::array<llvm::Value *, kNumBlockArgs>
LiftedFunctionArgs(llvm::BasicBlock *block);

// Serialize an LLVM object into a string.
std::string LLVMThingToString(llvm::Value *thing);
std::string LLVMThingToString(llvm::Type *thing);

// Apply a callback function to every semantics bitcode function.
using ISelCallback =
    std::function<void(llvm::GlobalVariable *, llvm::Function *)>;
void ForEachISel(llvm::Module *module, ISelCallback callback);

using ValueMap = std::unordered_map<llvm::Value *, llvm::Value *>;
using TypeMap = std::unordered_map<llvm::Type *, llvm::Type *>;
using MDMap = std::unordered_map<llvm::Metadata *, llvm::Metadata *>;

// Clone function `source_func` into `dest_func`, using `value_map` to map over
// values. This will strip out debug info during the clone. This will strip out
// debug info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func,
                       ValueMap &value_map, TypeMap &type_map, MDMap &md_map);

// Clone function `source_func` into `dest_func`. This will strip out debug
// info during the clone.
//
// Note: this will try to clone globals referenced from the module of
//       `source_func` into the module of `dest_func`.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func);

// Returns a list of callers of a specific function.
std::vector<llvm::CallInst *> CallersOf(llvm::Function *func);

// Returns the name of a module.
std::string ModuleName(llvm::Module *module);
std::string ModuleName(const std::unique_ptr<llvm::Module> &module);

// Replace all uses of a constant `old_c` with `new_c` inside of `module`.
//
// Returns the number of constant uses of `old_c`.
unsigned ReplaceAllUsesOfConstant(llvm::Constant *old_c, llvm::Constant *new_c,
                                  llvm::Module *module);

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
llvm::Value *LoadFromMemory(const IntrinsicTable &intrinsics,
                            llvm::BasicBlock *block, llvm::Type *type,
                            llvm::Value *mem_ptr, llvm::Value *addr);

// Produce a sequence of instructions that will store a value to
// memory. This will invoke the various memory write intrinsics
// in order to match the right type, or recursively destructure
// the type into components which can be written to memory.
//
// Returns the new value of the memory pointer.
llvm::Value *StoreToMemory(const IntrinsicTable &intrinsics,
                           llvm::BasicBlock *block, llvm::Value *val_to_store,
                           llvm::Value *mem_ptr, llvm::Value *addr);

// Create an array of index values to pass to a GetElementPtr instruction
// that will let us locate a particular register. Returns the final offset
// into `type` which was reached as the first value in the pair, and the type
// of what is at that offset in the second value of the pair.
std::pair<size_t, llvm::Type *>
BuildIndexes(const llvm::DataLayout &dl, llvm::Type *type, size_t offset,
             const size_t goal_offset,
             llvm::SmallVectorImpl<llvm::Value *> &indexes_out);

// Given a pointer, `ptr`, and a goal byte offset to which we'd like to index,
// build either a constant expression or sequence of instructions that can
// index to that offset. `ir` is provided to support the instruction case
// and to give access to a module for data layouts.
llvm::Value *BuildPointerToOffset(llvm::IRBuilder<> &ir, llvm::Value *ptr,
                                  size_t dest_elem_offset,
                                  llvm::Type *dest_ptr_type);

// Compute the total offset of a GEP chain.
std::pair<llvm::Value *, int64_t>
StripAndAccumulateConstantOffsets(const llvm::DataLayout &dl,
                                  llvm::Value *base);

}  // namespace remill
