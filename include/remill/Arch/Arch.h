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

// clang-format off
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <remill/BC/Compat/CTypes.h>
#include <remill/BC/Compat/CallingConvention.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IRBuilder.h>
#pragma clang diagnostic pop

// clang-format on

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "Instruction.h"

struct ArchState;

namespace llvm {
class BasicBlock;
class Constant;
class Function;
class FunctionType;
class GetElementPtrInst;
class Instruction;
class IntegerType;
class LLVMContext;
class Module;
class PointerType;
}  // namespace llvm.
namespace remill {

enum OSName : uint32_t;
enum ArchName : uint32_t;

class Arch;
class ArchImpl;
class Instruction;

struct Register {
 public:
  Register(const std::string &name_, uint64_t offset_, uint64_t size_,
           llvm::Type *type_, const Register *parent_, const ArchImpl *arch_);

  std::string name;  // Name of the register.
  uint64_t offset;  // Byte offset in `State`.
  uint64_t size;  // Size of this register (in bytes).

  // LLVM type associated with the field in `State`.
  llvm::Type *type;

  // An LLVM constant that represents this register's name.
  llvm::Constant *constant_name;

  // A pre-computed index list and type for creating pointers to this register
  // given a `State` structure pointer.
  llvm::SmallVector<llvm::Value *, 8> gep_index_list;

  // The offset in `State` nearest to `offset`. You can say that
  // the `sizeof(gep_type_at_offset)` starting at `gep_offset` in the `State`
  // structure fully enclose this register. The following invariant holds:
  //
  //    gep_offset
  //        <= offset
  //            <= offset + sizeof(type)
  //                <= gep_offset + sizeof(gep_type_at_offset)
  size_t gep_offset{0};

  // This may be different than `type`. If so, then a bitcast on a
  // `getelementptr` produced using `gep_index_list` to a `type*` is needed.
  llvm::Type *gep_type_at_offset{nullptr};

  // Returns the enclosing register of size AT LEAST `size`, or `nullptr`.
  const Register *EnclosingRegisterOfSize(uint64_t size) const;

  // Returns the largest enclosing register containing the current register.
  const Register *EnclosingRegister(void) const;

  // Returns the list of directly enclosed registers. For example,
  // `RAX` will directly enclose `EAX` but nothing else. `AX` will directly
  // enclose `AH` and `AL`.
  const std::vector<const Register *> &EnclosedRegisters(void) const;

  // Generate a value that will let us load/store to this register, given
  // a `State *`.
  llvm::Value *AddressOf(llvm::Value *state_ptr,
                         llvm::BasicBlock *add_to_end) const;

  llvm::Value *AddressOf(llvm::Value *state_ptr, llvm::IRBuilder<> &ir) const;

 private:
  friend class Arch;

  const Register *const parent;
  const ArchImpl *const arch;

  // The directly enclosed registers.
  std::vector<const Register *> children;

  void CompteGEPAccessors(const llvm::DataLayout &dl, llvm::Type *state_type);
};

class Arch {
 public:
  using ArchPtr = std::unique_ptr<const Arch>;

  virtual ~Arch(void);

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static auto Get(llvm::LLVMContext &context, std::string_view os,
                  std::string_view arch_name) -> ArchPtr;

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static auto Get(llvm::LLVMContext &context, OSName os, ArchName arch_name)
      -> ArchPtr;

  // Return the type of the state structure.
  llvm::StructType *StateStructType(void) const;

  // Pointer to a state structure type.
  llvm::PointerType *StatePointerType(void) const;

  // Return the type of an address, i.e. `addr_t` in the semantics.
  llvm::IntegerType *AddressType(void) const;

  // The type of memory.
  llvm::PointerType *MemoryPointerType(void) const;

  // Return the type of a lifted function.
  llvm::FunctionType *LiftedFunctionType(void) const;

  // Apply `cb` to every register.
  void ForEachRegister(std::function<void(const Register *)> cb) const;

  // Return information about the register at offset `offset` in the `State`
  // structure.
  const Register *RegisterAtStateOffset(uint64_t offset) const;

  // Return information about a register, given its name.
  const Register *RegisterByName(std::string_view name) const;

  // Returns the name of the stack pointer register.
  virtual std::string_view StackPointerRegisterName(void) const = 0;

  // Returns the name of the program counter register.
  virtual std::string_view ProgramCounterRegisterName(void) const = 0;

  // Create a lifted function declaration with name `name` inside of `module`.
  //
  // NOTE(pag): This should be called after `PrepareModule` and after the
  //            semantics have been loaded.
  llvm::Function *DeclareLiftedFunction(std::string_view name,
                                        llvm::Module *module) const;

  // Create a lifted function with name `name` inside of `module`.
  //
  // NOTE(pag): This should be called after `PrepareModule` and after the
  //            semantics have been loaded.
  llvm::Function *DefineLiftedFunction(std::string_view name,
                                       llvm::Module *module) const;

  // Initialize an empty lifted function with the default variables that it
  // should contain.
  void InitializeEmptyLiftedFunction(llvm::Function *func) const;

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture and ensures remill required
  // functions have the appropriate prototype and internal variables
  void PrepareModule(llvm::Module *mod) const;

  // Get the state pointer and various other types from the `llvm::LLVMContext`
  // associated with `module`.
  //
  // NOTE(pag): This is an internal API.
  void InitFromSemanticsModule(llvm::Module *module) const;

  inline void PrepareModule(const std::unique_ptr<llvm::Module> &mod) const {
    PrepareModule(mod.get());
  }

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture
  void PrepareModuleDataLayout(llvm::Module *mod) const;

  inline void
  PrepareModuleDataLayout(const std::unique_ptr<llvm::Module> &mod) const {
    PrepareModuleDataLayout(mod.get());
  }

  // Decode an instruction.
  //
  // NOTE(pag): If you give `DecodeInstruction` a bunch of bytes, then it will
  //            opportunistically look for opportunities to recognize some
  //            simple idioms and fuse them (e.g. `call; pop` on x86,
  //            `sethi; or` on sparc). If you don't want to decode idioms, then
  //            one usage pattern to avoid them is to start with
  //            `MinInstructionSize()` bytes, and if that fails to decode, then
  //            walk up, one byte at a time, to `MaxInstructionSize(false)`
  //            bytes being passed to the decoder, until you successfully decode
  //            or ultimately fail.
  virtual bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                                 Instruction &inst) const = 0;

  // Decode an instruction that is within a delay slot.
  bool DecodeDelayedInstruction(uint64_t address, std::string_view instr_bytes,
                                Instruction &inst) const {
    inst.in_delay_slot = true;
    return this->DecodeInstruction(address, instr_bytes, inst);
  }

  // Minimum alignment of an instruction for this particular architecture.
  virtual uint64_t MinInstructionAlign(void) const = 0;

  // Minimum number of bytes in an instruction for this particular architecture.
  virtual uint64_t MinInstructionSize(void) const = 0;

  // Maximum number of bytes in an instruction for this particular architecture.
  //
  // `permit_fuse_idioms` is `true` if Remill is allowed to decode multiple
  // instructions at a time and look for instruction fusing idioms that are
  // common to this architecture.
  virtual uint64_t MaxInstructionSize(bool permit_fuse_idioms=true) const = 0;

  // Default calling convention for this architecture.
  virtual llvm::CallingConv::ID DefaultCallingConv(void) const = 0;

  // Get the LLVM triple for this architecture.
  virtual llvm::Triple Triple(void) const = 0;

  // Get the LLVM DataLayout for this architecture.
  virtual llvm::DataLayout DataLayout(void) const = 0;

  // Returns `true` if memory access are little endian byte ordered.
  virtual bool MemoryAccessIsLittleEndian(void) const;

  // Returns `true` if a given instruction might have a delay slot.
  virtual bool MayHaveDelaySlot(const Instruction &inst) const;

  // Returns `true` if we should lift the semantics of `next_inst` as a delay
  // slot of `inst`. The `branch_taken_path` tells us whether we are in the
  // context of the taken path of a branch or the not-taken path of a branch.
  virtual bool NextInstructionIsDelayed(const Instruction &inst,
                                        const Instruction &next_inst,
                                        bool branch_taken_path) const;

  // Get the architecture related to a module.
  static remill::Arch::ArchPtr GetModuleArch(const llvm::Module &module);

  const OSName os_name;
  const ArchName arch_name;

  // Number of bits in an address.
  const unsigned address_size;

  // Constant pointer to non-const object
  llvm::LLVMContext *const context;

  bool IsX86(void) const;
  bool IsAMD64(void) const;
  bool IsAArch32(void) const;
  bool IsAArch64(void) const;
  bool IsSPARC32(void) const;
  bool IsSPARC64(void) const;

  bool IsWindows(void) const;
  bool IsLinux(void) const;
  bool IsMacOS(void) const;
  bool IsSolaris(void) const;

  // Avoids global cache
  static ArchPtr Build(llvm::LLVMContext *context, OSName os,
                       ArchName arch_name);

  // Get the (approximate) architecture of the system library was built on. This may not
  // include all feature sets.
  static ArchPtr GetHostArch(llvm::LLVMContext &contex);

 protected:
  Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  // Populate the table of register information.
  virtual void PopulateRegisterTable(void) const = 0;

  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  virtual void FinishLiftedFunctionInitialization(
      llvm::Module *module, llvm::Function *bb_func) const = 0;

  llvm::Triple BasicTriple(void) const;

  // Add a register into this
  const Register *AddRegister(const char *reg_name, llvm::Type *val_type,
                              size_t offset, const char *parent_reg_name) const;

 private:
  // Defined in `lib/Arch/X86/Arch.cpp`.
  static ArchPtr GetX86(llvm::LLVMContext *context, OSName os,
                        ArchName arch_name);

  // Defined in `lib/Arch/AArch32/Arch.cpp`.
  static ArchPtr GetAArch32(llvm::LLVMContext *context, OSName os,
                            ArchName arch_name);

  // Defined in `lib/Arch/AArch64/Arch.cpp`.
  static ArchPtr GetAArch64(llvm::LLVMContext *context, OSName os,
                            ArchName arch_name);

  // Defined in `lib/Arch/SleighX86/Arch.cpp`
  static ArchPtr GetSleighX86(llvm::LLVMContext *context, OSName os,
                              ArchName arch_name);

  // Defined in `lib/Arch/SPARC32/Arch.cpp`.
  static ArchPtr GetSPARC(llvm::LLVMContext *context, OSName os,
                          ArchName arch_name);

  // Defined in `lib/Arch/SPARC64/Arch.cpp`.
  static ArchPtr GetSPARC64(llvm::LLVMContext *context, OSName os,
                            ArchName arch_name);

  Arch(void) = delete;

 protected:
  mutable std::unique_ptr<ArchImpl> impl;
};

}  // namespace remill
