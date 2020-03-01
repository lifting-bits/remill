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

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Module.h>

#include "remill/BC/Compat/CallingConvention.h"

struct ArchState;

namespace llvm {
class LLVMContext;
class Module;
class BasicBlock;
class Function;
class GetElementPtrInst;
class Instruction;
}  // namespace llvm.
namespace remill {

enum OSName : uint32_t;
enum ArchName : uint32_t;

class Arch;
class Instruction;

struct Register {
 public:
  Register(const std::string &name_, uint64_t offset_, uint64_t size_,
           uint64_t order_, llvm::Type *type_);

  std::string name;  // Name of the register.
  uint64_t offset;  // Byte offset in `State`.
  uint64_t size;  // Size of this register.

  // How many indexes/casts it takes to get at this register withing the
  // original bitcode of `__remill_basic_block`. This is a useful metric
  // when trying to decide is something is a sub-register of another. For
  // example, `Q0` is a sub register of `V0` on AArch64, even though they
  // are the same size. The complexity allows us to see that it "takes more"
  // to index into `Q0` than it does for `V0`, and thus `Q0` is a sub-register.
  unsigned complexity;

  // LLVM type associated with the field in `State`.
  llvm::Type *type;

  // A pre-computed index list and type for creating pointers to this register
  // given a `State` structure pointer.
  std::vector<llvm::Value *> gep_index_list;

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

  // Generate an instruction that will let us load/store to this register, given
  // a `State *`.
  llvm::Instruction *AddressOf(
      llvm::Value *state_ptr, llvm::BasicBlock *add_to_end) const;

 private:
  friend class Arch;

  const Register * parent{nullptr};

  // The directly enclosed registers.
  std::vector<const Register *> children;
};

class Arch {
 public:
  using ArchPtr = std::unique_ptr<const Arch>;

  virtual ~Arch(void);

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static const Arch *Get(llvm::LLVMContext &context, OSName os, ArchName arch_name);

  // Return information about the register at offset `offset` in the `State`
  // structure.
  const Register *RegisterAtStateOffset(uint64_t offset) const;

  // Return information about a register, given its name.
  const Register *RegisterByName(const std::string &name) const;

  // Returns the name of the stack pointer register.
  virtual const char *StackPointerRegisterName(void) const = 0;

  // Returns the name of the program counter register.
  virtual const char *ProgramCounterRegisterName(void) const = 0;

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture and ensures remill requied functions
  // have the appropriate prototype and internal variables
  void PrepareModule(llvm::Module *mod) const;

  inline void PrepareModule(const std::unique_ptr<llvm::Module> &mod) const {
    PrepareModule(mod.get());
  }

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture
  void PrepareModuleDataLayout(llvm::Module *mod) const;

  inline void PrepareModuleDataLayout(
      const std::unique_ptr<llvm::Module> &mod) const {
    PrepareModuleDataLayout(mod.get());
  }

  // Decode an instruction.
  virtual bool DecodeInstruction(
      uint64_t address, const std::string &instr_bytes,
      Instruction &inst) const = 0;

  // Fully decode any control-flow transfer instructions, but only partially
  // decode other instructions.
  virtual bool LazyDecodeInstruction(
      uint64_t address, const std::string &instr_bytes,
      Instruction &inst) const;

  // Maximum number of bytes in an instruction for this particular architecture.
  virtual uint64_t MaxInstructionSize(void) const = 0;

  // Default calling convention for this architecture.
  virtual llvm::CallingConv::ID DefaultCallingConv(void) const = 0;

  // Get the LLVM triple for this architecture.
  virtual llvm::Triple Triple(void) const = 0;

  // Get the LLVM DataLayout for this architecture.
  virtual llvm::DataLayout DataLayout(void) const = 0;

  // Get the architecture related to a module.
  static remill::Arch::ArchPtr GetModuleArch(const llvm::Module &module);

  // Number of bits in an address.
  const OSName os_name;
  const ArchName arch_name;
  const uint64_t address_size;

  // Constant pointer to non-const object
  llvm::LLVMContext * const context;

  bool IsX86(void) const;
  bool IsAMD64(void) const;
  bool IsAArch64(void) const;

  bool IsWindows(void) const;
  bool IsLinux(void) const;
  bool IsMacOS(void) const;

  // Avoids global cache
  static ArchPtr Build(llvm::LLVMContext *context, OSName os, ArchName arch_name);

  // Get the architecture of the modelled code. This is based on command-line
  // flags. Rather use directly Build.
  static ArchPtr GetTargetArch(llvm::LLVMContext &context);

  // Get the (approximate) architecture of the system library was built on. This may not
  // include all feature sets.
  static ArchPtr GetHostArch(llvm::LLVMContext &contex);

 protected:
  Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  llvm::Triple BasicTriple(void) const;

 private:
  // Defined in `remill/Arch/X86/Arch.cpp`.
  static ArchPtr GetX86(
      llvm::LLVMContext *context, OSName os, ArchName arch_name);

  // Defined in `remill/Arch/AArch64/Arch.cpp`.
  static ArchPtr GetAArch64(
      llvm::LLVMContext *context, OSName os, ArchName arch_name);

  // Get all of the register information from the prepared module.
  void CollectRegisters(llvm::Module *module) const;

  mutable std::vector<Register> registers;
  mutable std::vector<const Register *> reg_by_offset;
  mutable std::unordered_map<std::string, const Register *> reg_by_name;

  Arch(void) = delete;
};

/* Deprecated, do not use, prefer Arch::Build */

const Arch *GetHostArch(llvm::LLVMContext &context);
const Arch *GetTargetArch(llvm::LLVMContext &context);

// In case it already exists with different os and arch it is still returned!
const Arch *GetOrCreate(llvm::LLVMContext &context, OSName os, ArchName name);

// Double deprecated, leaks memory
const Arch *GetTargetArch();

}  // namespace remill
