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

#ifndef REMILL_ARCH_ARCH_H_
#define REMILL_ARCH_ARCH_H_

#include <string>

struct ArchState;

namespace llvm {
class Module;
class BasicBlock;
class Function;
}  // namespace llvm.
namespace remill {

enum OSName : uint32_t;
enum ArchName : uint32_t;

class Instruction;

class Arch {
 public:
  virtual ~Arch(void);

  // Factory method for loading the correct architecture class for a given
  // operating system and architecture class.
  static const Arch *Get(OSName os, ArchName arch_name);

  // Converts an LLVM module object to have the right triple / data layout
  // information for the target architecture.
  virtual void PrepareModule(llvm::Module *mod) const = 0;

  // Decode an instruction.
  virtual Instruction *DecodeInstruction(
      uint64_t address,
      const std::string &instr_bytes) const = 0;

  virtual uint64_t ProgramCounter(const ArchState *state) const = 0;

  // Number of bits in an address.
  const OSName os_name;
  const ArchName arch_name;
  const uint64_t address_size;

 protected:
  Arch(OSName os_name_, ArchName arch_name_);

 private:

  // Defined in `remill/Arch/X86/Arch.cpp`.
  static const Arch *GetX86(OSName os, ArchName arch_name);

  Arch(void) = delete;
};

const Arch *GetGlobalArch(void);

}  // namespace remill

#endif  // REMILL_ARCH_ARCH_H_
