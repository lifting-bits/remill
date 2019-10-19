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

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

namespace llvm {
class Argument;
class Function;
class Module;
class GlobalVariable;
class LLVMContext;
class IntegerType;
class BasicBlock;
class Value;
}  // namespace llvm

namespace remill {

class Arch;
class Instruction;
class IntrinsicTable;
class Operand;

enum LiftStatus {
  kLiftedInvalidInstruction,
  kLiftedUnsupportedInstruction,
  kLiftedInstruction
};

// Wraps the process of lifting an instruction into a block. This resolves
// the intended instruction target to a function, and ensures that the function
// is called with the appropriate arguments.
class InstructionLifter {
 public:
  virtual ~InstructionLifter(void);

  inline InstructionLifter(const Arch *arch_,
                           const IntrinsicTable &intrinsics_)
      : InstructionLifter(arch_, &intrinsics_) {}

  InstructionLifter(const Arch *arch_,
                    const IntrinsicTable *intrinsics_);

  // Lift a single instruction into a basic block.
  virtual LiftStatus LiftIntoBlock(
      Instruction &inst, llvm::BasicBlock *block);

  const Arch * const arch;

  // Machine word type for this architecture.
  llvm::IntegerType * const word_type;

  // Set of intrinsics.
  const IntrinsicTable * const intrinsics;

 protected:
  // Lift an operand to an instruction.
  virtual llvm::Value *LiftOperand(Instruction &inst,
                                   llvm::BasicBlock *block,
                                   llvm::Argument *arg,
                                   Operand &op);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftShiftRegisterOperand(Instruction &inst,
                                                llvm::BasicBlock *block,
                                                llvm::Argument *arg,
                                                Operand &reg);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftRegisterOperand(Instruction &inst,
                                           llvm::BasicBlock *block,
                                           llvm::Argument *arg,
                                           Operand &reg);

  // Lift an immediate operand.
  virtual llvm::Value *LiftImmediateOperand(Instruction &inst,
                                            llvm::BasicBlock *block,
                                            llvm::Argument *arg,
                                            Operand &op);

  // Lift an indirect memory operand to a value.
  virtual llvm::Value *LiftAddressOperand(Instruction &inst,
                                          llvm::BasicBlock *block,
                                          llvm::Argument *arg,
                                          Operand &mem);

 private:
  InstructionLifter(void) = delete;
};

using TraceMap = std::unordered_map<uint64_t, llvm::Function *>;

enum class DevirtualizedTargetKind {
  kTraceLocal,
  kTraceHead
};

// Manages information about traces. Permits a user of the trace lifter to
// provide more global information to the decoder as it goes, e.g. by pre-
// declaring the existence of many traces, and by supporting devirtualization.
class TraceManager {
 public:
  virtual ~TraceManager(void);

  // Figure out the name for the trace starting at address `addr`.
  //
  // By default, the naming scheme is `sub_XXX` where `XXX` is the lower case
  // hexadecimal representation of `addr`.
  virtual std::string TraceName(uint64_t addr);

  // Called when we have lifted, i.e. defined the contents, of a new trace.
  // The derived class is expected to do something useful with this.
  virtual void SetLiftedTraceDefinition(
      uint64_t addr, llvm::Function *lifted_func) = 0;

  // Get a declaration for a lifted trace. The idea here is that a derived
  // class might have additional global info available to them that lets
  // them declare traces ahead of time. In order to distinguish between
  // stuff we've lifted, and stuff we haven't lifted, we allow the lifter
  // to access "defined" vs. "declared" traces.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  //
  // NOTE: This must return a function with our special 3-argument
  //       lifted function form.
  virtual llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);

  // Get a definition for a lifted trace.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  //
  // NOTE: This is permitted to return a function of an arbitrary
  //       type. The trace lifter only invokes this function when
  //       it is checking if some trace has already been lifted.
  virtual llvm::Function *GetLiftedTraceDefinition(uint64_t addr);

  // Apply a callback that gives the decoder access to multiple
  // targets of this instruction (indirect call or jump). This enables the
  // lifter to support devirtualization, e.g. handling jump tables as
  // `switch` statements, or handling indirect calls through the PLT as
  // direct jumps.
  virtual void ForEachDevirtualizedTarget(
      const Instruction &inst,
      std::function<void(uint64_t, DevirtualizedTargetKind)> func);

  // Try to read an executable byte of memory. Returns `true` of the byte
  // at address `addr` is executable and readable, and updates the byte
  // pointed to by `byte` with the read value.
  virtual bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) = 0;
};

// Implements a recursive decoder that lifts a trace of instructions to bitcode.
class TraceLifter {
 public:
  inline TraceLifter(InstructionLifter &inst_lifter_,
                     TraceManager &manager_)
      : TraceLifter(&inst_lifter_, &manager_) {}

  TraceLifter(InstructionLifter *inst_lifter_,
              TraceManager *manager_);

  static void NullCallback(uint64_t, llvm::Function *);

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(
      uint64_t addr,
      std::function<void(uint64_t,llvm::Function *)> callback=NullCallback);

 private:
  TraceLifter(void) = delete;

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr);

  const Arch * const arch;
  InstructionLifter &inst_lifter;
  const remill::IntrinsicTable *intrinsics;
  llvm::LLVMContext &context;
  llvm::Module * const module;
  const uint64_t addr_mask;
  TraceManager &manager;
};

}  // namespace remill
