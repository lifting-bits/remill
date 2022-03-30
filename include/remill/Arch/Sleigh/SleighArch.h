/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
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

#include <remill/Arch/Arch.h>

#include <sleigh/libsleigh.hh>


// Unifies shared functionality between sleigh architectures

namespace remill::sleigh {

// NOTE(Ian): Ok so there is some horrible collaboration with the lifter. The lifter has to add metavars
// So the lifter is responsible for working out if a branch was taken
class InstructionFlowResolver {
 public:
  using IFRPtr = std::shared_ptr<InstructionFlowResolver>;

  virtual void ResolveControlFlow(uint64_t fall_through,
                                  remill::Instruction &insn) = 0;


  static IFRPtr CreateDirectCBranchResolver(uint64_t target);
  static IFRPtr CreateIndirectCall();
  static IFRPtr CreateIndirectRet();
  static IFRPtr CreateIndirectBranch();

  static IFRPtr CreateDirectBranch(uint64_t target);
  static IFRPtr CreateDirectCall(uint64_t target);

  static IFRPtr CreateNormal();
};


class NormalResolver : public InstructionFlowResolver {
 public:
  NormalResolver();
  virtual ~NormalResolver();

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};

// Direct Branch
class DirectBranchResolver : public InstructionFlowResolver {
 private:
  uint64_t target_address;

  // Can be a call or branch.
  remill::Instruction::Category category;

 public:
  DirectBranchResolver(uint64_t target_address,
                       remill::Instruction::Category category);
  virtual ~DirectBranchResolver();

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};

// Cbranch(NOTE): this may be normal if the cbranch target is the same as the fallthrough
class DirectCBranchResolver : public InstructionFlowResolver {
 private:
  uint64_t target_address;

 public:
  DirectCBranchResolver(uint64_t target_address);
  virtual ~DirectCBranchResolver();

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};


class IndirectBranch : public InstructionFlowResolver {
  // can be a return, callind, or branchind
  remill::Instruction::Category category;

 public:
  IndirectBranch(remill::Instruction::Category category);

  virtual ~IndirectBranch();

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};


class PcodeDecoder final : public PcodeEmit {
 public:
  PcodeDecoder(Sleigh &engine_, Instruction &inst_);

  void dump(const Address &, OpCode op, VarnodeData *outvar, VarnodeData *vars,
            int32_t isize) override;

  InstructionFlowResolver::IFRPtr GetResolver();

 private:
  void print_vardata(std::stringstream &s, VarnodeData &data);

  void DecodeOperand(VarnodeData &var);

  void DecodeRegister(const VarnodeData &var);

  void DecodeMemory(const VarnodeData &var);

  void DecodeConstant(const VarnodeData &var);

  void DecodeCategory(OpCode op, VarnodeData *vars, int32_t isize);

  Sleigh &engine;
  Instruction &inst;

  std::optional<InstructionFlowResolver::IFRPtr> current_resolver;
};

class CustomLoadImage final : public LoadImage {
 public:
  CustomLoadImage(void);

  void SetInstruction(uint64_t new_offset, std::string_view instr_bytes);

  void loadFill(unsigned char *ptr, int size, const Address &addr) override;
  std::string getArchType(void) const override;

  void adjustVma(long) override;


 private:
  std::string current_bytes;
  uint64_t current_offset;
};

// Holds onto contextual sleigh information in order to provide an interface with which you can decode single instructions
// Give me bytes and i give you pcode (maybe)
class SingleInstructionSleighContext {
 private:
  CustomLoadImage image;
  ContextInternal ctx;
  Sleigh engine;
  DocumentStorage storage;
  //NOTE(Ian): Who knows if this is enough? Need to figure out how much, if any of sleigh is thread safe
  static std::mutex sleigh_parsing_mutex;

 public:
  Address GetAddressFromOffset(uint64_t off);
  std::optional<int32_t> oneInstruction(uint64_t address, PcodeEmit &emitter,
                                        std::string_view instr_bytes);


  Sleigh &GetEngine();

  SingleInstructionSleighContext(std::string sla_name);
};

class SleighArch : public Arch {
 public:
  SleighArch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_,
             std::string sla_name);


 public:
  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst) const override;


  InstructionLifter::LifterPtr
  GetLifter(const remill::IntrinsicTable &intrinsics) const override;


  // Arch specific preperation
  virtual void
  InitializeSleighContext(SingleInstructionSleighContext &) const = 0;

  std::string GetSLAName() const;

 protected:
  bool DecodeInstructionImpl(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst);

  SingleInstructionSleighContext sleigh_ctx;
  std::string sla_name;
};
}  // namespace remill::sleigh