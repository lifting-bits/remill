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

#include <remill/Arch/ArchBase.h>
#include <remill/BC/SleighLifter.h>

#include <sleigh/libsleigh.hh>
#include <unordered_set>

// Unifies shared functionality between sleigh architectures

namespace remill::sleigh {

// NOTE(Ian): Ok so there is some horrible collaboration with the lifter.
// The lifter has to add metavars. So the lifter is responsible for working
// out if a branch was taken
class InstructionFlowResolver {
 public:
  virtual ~InstructionFlowResolver(void) = default;

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
  NormalResolver() = default;
  virtual ~NormalResolver() = default;

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
  virtual ~DirectBranchResolver() = default;

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};

// Cbranch(NOTE): this may be normal if the cbranch target is the same as the fallthrough
class DirectCBranchResolver : public InstructionFlowResolver {
 private:
  uint64_t target_address;

 public:
  DirectCBranchResolver(uint64_t target_address);
  virtual ~DirectCBranchResolver() = default;

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};


class IndirectBranch : public InstructionFlowResolver {
  // can be a return, callind, or branchind
  remill::Instruction::Category category;

 public:
  IndirectBranch(remill::Instruction::Category category);

  virtual ~IndirectBranch() = default;

  void ResolveControlFlow(uint64_t fall_through,
                          remill::Instruction &insn) override;
};

class PcodeDecoder final : public PcodeEmit {
 public:
  PcodeDecoder(::Sleigh &engine_, Instruction &inst_);

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

  static std::optional<InstructionFlowResolver::IFRPtr>
  GetFlowResolverForOp(OpCode op, VarnodeData *vars, int32_t isize);

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
  uint64_t current_offset{0};
};

// Holds onto contextual sleigh information in order to provide an interface with which you can decode single instructions
// Give me bytes and i give you pcode (maybe)
class SingleInstructionSleighContext {
 private:
  CustomLoadImage image;
  ContextInternal ctx;
  ::Sleigh engine;
  DocumentStorage storage;

  std::optional<int32_t>
  oneInstruction(uint64_t address,
                 const std::function<int32_t(Address addr)> &decode_func,
                 std::string_view instr_bytes);

  void restoreEngineFromStorage();

 public:
  Address GetAddressFromOffset(uint64_t off);
  std::optional<int32_t> oneInstruction(uint64_t address, PcodeEmit &emitter,
                                        std::string_view instr_bytes);

  std::optional<int32_t> oneInstruction(uint64_t address, AssemblyEmit &emitter,
                                        std::string_view instr_bytes);

  ::Sleigh &GetEngine(void);

  ContextDatabase &GetContext(void);

  void resetContext();

  SingleInstructionSleighContext(std::string sla_name, std::string pspec_name);


  // Builds sleigh decompiler arch. Allows access to useropmanager and other internal sleigh info mantained by the arch.
  std::vector<std::string> getUserOpNames();
};


class ContextUpdater : public PcodeEmit {
 private:
  DecodingContext curr_context;
  const std::unordered_map<std::string, std::string> &register_mapping;
  Sleigh &engine;
  std::unordered_set<std::string> already_assigned;

 public:
  ContextUpdater(
      DecodingContext curr_context,
      const std::unordered_map<std::string, std::string> &register_mapping,
      Sleigh &engine_);

  virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
                    VarnodeData *vars, int4 isize) override;

  DecodingContext GetContext() const;
};

class SleighDecoder {
 public:
  SleighDecoder() = delete;
  SleighDecoder(const remill::Arch &arch, std::string sla_name,
                std::string pspec_name,
                std::unordered_map<std::string, std::string> register_mapping);
  std::string GetSLAName() const;

  std::string GetPSpec() const;
  // Decoder specific prep
  virtual void
  InitializeSleighContext(SingleInstructionSleighContext &) const = 0;


  Arch::DecodingResult
  DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                    Instruction &inst, DecodingContext context) const;


  std::shared_ptr<remill::SleighLifter> GetLifter() const;

 protected:
  Arch::DecodingResult
  DecodeInstructionImpl(uint64_t address, std::string_view instr_bytes,
                        Instruction &inst, DecodingContext context);


  SingleInstructionSleighContext sleigh_ctx;
  std::string sla_name;
  std::string pspec_name;

 private:
  mutable std::shared_ptr<remill::SleighLifter> lifter;
  const remill::Arch &arch;
  std::unordered_map<std::string, std::string> register_mapping;
};
}  // namespace remill::sleigh
