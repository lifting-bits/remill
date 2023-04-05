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
#include <lib/Arch/Sleigh/ControlFlowStructuring.h>
#include <remill/Arch/ArchBase.h>
#include <remill/BC/SleighLifter.h>

#include <sleigh/libsleigh.hh>
#include <unordered_set>

// Unifies shared functionality between sleigh architectures

namespace remill::sleigh {

class PcodeDecoder final : public PcodeEmit {
 public:
  PcodeDecoder(::Sleigh &engine_);

  void dump(const Address &, OpCode op, VarnodeData *outvar, VarnodeData *vars,
            int32_t isize) override;


  std::vector<RemillPcodeOp> ops;

 private:
  ::Sleigh &engine;
  void print_vardata(std::stringstream &s, VarnodeData &data);
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

struct ContextRegMappings {

 private:
  std::unordered_map<std::string, std::string> context_reg_mapping;
  // Stores the size of the context register in bytes.
  // We need to allocate space for an instruction to manipulate a
  // Context reg as needed. This space is also populated with the incoming value.
  std::unordered_map<std::string, size_t> vnode_size_mapping;

 public:
  ContextRegMappings(
      std::unordered_map<std::string, std::string> context_reg_mapping,
      std::unordered_map<std::string, size_t> vnode_size_mapping)
      : context_reg_mapping(std::move(context_reg_mapping)),
        vnode_size_mapping(std::move(vnode_size_mapping)) {}

  const std::unordered_map<std::string, size_t> &GetSizeMapping() const;

  const std::unordered_map<std::string, std::string> &
  GetInternalRegMapping() const;
};

class SleighDecoder {
 public:
  SleighDecoder() = delete;
  SleighDecoder(
      const remill::Arch &arch, std::string sla_name, std::string pspec_name,
      ContextRegMappings context_reg_mapping,
      std::unordered_map<std::string, std::string> state_reg_remappings);
  const std::string &GetSLAName() const;

  const std::string &GetPSpec() const;
  // Decoder specific prep
  virtual void InitializeSleighContext(uint64_t address,
                                       SingleInstructionSleighContext &,
                                       const ContextValues &) const = 0;


  virtual llvm::Value *
  LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *curr_pc,
                   size_t curr_insn_size, const DecodingContext &) const = 0;


  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst, DecodingContext context) const;

  // Gets the context registers that are required to be set in order to decode, maps pcode context reg names to remill context reg names.
  const ContextRegMappings &GetContextRegisterMapping() const;

  // Maps pcode registers to their names in the remill state structure for the given arch (if a renaming is required.)
  const std::unordered_map<std::string, std::string> &
  GetStateRegRemappings() const;

  std::shared_ptr<remill::OperandLifter> GetOpLifter() const;

 protected:
  ControlFlowStructureAnalysis::SleighDecodingResult
  DecodeInstructionImpl(uint64_t address, std::string_view instr_bytes,
                        Instruction &inst, DecodingContext context);


  SingleInstructionSleighContext sleigh_ctx;
  std::string sla_name;
  std::string pspec_name;

 private:
  std::shared_ptr<remill::SleighLifter> GetLifter() const;
  // Compatibility that applies old categories from constructed flows
  void ApplyFlowToInstruction(remill::Instruction &) const;


  mutable std::shared_ptr<remill::SleighLifter> lifter;
  const remill::Arch &arch;
  ContextRegMappings context_reg_mapping;
  std::unordered_map<std::string, std::string> state_reg_remappings;
};

uint64_t GetContextRegisterValue(const char *remill_reg_name,
                                 uint64_t default_value,
                                 const ContextValues &context_values);

void SetContextRegisterValueInSleigh(
    uint64_t addr, const char *remill_reg_name, const char *sleigh_reg_name,
    uint64_t default_value, sleigh::SingleInstructionSleighContext &ctxt,
    const ContextValues &context_values);

}  // namespace remill::sleigh
