#pragma once

#include <remill/Arch/Instruction.h>
#include <remill/BC/SleighLifter.h>
#include <stdint.h>

#include <sleigh/libsleigh.hh>
#include <sleigh/pcoderaw.hh>
#include <unordered_map>

namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode);


struct RemillPcodeOp {
  OpCode op;
  std::optional<VarnodeData> outvar;
  std::vector<VarnodeData> vars;
};

/// A context updates a context if the target PcodeOp updates the context. if it is non constant it drops the context
class ContextUpdater {
 private:
  const std::unordered_map<std::string, std::string> &context_reg_mapping;
  DecodingContext curr_context;
  Sleigh &engine;

 public:
  ContextUpdater(
      const std::unordered_map<std::string, std::string> &context_reg_mapping,
      DecodingContext initial_context, Sleigh &engine_);

  // Applies a pcode op to the held context, this may produce a complete context
  void ApplyPcodeOp(const RemillPcodeOp &op);

  std::optional<std::string> GetRemillReg(const VarnodeData &);


  // May have a complete context
  std::optional<DecodingContext> GetContext() const;
};

class ControlFlowStructureAnalysis {

 private:
  const std::unordered_map<std::string, std::string> &context_reg_mapping;
  Sleigh &engine;


  ContextUpdater BuildContextUpdater(DecodingContext initial_context);

 public:
  using SleighDecodingResult = std::optional<
      std::pair<Instruction::InstructionFlowCategory, MaybeBranchTakenVar>>;
  ControlFlowStructureAnalysis(
      const std::unordered_map<std::string, std::string> &context_reg_mapping,
      Sleigh &engine);

  static bool isControlFlowPcodeOp(OpCode opc);

  SleighDecodingResult ComputeCategory(const std::vector<RemillPcodeOp> &ops,
                                       uint64_t fallthrough_addr,
                                       DecodingContext entry_context);
};
}  // namespace remill::sleigh
