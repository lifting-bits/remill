#pragma once

#include <remill/Arch/Instruction.h>
#include <stdint.h>

#include <sleigh/libsleigh.hh>
#include <unordered_map>

namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode);

struct BranchTakenVar {
  bool invert;
  size_t index;
};

struct RemillPcodeOp {
  OpCode op;
  std::optional<VarnodeData> outvar;
  std::vector<VarnodeData> vars;
};

/// A context updates a context if the target PcodeOp updates the context. if it is non constant it drops the context
class ContextUpdater {
 private:
  const std::unordered_map<std::string, std::string> &register_mapping;

  Sleigh &engine;

 public:
  ContextUpdater(
      const std::unordered_map<std::string, std::string> &register_mapping,
      Sleigh &engine_);

  std::optional<DecodingContext> NextContext(const RemillPcodeOp &,
                                             DecodingContext prev) const;
};

class ControlFlowStructureAnalysis {

 private:
  ContextUpdater context_evaluator;


 public:
  static bool isControlFlowPcodeOp(OpCode opc);

  std::optional<std::pair<Instruction::InstructionFlowCategory,
                          std::optional<BranchTakenVar>>>
  ComputeCategory(const std::vector<RemillPcodeOp> &ops,
                  uint64_t fallthrough_addr, DecodingContext entry_context);
};
}  // namespace remill::sleigh