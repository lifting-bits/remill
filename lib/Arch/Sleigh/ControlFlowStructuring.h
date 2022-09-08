#pragma once

#include <remill/Arch/Instruction.h>
#include <stdint.h>

#include <sleigh/libsleigh.hh>
#include <unordered_map>

namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode);

// If you lift a varnode before the given pcode index, then you have a branch taken metavar
struct BranchTakenVar {
  bool invert;
  VarnodeData target_vnode;
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
  DecodingContext curr_context;
  Sleigh &engine;

 public:
  ContextUpdater(
      const std::unordered_map<std::string, std::string> &register_mapping,
      Sleigh &engine_);

  // Applies a pcode op to the held context, this may produce a complete context
  void ApplyPcodeOp(const RemillPcodeOp &op);

  // May have a complete context
  std::optional<DecodingContext> GetContext() const;
};

class ControlFlowStructureAnalysis {

 private:
  const std::unordered_map<std::string, std::string> &register_mapping;
  Sleigh &engine;


  ContextUpdater BuildContextUpdater();

 public:
  ControlFlowStructureAnalysis(
      const std::unordered_map<std::string, std::string> &register_mapping,
      Sleigh &engine);

  static bool isControlFlowPcodeOp(OpCode opc);

  std::optional<std::pair<Instruction::InstructionFlowCategory,
                          std::optional<BranchTakenVar>>>
  ComputeCategory(const std::vector<RemillPcodeOp> &ops,
                  uint64_t fallthrough_addr, DecodingContext entry_context);
};
}  // namespace remill::sleigh