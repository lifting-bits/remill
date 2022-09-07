#include "ControlFlowStructuring.h"
namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode) {
  auto spc = vnode.getAddr().getSpace();
  return spc->constant_space_index == spc->getIndex();
}


namespace {

enum CoarseEffect { ABNORMAL, NORMAL };

struct CoarseFlow {
  CoarseEffect eff;
  bool is_conditional;
};

enum CoarseCategory { CAT_NORMAL, CAT_ABNORMAL, CAT_CONDITIONAL_ABNORMAL };


static std::optional<CoarseFlow>
CoarseFlowFromControlFlowOp(const RemillPcodeOp &op, uint64_t next_pc) {
  if (op.op == CPUI_CALL || op.op == CPUI_CALLIND || op.op == CPUI_BRANCHIND ||
      op.op == CPUI_RETURN) {
    return {{CoarseEffect::ABNORMAL, false}};
  }

  // either a branch or a cbranch

  // figure out if this is a fallthrough, input 0 is the next target

  auto is_conditional = op.op == CPUI_CBRANCH;
  if (isVarnodeInConstantSpace(op.vars[0])) {
    // this is an internal branch.. we cant handle that right now
    return std::nullopt;
  }

  if (op.vars[0].offset == next_pc) {
    return {{CoarseEffect::NORMAL, is_conditional}};
  } else {
    return {{CoarseEffect::ABNORMAL, is_conditional}};
  }
}

// gets a list of indeces and coarse categories in this pcodeop block
static std::optional<std::map<size_t, CoarseFlow>>
CoarseFlows(const std::vector<RemillPcodeOp> &ops, uint64_t next_pc) {
  size_t ind = 0;
  std::map<size_t, CoarseFlow> res;
  for (auto op : ops) {
    if (ControlFlowStructureAnalysis::isControlFlowPcodeOp(op.op)) {
      auto cc = CoarseFlowFromControlFlowOp(op, next_pc);
      if (!cc) {
        return std::nullopt;
      }

      res.emplace(ind, *cc);
      // insert a pseudo control flow op at the end
    } else if (ind == res.size() - 1) {
      CoarseFlow cat = {CoarseEffect::NORMAL, false};
      res.emplace(ind, cat);
    }
  }

  return res;
}

static bool isConditionalAbnormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::ABNORMAL && flow.is_conditional;
}

static bool isUnconditionalAbnormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::ABNORMAL && !flow.is_conditional;
}

static bool isConditionalNormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::NORMAL && flow.is_conditional;
}

static bool isUnconditionalNormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::NORMAL && !flow.is_conditional;
}

static std::optional<CoarseCategory>
CoarseCategoryFromFlows(const std::map<size_t, CoarseFlow> &ops) {
  if (std::all_of(ops.begin(), ops.end(), [](std::pair<size_t, CoarseFlow> op) {
        return op.second.eff == CoarseEffect::NORMAL;
      })) {
    return CoarseCategory::CAT_NORMAL;
  }

  if (std::all_of(ops.begin(), ops.end(), [](std::pair<size_t, CoarseFlow> op) {
        return op.second.eff == CoarseEffect::ABNORMAL;
      })) {
    return CoarseCategory::CAT_ABNORMAL;
  }

  if (ops.size() == 2) {
    auto fst = ops.begin()->second;
    auto snd = ops.rbegin()->second;
    if (((isConditionalAbnormal(fst) && isUnconditionalNormal(snd)) ||
         (isConditionalNormal(fst) && isUnconditionalAbnormal(snd)))) {
      return CoarseCategory::CAT_CONDITIONAL_ABNORMAL;
    }
  }


  return std::nullopt;
}

static bool isFallthrough(OpCode opc) {
  return opc == OpCode::CPUI_BRANCH || opc == OpCode::CPUI_CBRANCH ||
         opc == OpCode::CPUI_CALL || opc == OpCode::CPUI_BRANCHIND ||
         opc == OpCode::CPUI_CALLIND || opc == OpCode::CPUI_RETURN;
}

struct Flow {
  CoarseFlow flow;
  std::optional<DecodingContext> context;
};

std::vector<Flow>
GetBoundContextsForFlows(const std::vector<RemillPcodeOp> &ops,
                         const std::map<size_t, CoarseFlow> &cc) {
  for (auto op : ops) {
  }
}
}  // namespace


std::optional<DecodingContext>
ContextUpdater::NextContext(const RemillPcodeOp &op,
                            DecodingContext prev) const {
  // So we are updating a variable, if it's a target we either need to give it a new constant value or drop it to nonconstant
  if (!op.outvar) {
    return prev;
  }

  auto outvar_name = this->engine.getRegisterName(
      op.outvar->space, op.outvar->offset, op.outvar->size);
  auto target_remill_cont_reg = this->register_mapping.find(outvar_name);
  if (target_remill_cont_reg == this->register_mapping.end()) {
    return prev;
  }

  if (op.op == OpCode::CPUI_COPY && isVarnodeInConstantSpace(op.vars[0])) {
    prev.UpdateContextReg(target_remill_cont_reg->second, op.vars[0].offset);
    return prev;
  }

  return std::nullopt;
}

bool ControlFlowStructureAnalysis::isControlFlowPcodeOp(OpCode opc) {
  return opc == OpCode::CPUI_BRANCH || opc == OpCode::CPUI_CBRANCH ||
         opc == OpCode::CPUI_CALL || opc == OpCode::CPUI_BRANCHIND ||
         opc == OpCode::CPUI_CALLIND || opc == OpCode::CPUI_RETURN;
}


// Since wre aren't supporting internal control flow right now we can categorize based on the first outgoing flow
// The only subtlety here really is allowing for conditional normals where we cbranch [fallthrough_addr] and then potentially fallthrough

/*
So in a coarse grained way we can just treat indirect/direct/interprocedural flows as the same thing and losely classify these as "abnormal" or non-fallthrough.
Either a fallthrough or an abnormal flow can be conditional

So the first step is to categorize a coarse grained control flow category which is one of:
- Normal, in this case there are only fallthroughs, conditional or otherwise  
- Conditional Abnormal: either we have a CONDITIONAL_FALLTHROUGH followed by an ABNORMAL
  - or we have a CONDITIONAL_ABNORMAL followed by a FALLTHROUGH
- Abnormal: we have many ABNORMALs conditional or otherwise 

We forbid multiple conditionals in a flow because then we'd need to join conditions

After we find coarse categories and the flows follow these patterns, we determine if there is a constant context for each relevant flow. 

Finally we pass these coarse flows to a final categorizer to attempt to print these into a flow type
*/

std::optional<std::pair<Instruction::InstructionFlowCategory,
                        std::optional<BranchTakenVar>>>
ControlFlowStructureAnalysis::ComputeCategory(
    const std::vector<RemillPcodeOp> &ops, uint64_t fallthrough_addr,
    DecodingContext entry_context) {
  auto maybe_cc = CoarseFlows(ops, fallthrough_addr);
  if (!maybe_cc) {
    return std::nullopt;
  }

  auto cc = *maybe_cc;

  auto maybe_ccategory = CoarseCategoryFromFlows(cc);
  if (!maybe_ccategory) {
    return std::nullopt;
  }

  auto flows = GetBoundContextsForFlows(ops, cc);
}
}  // namespace remill::sleigh