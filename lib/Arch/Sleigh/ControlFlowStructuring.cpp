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

    ind++;
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


struct Flow {
  size_t pcode_index;
  CoarseFlow flow;
  std::optional<DecodingContext> context;
};

std::vector<Flow>
GetBoundContextsForFlows(const std::vector<RemillPcodeOp> &ops,
                         const std::map<size_t, CoarseFlow> &cc,
                         ContextUpdater &updater) {
  size_t curr_ind = 0;
  std::vector<Flow> res;
  for (auto op : ops) {
    if (auto curr = cc.find(curr_ind); curr != cc.end()) {
      auto cont = updater.GetContext();
      Flow f = {curr_ind, curr->second, cont};
      res.push_back(std::move(f));
    }

    updater.ApplyPcodeOp(op);
    curr_ind += 1;
  }

  return res;
}


// DirectJump, IndirectJump, FunctionReturn
static std::optional<Instruction::InstructionFlowCategory>
AbnormalCategoryOfFlow(const Flow &flow, const RemillPcodeOp &op) {
  if (op.op == CPUI_RETURN) {
    Instruction::IndirectFlow id_flow = {{}, flow.context};
    Instruction::FunctionReturn ret = {{id_flow}};
    return ret;
  }

  if (op.op == CPUI_BRANCHIND) {
    Instruction::IndirectFlow id_flow = {{}, flow.context};
    Instruction::IndirectJump id_jump = {id_flow};
    return id_jump;
  }

  if (op.op == CPUI_BRANCH && !isVarnodeInConstantSpace(op.vars[0]) &&
      flow.context) {
    auto target = op.vars[0].offset;
    Instruction::DirectFlow dflow = {{}, target, *flow.context};
    Instruction::DirectJump djump = {dflow};
    return djump;
  }


  return std::nullopt;
}


static std::optional<std::pair<Instruction::InstructionFlowCategory,
                               std::optional<BranchTakenVar>>>
ExtractNonConditionalCategory(
    const std::vector<Flow> &flows, const std::vector<RemillPcodeOp> &ops,
    const std::function<std::optional<Instruction::InstructionFlowCategory>(
        const Flow &, const RemillPcodeOp &)> &compute_single_flow_category) {

  // So here the requirement to make this cateogry work is that all flows target the same abnormal (or are all returns), and all decoding contexts are equal
  std::vector<Instruction::InstructionFlowCategory> cats;
  for (auto flow : flows) {
    if (auto cat = compute_single_flow_category(flow, ops[flow.pcode_index])) {
      cats.push_back(*cat);
    } else {
      return std::nullopt;
    }
  }

  // if all cats are equal then we have our result

  if (cats.size() < 1) {
    return std::nullopt;
  }

  Instruction::InstructionFlowCategory fst = cats[0];

  if (std::all_of(cats.begin(), cats.end(),
                  [&fst](Instruction::InstructionFlowCategory curr_cat) {
                    return fst == curr_cat;
                  })) {
    return std::make_pair(fst, std::nullopt);
  }

  return std::nullopt;
}

static std::optional<std::pair<Instruction::InstructionFlowCategory,
                               std::optional<BranchTakenVar>>>
ExtractNormal(const std::vector<Flow> &flows,
              const std::vector<RemillPcodeOp> &ops) {
  // So we already know the op fallsthrough
  return ExtractNonConditionalCategory(
      flows, ops,
      [](const Flow &flow, const RemillPcodeOp &op)
          -> std::optional<Instruction::InstructionFlowCategory> {
        if (flow.context) {
          Instruction::NormalInsn norm = {{{}, *flow.context}};
          return {norm};
        }

        return std::nullopt;
      });
}


static std::optional<std::pair<Instruction::InstructionFlowCategory,
                               std::optional<BranchTakenVar>>>
ExtractAbnormal(const std::vector<Flow> &flows,
                const std::vector<RemillPcodeOp> &ops) {
  return ExtractNonConditionalCategory(flows, ops, AbnormalCategoryOfFlow);
}

static std::optional<std::pair<Instruction::InstructionFlowCategory,
                               std::optional<BranchTakenVar>>>
ExtractConditionalAbnormal(const std::vector<Flow> &flows,
                           const std::vector<RemillPcodeOp> &ops) {
  if (flows.size() != 2) {
    return std::nullopt;
  }

  auto first_flow = flows[0];
  auto snd_flow = flows[1];

  // Two case sto handle here either conditional_fallthrough->abnormal
  // Or conditional_abnormal -> fallthrough
  if (isConditionalNormal(first_flow.flow)) {
    CHECK(isUnconditionalAbnormal(snd_flow));
  }
}

}  // namespace

/*

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
*/

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

  auto flows = GetBoundContextsForFlows(ops, cc, this->context_evaluator);

  switch (*maybe_ccategory) {
    case CAT_ABNORMAL: return ExtractAbnormal(flows, ops);
    case CAT_CONDITIONAL_ABNORMAL: return std::nullopt;
    case CAT_NORMAL: return ExtractNormal(flows, ops);
  }
}
}  // namespace remill::sleigh