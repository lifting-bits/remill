#include <glog/logging.h>
#include <lib/Arch/Sleigh/ControlFlowStructuring.h>

#include <algorithm>
#include <optional>
#include <sleigh/space.hh>

namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode) {
  auto spc = vnode.getAddr().getSpace();
  return spc->getType() == IPTR_CONSTANT;
}


namespace {

// variant casting taken c&ped.
template <class... Args>
struct variant_cast_proxy {
  std::variant<Args...> v;

  template <class... ToArgs>
  operator std::variant<ToArgs...>() const {
    return std::visit([](auto &&arg) -> std::variant<ToArgs...> { return arg; },
                      v);
  }
};

template <class... Args>
auto variant_cast(const std::variant<Args...> &v)
    -> variant_cast_proxy<Args...> {
  return {v};
}

enum class CoarseEffect { kAbnormal, kNormal, kIntraInstruction };

struct CoarseFlow {
  CoarseEffect eff;
  bool is_conditional;
};

enum class CoarseCategory {
  kCatNormal,
  kCatNormalWithIntraInstructionFlow,
  kCatAbnormal,
  kCatConditionalAbnormal
};


static CoarseEffect EffectFromDirectControlFlowOp(const RemillPcodeOp &op,
                                                  uint64_t next_pc) {
  CHECK(op.op == CPUI_BRANCH || op.op == CPUI_CBRANCH);
  return op.vars[0].offset == next_pc ? CoarseEffect::kNormal
                                      : CoarseEffect::kAbnormal;
}

static std::optional<CoarseFlow>
CoarseFlowFromControlFlowOp(const RemillPcodeOp &op, uint64_t next_pc) {
  if (op.op == CPUI_CALL || op.op == CPUI_CALLIND || op.op == CPUI_BRANCHIND ||
      op.op == CPUI_RETURN) {
    return {{CoarseEffect::kAbnormal, false}};
  }

  // either a branch or a cbranch

  // figure out if this is a fallthrough, input 0 is the next target

  auto is_conditional = op.op == CPUI_CBRANCH;
  if (isVarnodeInConstantSpace(op.vars[0])) {
    return {{CoarseEffect::kIntraInstruction, is_conditional}};
  }

  return {{EffectFromDirectControlFlowOp(op, next_pc), is_conditional}};
}

// gets a list of indices and coarse categories in this pcodeop block
static std::optional<std::map<size_t, CoarseFlow>>
CoarseFlows(const std::vector<RemillPcodeOp> &ops, uint64_t next_pc) {
  std::map<size_t, CoarseFlow> res;
  size_t ind = 0;
  for (auto op : ops) {
    if (ControlFlowStructureAnalysis::isControlFlowPcodeOp(op.op)) {
      auto cc = CoarseFlowFromControlFlowOp(op, next_pc);
      if (!cc) {
        return std::nullopt;
      }

      res.emplace(ind, *cc);
    }

    ind++;
  }

  // insert a pseudo control flow op at the end
  // add a fallthrough insn at +1 to represent a last fallthrough if there is a chance we fallthrough at the end
  auto insn_may_fallthrough_at_end =
      ops.empty() ||
      !ControlFlowStructureAnalysis::isControlFlowPcodeOp(
          ops[ops.size() - 1].op) ||
      ops[ops.size() - 1].op == CPUI_CBRANCH;
  if (insn_may_fallthrough_at_end) {
    CoarseFlow cat = {CoarseEffect::kNormal, false};
    res.emplace(ops.size(), cat);
  }

  return res;
}

static bool isConditionalAbnormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::kAbnormal && flow.is_conditional;
}

static bool isUnconditionalAbnormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::kAbnormal && !flow.is_conditional;
}

static bool isConditionalNormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::kNormal && flow.is_conditional;
}

static bool isUnconditionalNormal(CoarseFlow flow) {
  return flow.eff == CoarseEffect::kNormal && !flow.is_conditional;
}

static std::optional<CoarseCategory>
CoarseCategoryFromFlows(const std::map<size_t, CoarseFlow> &ops) {

  auto all_normal_effects = std::all_of(
      ops.begin(), ops.end(), [](const std::pair<size_t, CoarseFlow> &op) {
        return op.second.eff == CoarseEffect::kNormal;
      });
  if (all_normal_effects) {
    return CoarseCategory::kCatNormal;
  }

  auto is_normal_or_intra = [](const std::pair<size_t, CoarseFlow> &op) {
    return op.second.eff == CoarseEffect::kNormal ||
           op.second.eff == CoarseEffect::kIntraInstruction;
  };
  auto all_normal_or_intra_effects =
      std::all_of(ops.begin(), ops.end(), is_normal_or_intra);

  if (all_normal_or_intra_effects) {
    return CoarseCategory::kCatNormalWithIntraInstructionFlow;
  }

  auto all_abnormal_effects = std::all_of(
      ops.begin(), ops.end(), [](const std::pair<size_t, CoarseFlow> &op) {
        return op.second.eff == CoarseEffect::kAbnormal;
      });
  if (all_abnormal_effects) {
    return CoarseCategory::kCatAbnormal;
  }

  if (ops.size() == 2) {
    auto fst = ops.begin()->second;
    auto snd = ops.rbegin()->second;
    if (((isConditionalAbnormal(fst) && isUnconditionalNormal(snd)) ||
         (isConditionalNormal(fst) && isUnconditionalAbnormal(snd)))) {
      return CoarseCategory::kCatConditionalAbnormal;
    }
  }


  return std::nullopt;
}


struct Flow {
  size_t pcode_index;
  CoarseFlow flow;
  std::optional<DecodingContext> context;

  Flow(size_t pcode_index, CoarseFlow flow,
       std::optional<DecodingContext> context)
      : pcode_index(pcode_index),
        flow(std::move(flow)),
        context(std::move(context)) {}
};

std::vector<Flow>
GetBoundContextsForFlows(const std::vector<RemillPcodeOp> &ops,
                         const std::map<size_t, CoarseFlow> &cc,
                         ContextUpdater &updater) {

  std::vector<Flow> res;
  CHECK(cc.size() >= 1);
  CHECK(cc.crbegin()->first <= ops.size());
  for (size_t curr_ind = 0; curr_ind <= ops.size(); curr_ind++) {
    if (auto curr = cc.find(curr_ind); curr != cc.end()) {
      auto cont = updater.GetContext();
      res.emplace_back(curr_ind, curr->second, cont);
    }

    if (curr_ind < ops.size()) {
      updater.ApplyPcodeOp(ops[curr_ind]);
    }
  }

  return res;
}


// DirectJump, IndirectJump, FunctionReturn
static std::optional<Instruction::AbnormalFlow>
AbnormalCategoryOfFlow(const Flow &flow, const RemillPcodeOp &op) {
  if (op.op == CPUI_RETURN) {
    Instruction::IndirectFlow id_flow(flow.context);
    Instruction::FunctionReturn ret(id_flow);
    return ret;
  }

  if (op.op == CPUI_BRANCHIND) {
    Instruction::IndirectFlow id_flow(flow.context);
    Instruction::IndirectJump id_jump(id_flow);
    return id_jump;
  }

  if (op.op == CPUI_BRANCH && !isVarnodeInConstantSpace(op.vars[0]) &&
      flow.context) {
    auto target = op.vars[0].offset;
    Instruction::DirectFlow dflow(target, *flow.context);
    Instruction::DirectJump djump(dflow);
    return djump;
  }

  if (op.op == CPUI_CALL) {
    auto target = op.vars[0].offset;
    Instruction::DirectFlow dflow(target, *flow.context);
    Instruction::DirectFunctionCall call(dflow);
    return call;
  }

  if (op.op == CPUI_CALLIND) {
    Instruction::IndirectFlow id_flow(flow.context);
    Instruction::IndirectFunctionCall call(id_flow);
    return call;
  }


  // still need to pick up the flow for the actual abnormal transition
  if (op.op == CPUI_CBRANCH) {
    auto target = op.vars[0].offset;
    Instruction::DirectFlow dflow(target, *flow.context);
    Instruction::DirectJump djump(dflow);
    return djump;
  }

  return std::nullopt;
}


static ControlFlowStructureAnalysis::SleighDecodingResult
ExtractNonConditionalCategory(
    const std::vector<Flow> &flows, const std::vector<RemillPcodeOp> &ops,
    std::function<std::optional<Instruction::InstructionFlowCategory>(
        const Flow &, const RemillPcodeOp &)>
        compute_single_flow_category) {

  // So here the requirement to make this cateogry work is that all flows target the same abnormal (or are all returns), and all decoding contexts are equal
  std::vector<Instruction::InstructionFlowCategory> cats;
  for (auto flow : flows) {
    if (auto cat = compute_single_flow_category(flow, ops[flow.pcode_index])) {
      cats.push_back(*cat);
    } else {
      DLOG(ERROR) << "Missing flow cat";
      return std::nullopt;
    }
  }

  // if all cats are equal then we have our result

  if (cats.size() < 1) {
    DLOG(ERROR) << "No extracted cats";
    return std::nullopt;
  }

  auto fst = cats[0];
  auto all_flows_equal = [&fst](Instruction::InstructionFlowCategory curr_cat) {
    return fst == curr_cat;
  };
  if (std::all_of(cats.begin(), cats.end(), std::move(all_flows_equal))) {
    return std::make_pair(fst, std::nullopt);
  }
  DLOG(ERROR) << "Not equal flows";

  return std::nullopt;
}

static ControlFlowStructureAnalysis::SleighDecodingResult
ExtractNormal(const std::vector<Flow> &flows,
              const std::vector<RemillPcodeOp> &ops) {
  // So we already know the op fallsthrough
  return ExtractNonConditionalCategory(
      flows, ops,
      [](const Flow &flow, const RemillPcodeOp &op)
          -> std::optional<Instruction::InstructionFlowCategory> {
        if (flow.context) {
          Instruction::NormalInsn norm(
              Instruction::FallthroughFlow(*flow.context));
          return norm;
        }
        DLOG(ERROR) << "Normal does not have context";
        return std::nullopt;
      });
}


static ControlFlowStructureAnalysis::SleighDecodingResult
ExtractAbnormal(const std::vector<Flow> &flows,
                const std::vector<RemillPcodeOp> &ops) {
  return ExtractNonConditionalCategory(
      flows, ops,
      [](const Flow &flow, const RemillPcodeOp &op)
          -> std::optional<Instruction::InstructionFlowCategory> {
        auto res = AbnormalCategoryOfFlow(flow, op);
        if (res) {
          return variant_cast(*res);
        }
        return std::nullopt;
      });
}

static ControlFlowStructureAnalysis::SleighDecodingResult
ExtractConditionalAbnormal(const std::vector<Flow> &flows,
                           const std::vector<RemillPcodeOp> &ops) {
  if (flows.size() != 2) {
    return std::nullopt;
  }

  const auto &first_flow = flows[0];
  const auto &snd_flow = flows[1];

  // Two case sto handle here either conditional_fallthrough->abnormal
  // Or conditional_abnormal -> fallthrough


  if (!isConditionalNormal(first_flow.flow) &&
      !isConditionalAbnormal(first_flow.flow)) {
    return std::nullopt;
  }

  auto flip_cond = isConditionalNormal(first_flow.flow);
  const auto &abnormal_flow =
      isConditionalNormal(first_flow.flow) ? snd_flow : first_flow;
  const auto &normal_flow =
      isConditionalNormal(first_flow.flow) ? first_flow : snd_flow;
  // so here we know the first flow is conditional of some sort and it should be followed by some unconditonal flow
  CHECK(isUnconditionalAbnormal(snd_flow.flow) ||
        isUnconditionalNormal(snd_flow.flow));

  const auto &cond_insn = ops[first_flow.pcode_index];

  CHECK(cond_insn.op == CPUI_CBRANCH);

  BranchTakenVar taken_var = {
      flip_cond,
      cond_insn.vars[1],
      first_flow.pcode_index,
  };


  if (!normal_flow.context) {
    return std::nullopt;
  }
  auto normal_context = *normal_flow.context;

  auto abnormal_part =
      AbnormalCategoryOfFlow(abnormal_flow, ops[abnormal_flow.pcode_index]);


  if (!abnormal_part) {
    return std::nullopt;
  }

  Instruction::ConditionalInstruction cond(
      *abnormal_part, Instruction::FallthroughFlow(normal_context));

  return {{cond, taken_var}};
}

}  // namespace


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
- Conditional Abnormal: either we have a CONDITIONAL_FALLTHROUGH followed by an kAbnormal
  - or we have a CONDITIONAL_ABNORMAL followed by a FALLTHROUGH
- Abnormal: we have many ABNORMALs conditional or otherwise

We forbid multiple conditionals in a flow because then we'd need to join conditions

After we find coarse categories and the flows follow these patterns, we determine if there is a constant context for each relevant flow.

Finally we pass these coarse flows to a final categorizer to attempt to print these into a flow type
*/

ControlFlowStructureAnalysis::SleighDecodingResult
ControlFlowStructureAnalysis::ComputeCategory(
    const std::vector<RemillPcodeOp> &ops, uint64_t fallthrough_addr,
    DecodingContext entry_context) {

  auto maybe_cc = CoarseFlows(ops, fallthrough_addr);
  if (!maybe_cc) {
    DLOG(ERROR) << "No coarse flow found";
    return std::nullopt;
  }

  auto cc = std::move(*maybe_cc);

  auto maybe_ccategory = CoarseCategoryFromFlows(cc);
  if (!maybe_ccategory) {
    DLOG(ERROR) << "No coarse category found";
    return std::nullopt;
  }
  auto context_updater = BuildContextUpdater(entry_context);

  if (*maybe_ccategory == CoarseCategory::kCatNormalWithIntraInstructionFlow) {
    // our control flow analysis for decoding contexts doesnt handle intraprocedural control flow,
    // so if we have a normal instruction with no decoding context updates then we are fine otherwise bail
    auto no_context_updates = std::all_of(
        ops.begin(), ops.end(), [&context_updater](const RemillPcodeOp &op) {
          return !op.outvar.has_value() ||
                 !context_updater.GetRemillReg(*op.outvar).has_value();
        });

    if (no_context_updates) {
      Instruction::NormalInsn norm_insn(
          (Instruction::FallthroughFlow(entry_context)));
      Instruction::InstructionFlowCategory ifc = norm_insn;
      return std::make_pair(ifc, std::nullopt);
    }
    DLOG(ERROR)
        << "Had an instructon with intrainstruction flow, but also decoding context updates";
    return std::nullopt;
  }

  auto flows = GetBoundContextsForFlows(ops, cc, context_updater);

  switch (*maybe_ccategory) {
    case CoarseCategory::kCatNormalWithIntraInstructionFlow:
      return std::nullopt;
    case CoarseCategory::kCatAbnormal: return ExtractAbnormal(flows, ops);
    case CoarseCategory::kCatConditionalAbnormal:
      return ExtractConditionalAbnormal(flows, ops);
    case CoarseCategory::kCatNormal: return ExtractNormal(flows, ops);
  }
}

std::optional<std::string>
ContextUpdater::GetRemillReg(const VarnodeData &outvar) {
  auto reg_name =
      engine.getRegisterName(outvar.space, outvar.offset, outvar.size);
  auto it = context_reg_mapping.find(reg_name);
  if (it != context_reg_mapping.end()) {
    return it->second;
  }
  return std::nullopt;
}


// Applies a pcode op to the held context, this may produce a complete context
void ContextUpdater::ApplyPcodeOp(const RemillPcodeOp &op) {
  if (!op.outvar) {
    return;
  }

  auto out = *op.outvar;
  auto maybe_remill_reg_name = GetRemillReg(out);
  if (!maybe_remill_reg_name) {
    return;
  }

  auto remill_reg_name = *maybe_remill_reg_name;

  if (op.op == CPUI_COPY && isVarnodeInConstantSpace(op.vars[0])) {
    curr_context.UpdateContextReg(remill_reg_name, op.vars[0].offset);
  } else {
    curr_context.DropReg(remill_reg_name);
  }
}

// May have a complete context
std::optional<DecodingContext> ContextUpdater::GetContext() const {
  for (const auto &[_, remill_reg] : this->context_reg_mapping) {
    if (!curr_context.HasValueForReg(remill_reg)) {
      return std::nullopt;
    }
  }

  return curr_context;
}

ContextUpdater ControlFlowStructureAnalysis::BuildContextUpdater(
    DecodingContext initial_context) {
  return ContextUpdater(context_reg_mapping, std::move(initial_context),
                        engine);
}

ContextUpdater::ContextUpdater(
    const std::unordered_map<std::string, std::string> &context_reg_mapping,
    DecodingContext initial_context, Sleigh &engine_)
    : context_reg_mapping(context_reg_mapping),
      curr_context(std::move(initial_context)),
      engine(engine_) {}


ControlFlowStructureAnalysis::ControlFlowStructureAnalysis(
    const std::unordered_map<std::string, std::string> &register_mapping_,
    Sleigh &engine_)
    : context_reg_mapping(register_mapping_),
      engine(engine_) {}


}  // namespace remill::sleigh
