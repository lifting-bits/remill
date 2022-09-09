#include "ControlFlowStructuring.h"

#include <glog/logging.h>


namespace remill {
bool Instruction::DirectJump::operator==(const DirectJump &rhs) const {
  return this->taken_flow == rhs.taken_flow;
}

bool Instruction::DirectFlow::operator==(
    remill::Instruction::DirectFlow const &rhs) const {
  return this->known_target == rhs.known_target &&
         this->static_context == rhs.static_context;
}

bool Instruction::NormalInsn::operator==(
    remill::Instruction::NormalInsn const &rhs) const {
  return Instruction::FallthroughFlow::operator==(rhs);
}

bool Instruction::InvalidInsn::operator==(
    remill::Instruction::InvalidInsn const &invalid) const {
  return true;
}

bool Instruction::IndirectJump::operator==(
    remill::Instruction::IndirectJump const &rhs) const {
  return this->taken_flow == rhs.taken_flow;
}

bool Instruction::AsyncHyperCall::operator==(
    remill::Instruction::AsyncHyperCall const &rhs) const {
  return true;
}

bool Instruction::FunctionReturn::operator==(
    remill::Instruction::FunctionReturn const &rhs) const {
  return Instruction::IndirectJump::operator==(rhs);
}

bool Instruction::FallthroughFlow::operator==(
    remill::Instruction::FallthroughFlow const &rhs) const {
  return this->fallthrough_context == rhs.fallthrough_context;
}

bool Instruction::DirectFunctionCall::operator==(
    remill::Instruction::DirectFunctionCall const &rhs) const {
  return Instruction::DirectJump::operator==(rhs);
}

bool Instruction::ConditionalInstruction::operator==(
    remill::Instruction::ConditionalInstruction const &rhs) const {
  return this->fall_through == rhs.fall_through &&
         this->taken_branch == rhs.taken_branch;
}

bool Instruction::IndirectFlow::operator==(
    remill::Instruction::IndirectFlow const &rhs) const {
  return this->maybe_context == rhs.maybe_context;
}

bool Instruction::IndirectFunctionCall::operator==(
    remill::Instruction::IndirectFunctionCall const &rhs) const {
  return Instruction::IndirectJump::operator==(rhs);
}

bool Instruction::ErrorInsn::operator==(
    remill::Instruction::ErrorInsn const &) const {
  return true;
}


}  // namespace remill

namespace remill::sleigh {

bool isVarnodeInConstantSpace(VarnodeData vnode) {
  auto spc = vnode.getAddr().getSpace();
  return spc->constant_space_index == spc->getIndex();
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
    }

    // add a fallthrough insn at +1 to represent a last fallthrough if there is a chance we fallthrough at the end
    if ((!ControlFlowStructureAnalysis::isControlFlowPcodeOp(op.op) ||
         op.op == CPUI_CBRANCH) &&
        ind == res.size() - 1) {
      CoarseFlow cat = {CoarseEffect::NORMAL, false};
      res.emplace(ind + 1, cat);
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
static std::optional<Instruction::AbnormalFlow>
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

  if (op.op == CPUI_CALL) {
    auto target = op.vars[0].offset;
    Instruction::DirectFlow dflow = {{}, target, *flow.context};
    Instruction::DirectJump djump = {dflow};
    Instruction::DirectFunctionCall call = {djump};
    return call;
  }

  if (op.op == CPUI_CALLIND) {
    Instruction::IndirectFlow id_flow = {{}, flow.context};
    Instruction::IndirectJump id_jump = {id_flow};
    Instruction::IndirectFunctionCall call = {id_jump};
    return call;
  }


  // still need to pick up the flow for the actual abnormal transition
  if (op.op == CPUI_CBRANCH) {
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
  return ExtractNonConditionalCategory(
      flows, ops,
      [](const Flow &flow, const RemillPcodeOp &op)
          -> std::optional<Instruction::InstructionFlowCategory> {
        auto res = AbnormalCategoryOfFlow(flow, op);
        if (res) {
          return variant_cast(*res);
        } else {
          return std::nullopt;
        }
      });
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

  auto abnormal_part =
      AbnormalCategoryOfFlow(abnormal_flow, ops[abnormal_flow.pcode_index]);


  if (!normal_flow.context) {
    return std::nullopt;
  }
  auto normal_context = *normal_flow.context;


  if (!abnormal_part) {
    return std::nullopt;
  }

  Instruction::ConditionalInstruction cond = {*abnormal_part,
                                              {{}, normal_context}};

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
  auto context_updater = this->BuildContextUpdater(std::move(entry_context));
  auto flows = GetBoundContextsForFlows(ops, cc, context_updater);

  switch (*maybe_ccategory) {
    case CAT_ABNORMAL: return ExtractAbnormal(flows, ops);
    case CAT_CONDITIONAL_ABNORMAL:
      return ExtractConditionalAbnormal(flows, ops);
    case CAT_NORMAL: return ExtractNormal(flows, ops);
  }
}

// Applies a pcode op to the held context, this may produce a complete context
void ContextUpdater::ApplyPcodeOp(const RemillPcodeOp &op) {
  if (!op.outvar) {
    return;
  }

  auto out = *op.outvar;
  auto reg_name = this->engine.getRegisterName(out.space, out.offset, out.size);
  auto maybe_remill_reg_name = this->register_mapping.find(reg_name);
  if (maybe_remill_reg_name == this->register_mapping.end()) {
    return;
  }

  auto remill_reg_name = maybe_remill_reg_name->second;

  if (op.op == CPUI_COPY && isVarnodeInConstantSpace(op.vars[0])) {
    this->curr_context.UpdateContextReg(remill_reg_name, op.vars[0].offset);
  } else {
    this->curr_context.DropReg(remill_reg_name);
  }
}

// May have a complete context
std::optional<DecodingContext> ContextUpdater::GetContext() const {
  for (const auto &[_, remill_reg] : this->register_mapping) {
    if (!this->curr_context.HasContextValue(remill_reg)) {
      return std::nullopt;
    }
  }

  return this->curr_context;
}

ContextUpdater ControlFlowStructureAnalysis::BuildContextUpdater(
    DecodingContext initial_context) {
  return ContextUpdater(this->register_mapping, std::move(initial_context),
                        this->engine);
}

ContextUpdater::ContextUpdater(
    const std::unordered_map<std::string, std::string> &register_mapping,
    DecodingContext initial_context, Sleigh &engine_)
    : register_mapping(register_mapping),
      curr_context(std::move(initial_context)),
      engine(engine_) {}


ControlFlowStructureAnalysis::ControlFlowStructureAnalysis(
    const std::unordered_map<std::string, std::string> &register_mapping_,
    Sleigh &engine_)
    : register_mapping(register_mapping_),
      engine(engine_) {}


}  // namespace remill::sleigh