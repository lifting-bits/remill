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


#include "Arch.h"

#include <glog/logging.h>
#include <remill/Arch/Name.h>
#include <remill/BC/SleighLifter.h>

namespace remill::sleigh {

namespace {

class InstructionFunctionSetter : public AssemblyEmit {
 private:
  remill::Instruction &insn;

 public:
  InstructionFunctionSetter(remill::Instruction &insn) : insn(insn) {}

  void dump(const Address &addr, const string &mnem, const string &body) {
    insn.function = mnem;
  }
};

class AssemblyLogger : public AssemblyEmit {
  void dump(const Address &addr, const string &mnem, const string &body) {
    LOG(INFO) << "Decoded " << std::hex << addr.getOffset() << ": " << mnem
              << " " << body;
  }
};
}  // namespace

PcodeDecoder::PcodeDecoder(::Sleigh &engine_) : engine(engine_) {}


void PcodeDecoder::print_vardata(std::stringstream &s, VarnodeData &data) {
  s << '(' << data.space->getName() << ',';
  data.space->printOffset(s, data.offset);
  s << ',' << dec << data.size << ')';

  auto maybe_name =
      this->engine.getRegisterName(data.space, data.offset, data.size);
  if (!maybe_name.empty()) {
    s << ":" << maybe_name;
  }
}

void PcodeDecoder::dump(const Address &, OpCode op, VarnodeData *outvar,
                        VarnodeData *vars, int32_t isize) {
  RemillPcodeOp new_op;
  new_op.op = op;
  if (outvar) {
    new_op.outvar = *outvar;
  } else {
    new_op.outvar = std::nullopt;
  }

  for (int i = 0; i < isize; i++) {
    new_op.vars.push_back(vars[i]);
  }

  this->ops.push_back(std::move(new_op));
}

std::vector<std::string> SingleInstructionSleighContext::getUserOpNames() {
  std::vector<std::string> res;
  this->engine.getUserOpNames(res);
  return res;
}

SingleInstructionSleighContext::SingleInstructionSleighContext(
    std::string sla_name, std::string pspec_name)
    : engine(&image, &ctx) {

  auto guard = Arch::Lock(ArchName::kArchX86_SLEIGH);

  const std::optional<std::filesystem::path> sla_path =
      ::sleigh::FindSpecFile(sla_name.c_str());
  if (!sla_path) {
    LOG(FATAL) << "Couldn't find required spec file: " << sla_name << '\n';
  }
  LOG(INFO) << "Using spec at: " << sla_path->string();

  AttributeId::initialize();
  ElementId::initialize();


  auto pspec_path = ::sleigh::FindSpecFile(pspec_name.c_str());

  if (!pspec_path) {
    LOG(FATAL) << "Couldn't find required pspec file: " << pspec_name << '\n';
  }
  LOG(INFO) << "Using pspec at: " << pspec_path->string();

  Element *root = storage.openDocument(sla_path->string())->getRoot();
  storage.registerTag(root);

  auto pspec = storage.openDocument(pspec_path->string());
  storage.registerTag(pspec->getRoot());
  this->restoreEngineFromStorage();
}
void SingleInstructionSleighContext::restoreEngineFromStorage() {
  this->ctx = ContextInternal();
  engine.initialize(storage);
  const Element *el = storage.getTag("processor_spec");
  if (el) {
    XmlDecode decoder(&engine, el);
    uint4 elemId = decoder.openElement(ELEM_PROCESSOR_SPEC);
    for (;;) {
      uint4 subId = decoder.peekElement();
      if (subId == 0)
        break;
      else if (subId == ELEM_CONTEXT_DATA) {
        ctx.decodeFromSpec(decoder);
        break;
      } else {
        decoder.openElement();
        decoder.closeElementSkipping(subId);
      }
    }
    decoder.closeElement(elemId);
  }
  engine.allowContextSet(false);
}

Address SingleInstructionSleighContext::GetAddressFromOffset(uint64_t off) {
  return Address(this->engine.getDefaultCodeSpace(), off);
}


CustomLoadImage::CustomLoadImage(void) : LoadImage("nofile") {}

void CustomLoadImage::SetInstruction(uint64_t new_offset,
                                     std::string_view instr_bytes) {
  this->current_bytes = instr_bytes;
  this->current_offset = new_offset;
}

void CustomLoadImage::loadFill(unsigned char *ptr, int size,
                               const Address &addr) {
  uint64_t start = addr.getOffset();
  LOG(INFO) << "Fill at: " << start << " of size: " << size;

  for (int i = 0; i < size; ++i) {
    uint64_t offset = start + i;
    uint64_t index = offset - this->current_offset;

    if (offset < this->current_offset ||
        index >= this->current_bytes.length()) {
      ptr[i] = 0;
      continue;
    }

    ptr[i] = this->current_bytes[i];
  }
}

std::string CustomLoadImage::getArchType(void) const {
  return "custom";
}

void CustomLoadImage::adjustVma(long) {}

std::shared_ptr<remill::OperandLifter> SleighDecoder::GetOpLifter() const {
  return this->GetLifter();
}

std::shared_ptr<remill::SleighLifter> SleighDecoder::GetLifter() const {
  if (this->lifter) {
    return this->lifter;
  }

  if (!this->arch.GetInstrinsicTable()) {
    LOG(FATAL)
        << "Architecture was not initialized before asking for a lifting";
  }

  auto tab = this->arch.GetInstrinsicTable();

  this->lifter =
      std::make_shared<remill::SleighLifter>(this->arch, *this, *tab);

  return this->lifter;
}

bool SleighDecoder::DecodeInstruction(uint64_t address,
                                      std::string_view instr_bytes,
                                      Instruction &inst,
                                      DecodingContext context) const {


  auto context_values = context.GetContextValues();
  auto res_cat = const_cast<SleighDecoder *>(this)->DecodeInstructionImpl(
      address, instr_bytes, inst, std::move(context));

  if (!res_cat->second &&
      std::holds_alternative<remill::Instruction::ConditionalInstruction>(
          res_cat->first)) {
    LOG(FATAL)
        << "Should always emit branch taken var for conditional instruction";
  }

  inst.SetLifter(std::make_shared<SleighLifterWithState>(
      res_cat->second, std::move(context_values), this->GetLifter()));
  CHECK(inst.GetLifter() != nullptr);
  return res_cat.has_value();
}


SleighDecoder::SleighDecoder(
    const remill::Arch &arch_, std::string sla_name, std::string pspec_name,
    ContextRegMappings context_reg_map_,
    std::unordered_map<std::string, std::string> state_reg_map_)
    : sleigh_ctx(sla_name, pspec_name),
      sla_name(std::move(sla_name)),
      pspec_name(std::move(pspec_name)),
      lifter(nullptr),
      arch(arch_),
      context_reg_mapping(std::move(context_reg_map_)),
      state_reg_remappings(std::move(state_reg_map_)) {}


const ContextRegMappings &SleighDecoder::GetContextRegisterMapping() const {
  return this->context_reg_mapping;
}

const std::unordered_map<std::string, std::string> &
SleighDecoder::GetStateRegRemappings() const {
  return this->state_reg_remappings;
}

std::optional<
    std::pair<Instruction::InstructionFlowCategory, MaybeBranchTakenVar>>
SleighDecoder::DecodeInstructionImpl(uint64_t address,
                                     std::string_view instr_bytes,
                                     Instruction &inst,
                                     DecodingContext curr_context) {

  // The SLEIGH engine will query this image when we try to decode an instruction. Append the bytes so SLEIGH has data to read.


  // Now decode the instruction.
  this->sleigh_ctx.resetContext();
  this->InitializeSleighContext(address, this->sleigh_ctx,
                                curr_context.GetContextValues());
  PcodeDecoder pcode_handler(this->sleigh_ctx.GetEngine());


  inst.arch = &this->arch;
  inst.bytes = instr_bytes;
  inst.arch_name = this->arch.arch_name;
  inst.sub_arch_name = this->arch.arch_name;
  inst.branch_taken_arch_name = ArchName::kArchInvalid;
  inst.pc = address;
  inst.category = Instruction::kCategoryInvalid;

  auto instr_len =
      this->sleigh_ctx.oneInstruction(address, pcode_handler, inst.bytes);

  if (!instr_len || instr_len > instr_bytes.size()) {
    return std::nullopt;
  }
  // communicate the size back to the caller
  inst.bytes = instr_bytes.substr(0, *instr_len);
  assert(inst.bytes.size() == instr_len);

  InstructionFunctionSetter setter(inst);

  this->sleigh_ctx.oneInstruction(address, setter, inst.bytes);
  uint64_t fallthrough = address + *instr_len;
  inst.next_pc = fallthrough;

  ControlFlowStructureAnalysis analysis(
      this->context_reg_mapping.GetInternalRegMapping(),
      this->sleigh_ctx.GetEngine());


  auto cat =
      analysis.ComputeCategory(pcode_handler.ops, fallthrough, curr_context);
  if (!cat) {
    LOG(ERROR) << "Failed to compute category for inst at " << std::hex
               << inst.pc;
    inst.flows = Instruction::InvalidInsn();
    inst.category = Instruction::Category::kCategoryInvalid;
    return std::nullopt;
  }

  inst.flows = cat->first;

  this->ApplyFlowToInstruction(inst);

  DLOG(INFO) << "Fallthrough: " << fallthrough;
  DLOG(INFO) << "Decoded as " << inst.Serialize();

  return cat;
}


const std::string &SleighDecoder::GetSLAName() const {
  return this->sla_name;
}


const std::string &SleighDecoder::GetPSpec() const {
  return this->pspec_name;
}

Sleigh &SingleInstructionSleighContext::GetEngine() {
  return this->engine;
}

ContextDatabase &SingleInstructionSleighContext::GetContext() {
  return this->ctx;
}

void SingleInstructionSleighContext::resetContext() {
  this->engine.reset(&this->image, &this->ctx);
  this->restoreEngineFromStorage();
}

std::optional<int32_t> SingleInstructionSleighContext::oneInstruction(
    uint64_t address, const std::function<int32_t(Address addr)> &decode_func,
    std::string_view instr_bytes) {
  this->image.SetInstruction(address, instr_bytes);
  try {
    const int32_t instr_len = decode_func(this->GetAddressFromOffset(address));

    if (instr_len > 0 &&
        static_cast<size_t>(instr_len) <= instr_bytes.length()) {
      return instr_len;
    } else {
      LOG(ERROR) << "Instr too long " << instr_len << " vs "
                 << instr_bytes.length();
      return std::nullopt;
    }
  } catch (BadDataError e) {
    LOG(ERROR) << "Bad data error: " << e.explain;
    // NOTE (Ian): if sleigh cant find a constructor it throws an exception... yay for unrolling.
    return std::nullopt;
  } catch (UnimplError e) {
    // NOTE(Ian): Similar... except sleigh did decode we just dont have pcode semantics. unfortunately since we rely on those to correctly decode
    // the remill instruction we need to treat it as a decoding failure.
    std::stringstream ss;
    for (auto bt : instr_bytes) {
      ss << std::hex << (int) bt;
    }

    LOG(ERROR) << "Unimplemented error: " << ss.str();
    return std::nullopt;
  }
}

// TODO(Ian): do with templates?.
std::optional<int32_t> SingleInstructionSleighContext::oneInstruction(
    uint64_t address, PcodeEmit &handler, std::string_view instr_bytes) {
  return this->oneInstruction(
      address,
      [this, &handler](Address addr) {
        return this->engine.oneInstruction(handler, addr);
      },
      instr_bytes);
}

std::optional<int32_t> SingleInstructionSleighContext::oneInstruction(
    uint64_t address, AssemblyEmit &handler, std::string_view instr_bytes) {
  return this->oneInstruction(
      address,
      [this, &handler](Address addr) {
        return this->engine.printAssembly(handler, addr);
      },
      instr_bytes);
}


namespace {

template <typename... Ts>  // (7)
struct Overload : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
Overload(Ts...) -> Overload<Ts...>;

}  // namespace


const std::unordered_map<std::string, size_t> &
ContextRegMappings::GetSizeMapping() const {
  return this->vnode_size_mapping;
}

const std::unordered_map<std::string, std::string> &
ContextRegMappings::GetInternalRegMapping() const {
  return this->context_reg_mapping;
}

void SleighDecoder::ApplyFlowToInstruction(remill::Instruction &inst) const {


  auto applyer = Overload{
      [&inst](const remill::Instruction::NormalInsn &cat) -> void {
        inst.category = remill::Instruction::Category::kCategoryNormal;
      },
      [&inst](const remill::Instruction::NoOp &cat) {
        inst.category = remill::Instruction::Category::kCategoryNoOp;
      },
      [&inst](const remill::Instruction::InvalidInsn &cat) {
        inst.category = remill::Instruction::Category::kCategoryInvalid;
      },
      [&inst](const remill::Instruction::ErrorInsn &cat) {
        inst.category = remill::Instruction::Category::kCategoryError;
      },
      [&inst](const remill::Instruction::DirectJump &cat) {
        inst.category = remill::Instruction::Category::kCategoryDirectJump;
        inst.branch_taken_pc = cat.taken_flow.known_target;
      },
      [&inst](const remill::Instruction::IndirectJump &cat) {
        inst.category = remill::Instruction::Category::kCategoryIndirectJump;
      },
      [&inst](const remill::Instruction::DirectFunctionCall &cat) {
        // TODO(Ian) maybe add a return_to_flow for function call flows
        inst.branch_not_taken_pc = inst.next_pc;
        inst.branch_taken_pc = cat.taken_flow.known_target;
        inst.category =
            remill::Instruction::Category::kCategoryDirectFunctionCall;
      },
      [&inst](const remill::Instruction::IndirectFunctionCall &cat) {
        inst.branch_not_taken_pc = inst.next_pc;
        inst.category =
            remill::Instruction::Category::kCategoryIndirectFunctionCall;
      },
      [&inst](const remill::Instruction::FunctionReturn &cat) {
        inst.category = remill::Instruction::Category::kCategoryFunctionReturn;
      },
      [&inst](const remill::Instruction::AsyncHyperCall &cat) {
        inst.category = remill::Instruction::Category::kCategoryAsyncHyperCall;
      },
      [&inst](const remill::Instruction::ConditionalInstruction &cat) {
        // TODO(Ian)
        inst.branch_not_taken_pc = inst.next_pc;

        auto conditional_applyer = Overload{
            [&inst](
                const remill::Instruction::DirectFunctionCall &cat) -> void {
              inst.branch_not_taken_pc = inst.next_pc;
              inst.branch_taken_pc = cat.taken_flow.known_target;
              inst.category = remill::Instruction::Category::
                  kCategoryConditionalDirectFunctionCall;
            },
            [&inst](const remill::Instruction::IndirectFunctionCall &cat) {
              inst.category = remill::Instruction::Category::
                  kCategoryConditionalIndirectFunctionCall;
              inst.branch_not_taken_pc = inst.next_pc;
            },
            [&inst](const remill::Instruction::FunctionReturn &cat) {
              inst.category = remill::Instruction::Category::
                  kCategoryConditionalFunctionReturn;
              inst.branch_not_taken_pc = inst.next_pc;
            },
            [&inst](const remill::Instruction::AsyncHyperCall &cat) {
              inst.category = remill::Instruction::Category::
                  kCategoryConditionalAsyncHyperCall;
              inst.branch_not_taken_pc = inst.next_pc;
            },
            [&inst](const remill::Instruction::IndirectJump &cat) {
              inst.category = remill::Instruction::Category::
                  kCategoryConditionalIndirectJump;
              inst.branch_not_taken_pc = inst.next_pc;
            },
            [&inst](const remill::Instruction::DirectJump &cat) {
              inst.category =
                  remill::Instruction::Category::kCategoryConditionalBranch;
              inst.branch_taken_pc = cat.taken_flow.known_target;
              inst.branch_not_taken_pc = inst.next_pc;
            }};

        std::visit(conditional_applyer, cat.taken_branch);
      },
  };

  std::visit(applyer, inst.flows);
}

uint64_t GetContextRegisterValue(const char *remill_reg_name,
                                 uint64_t default_value,
                                 const ContextValues &context_values) {
  const auto iter = context_values.find(remill_reg_name);
  if (iter != context_values.end()) {
    return iter->second;
  }
  return default_value;
}


void SetContextRegisterValueInSleigh(
    uint64_t addr, const char *remill_reg_name, const char *sleigh_reg_name,
    uint64_t default_value, sleigh::SingleInstructionSleighContext &ctxt,
    const ContextValues &context_values) {
  auto value =
      GetContextRegisterValue(remill_reg_name, default_value, context_values);
  ctxt.GetContext().setVariable(sleigh_reg_name,
                                ctxt.GetAddressFromOffset(addr), value);
}


}  // namespace remill::sleigh
