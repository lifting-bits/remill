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

static bool isVarnodeInConstantSpace(VarnodeData vnode) {
  auto spc = vnode.getAddr().getSpace();
  return spc->constant_space_index == spc->getIndex();
}


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


static Instruction::InstructionFlowCategory
computeCategory(const std::vector<PcodeOp> &ops, uint64_t fallthrough_addr,
                DecodingContext entry_context) {
  throw std::logic_error("Function not yet implemented");
}

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
                        VarnodeData *vars, int32_t isize) {}

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

  auto pspec_path = ::sleigh::FindSpecFile(pspec_name.c_str());

  if (!pspec_path) {
    LOG(FATAL) << "Couldn't find required spec file: " << sla_name << '\n';
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
  if (const Element *spec_xml = storage.getTag("processor_spec")) {
    for (const Element *spec_element : spec_xml->getChildren()) {
      if (spec_element->getName() == "context_data") {
        LOG(INFO) << "Restoring from pspec context data";
        ctx.restoreFromSpec(spec_element, &engine);
        break;
      }
    }
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

Arch::DecodingResult
SleighDecoder::DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                                 Instruction &inst,
                                 DecodingContext context) const {
  inst.SetLifter(this->GetLifter());
  assert(inst.GetLifter() != nullptr);

  return const_cast<SleighDecoder *>(this)->DecodeInstructionImpl(
      address, instr_bytes, inst, std::move(context));
}


SleighDecoder::SleighDecoder(
    const remill::Arch &arch_, std::string sla_name, std::string pspec_name,
    std::unordered_map<std::string, std::string> reg_map_)
    : sleigh_ctx(sla_name, pspec_name),
      sla_name(sla_name),
      pspec_name(pspec_name),
      lifter(nullptr),
      arch(arch_),
      register_mapping(reg_map_) {}

Arch::DecodingResult SleighDecoder::DecodeInstructionImpl(
    uint64_t address, std::string_view instr_bytes, Instruction &inst,
    DecodingContext curr_context) {

  // The SLEIGH engine will query this image when we try to decode an instruction. Append the bytes so SLEIGH has data to read.


  // Now decode the instruction.
  this->sleigh_ctx.resetContext();
  this->InitializeSleighContext(this->sleigh_ctx);
  PcodeDecoder pcode_handler(this->sleigh_ctx.GetEngine());

  LOG(INFO) << "Provided insn size: " << instr_bytes.size();

  inst.Reset();
  inst.arch = &this->arch;
  inst.bytes = instr_bytes;
  inst.arch_name = this->arch.arch_name;
  inst.sub_arch_name = this->arch.arch_name;
  inst.branch_taken_arch_name = ArchName::kArchInvalid;
  inst.pc = address;
  inst.category = Instruction::kCategoryInvalid;

  auto instr_len =
      this->sleigh_ctx.oneInstruction(address, pcode_handler, instr_bytes);

  if (!instr_len || instr_len > instr_bytes.size()) {
    return std::nullopt;
  }
  // communicate the size back to the caller
  inst.bytes = instr_bytes.substr(0, *instr_len);
  assert(inst.bytes.size() == instr_len);

  InstructionFunctionSetter setter(inst);

  this->sleigh_ctx.oneInstruction(address, setter, inst.bytes);
  LOG(INFO) << "Instr len:" << *instr_len;
  LOG(INFO) << "Addr: " << address;
  auto fallthrough = address + *instr_len;
  inst.next_pc = fallthrough;
  inst.flows = computeCategory(pcode_handler.ops, fallthrough, curr_context);
  LOG(INFO) << "Fallthrough: " << fallthrough;
  LOG(INFO) << "Decoded as " << inst.Serialize();

  return DecodingContext::UniformContextMapping(curr_context);
}


std::string SleighDecoder::GetSLAName() const {
  return this->sla_name;
}


std::string SleighDecoder::GetPSpec() const {
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
    LOG(ERROR) << "Bad data error";
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


ContextUpdater::ContextUpdater(
    DecodingContext curr_context_,
    const std::unordered_map<std::string, std::string> &register_mapping_,
    Sleigh &engine_)
    : is_inter_procedural(false),
      curr_context(curr_context_),
      prev_context(std::move(curr_context_)),
      register_mapping(register_mapping_),
      engine(engine_) {}

void ContextUpdater::dump(const Address &addr, OpCode opc, VarnodeData *outvar,
                          VarnodeData *vars, int4 isize) {

  if (opc == OpCode::CPUI_CALL || opc == OpCode::CPUI_CALLIND) {
    this->is_inter_procedural = true;
  }

  // So we are updating a variable, if it's a target we either need to give it a new constant value or drop it to nonconstant
  if (!outvar) {
    return;
  }

  auto outvar_name =
      this->engine.getRegisterName(outvar->space, outvar->offset, outvar->size);
  auto target_remill_cont_reg = this->register_mapping.find(outvar_name);
  if (target_remill_cont_reg == this->register_mapping.end()) {
    return;
  }

  if (this->already_assigned.find(target_remill_cont_reg->second) !=
          this->already_assigned.end() ||
      !(opc == OpCode::CPUI_COPY && isVarnodeInConstantSpace(vars[0]))) {
    LOG(INFO) << "Dropping " << target_remill_cont_reg->second;
    this->curr_context.DropReg(target_remill_cont_reg->second);
    return;
  }


  this->curr_context.UpdateContextReg(target_remill_cont_reg->second,
                                      vars[0].offset);

  return;
}

DecodingContext ContextUpdater::GetContext() const {
  LOG(INFO) << "Getting context updater value";
  if (this->is_inter_procedural) {
    return this->prev_context;
  }
  return this->curr_context;
}

}  // namespace remill::sleigh
