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


#include <glog/logging.h>
#include <remill/Arch/Sleigh/SleighArch.h>
#include <remill/BC/SleighLifter.h>
namespace remill::sleigh {

namespace {


class AssemblyLogger : public AssemblyEmit {
  void dump(const Address &addr, const string &mnem, const string &body) {
    LOG(INFO) << "Decoded: " << mnem << " " << body;
  }
};
}  // namespace

PcodeDecoder::PcodeDecoder(Sleigh &engine_, Instruction &inst_)
    : engine(engine_),
      inst(inst_) {}


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
  inst.function = get_opname(op);

  std::stringstream ss;

  ss << get_opname(op);
  if (outvar) {
    print_vardata(ss, *outvar);
    ss << " = ";
    DecodeOperand(*outvar);
  }
  for (int i = 0; i < isize; ++i) {
    print_vardata(ss, vars[i]);
    DecodeOperand(vars[i]);
  }
  LOG(INFO) << "Pcode: " << ss.str();
  DecodeCategory(op, vars, isize);
}

void PcodeDecoder::DecodeOperand(VarnodeData &var) {
  const auto loc_name = var.space->getName();
  if (loc_name == "register") {
    DecodeRegister(var);
  } else if (loc_name == "unique") {
    DecodeMemory(var);
  } else if (loc_name == "ram") {
    DecodeMemory(var);
  } else if (loc_name == "const") {
    DecodeConstant(var);
  } else {
    LOG(FATAL) << "Instruction location " << loc_name << " not supported";
  }
}

void PcodeDecoder::DecodeRegister(const VarnodeData &var) {
  const auto reg_name = engine.getRegisterName(var.space, var.offset, var.size);
  Operand op;
  op.type = Operand::kTypeRegister;
  Operand::Register reg;
  reg.name = reg_name;
  reg.size =
      var.size;  // I don't think this is correct. Need to distinguish between the register width vs the read/write size.
  op.reg = reg;
  op.size = var.size;
  // TODO(alex): Pass information about whether its an outvar or not
  op.action = true ? Operand::kActionRead : Operand::kActionWrite;
  inst.operands.push_back(op);
}

void PcodeDecoder::DecodeMemory(const VarnodeData &var) {
  Operand op;
  op.size = var.size * 8;
  op.type = Operand::kTypeAddress;
  op.addr.address_size = 64;  // Not sure
  op.addr.kind =
      true ? Operand::Address::kMemoryRead : Operand::Address::kMemoryWrite;
  inst.operands.push_back(op);
}

void PcodeDecoder::DecodeConstant(const VarnodeData &var) {
  Operand op;
  op.type = Operand::kTypeImmediate;
  op.action = Operand::kActionRead;
  op.imm.is_signed = false;  // Not sure
  op.imm.val = var.offset;
  inst.operands.push_back(op);
}

/*
CPUI_BRANCH = 4,		///< Always branch
  CPUI_CBRANCH = 5,		///< Conditional branch
  CPUI_BRANCHIND = 6,		///< Indirect branch (jumptable)

  CPUI_CALL = 7,		///< Call to an absolute address
  CPUI_CALLIND = 8,		///< Call through an indirect address
  CPUI_CALLOTHER = 9,		///< User-defined operation
  CPUI_RETURN = 10,		///< Return from subroutine
*/

// TODO(Ian): these are kinda fake Pcode can have a lot of random stuff in the translation of an instruction,
// We are basically categorizing by the last PcodeOp.
// THis also might be a problem for operands maybe we consume them properly have to look.
void PcodeDecoder::DecodeCategory(OpCode op, VarnodeData *vars, int32_t isize) {
  if (op >= CPUI_BRANCH && op <= CPUI_RETURN) {
    if (this->current_resolver.has_value()) {
      // ok we've already seen a control flow instruction so call it an indirect branch
      this->current_resolver = InstructionFlowResolver::CreateIndirectBranch();
    }

    // TODO(Ian): we should check if we know about this address space and do something if not
    switch (op) {
      case CPUI_BRANCH:
        this->current_resolver =
            InstructionFlowResolver::CreateDirectBranch(vars[0].offset);
      case CPUI_CALL:
        this->current_resolver =
            InstructionFlowResolver::CreateDirectCall(vars[0].offset);

      case CPUI_CBRANCH:
        this->current_resolver =
            InstructionFlowResolver::CreateDirectCBranchResolver(
                vars[0].offset);
      case CPUI_BRANCHIND:
        this->current_resolver =
            InstructionFlowResolver::CreateIndirectBranch();
      case CPUI_CALLIND:
        this->current_resolver = InstructionFlowResolver::CreateIndirectCall();
      case CPUI_RETURN:
        this->current_resolver = InstructionFlowResolver::CreateIndirectRet();
    }
  }
}

InstructionFlowResolver::IFRPtr PcodeDecoder::GetResolver() {
  if (!this->current_resolver.has_value()) {
    return InstructionFlowResolver::CreateNormal();
  } else {
    return *this->current_resolver;
  }
}

InstructionFlowResolver::IFRPtr
InstructionFlowResolver::CreateDirectCBranchResolver(uint64_t target) {
  return std::make_shared<DirectCBranchResolver>(
      remill::Instruction::Category::kCategoryConditionalBranch);
}
InstructionFlowResolver::IFRPtr InstructionFlowResolver::CreateIndirectCall() {
  return std::make_shared<IndirectBranch>(
      remill::Instruction::Category::kCategoryIndirectFunctionCall);
}
InstructionFlowResolver::IFRPtr InstructionFlowResolver::CreateIndirectRet() {
  return std::make_shared<IndirectBranch>(
      remill::Instruction::Category::kCategoryFunctionReturn);
}
InstructionFlowResolver::IFRPtr
InstructionFlowResolver::CreateIndirectBranch() {
  return std::make_shared<IndirectBranch>(
      remill::Instruction::Category::kCategoryIndirectJump);
}

InstructionFlowResolver::IFRPtr
InstructionFlowResolver::CreateDirectBranch(uint64_t target) {
  return std::make_shared<DirectBranchResolver>(
      target, remill::Instruction::Category::kCategoryDirectJump);
}
InstructionFlowResolver::IFRPtr
InstructionFlowResolver::CreateDirectCall(uint64_t target) {
  return std::make_shared<DirectBranchResolver>(
      target, remill::Instruction::Category::kCategoryDirectFunctionCall);
}

InstructionFlowResolver::IFRPtr InstructionFlowResolver::CreateNormal() {
  return std::make_shared<NormalResolver>();
}

IndirectBranch::IndirectBranch(remill::Instruction::Category category)
    : category(category) {}


NormalResolver::NormalResolver() = default;

DirectBranchResolver::DirectBranchResolver(
    uint64_t target_address, remill::Instruction::Category category)
    : target_address(target_address),
      category(category) {}


DirectCBranchResolver::DirectCBranchResolver(uint64_t target_address)
    : target_address(target_address) {}

NormalResolver::~NormalResolver() = default;
DirectCBranchResolver::~DirectCBranchResolver() = default;
DirectBranchResolver::~DirectBranchResolver() = default;
IndirectBranch::~IndirectBranch() = default;

void IndirectBranch::ResolveControlFlow(uint64_t fall_through,
                                        remill::Instruction &insn) {
  insn.next_pc = 0;
  insn.category = this->category;
}


void DirectBranchResolver::ResolveControlFlow(uint64_t fall_through,
                                              remill::Instruction &insn) {
  insn.next_pc = this->target_address;
  insn.branch_taken_pc = 0;
  insn.branch_not_taken_pc = 0;
  insn.category = this->category;
}

void NormalResolver::ResolveControlFlow(uint64_t fall_through,
                                        remill::Instruction &insn) {
  insn.next_pc = fall_through;
  insn.category = remill::Instruction::Category::kCategoryNormal;
}

void DirectCBranchResolver::ResolveControlFlow(uint64_t fall_through,
                                               remill::Instruction &insn) {

  if (this->target_address == fall_through) {
    insn.next_pc = fall_through;
    insn.category = remill::Instruction::Category::kCategoryNormal;
  } else {
    insn.next_pc = 0;
    insn.branch_taken_pc = this->target_address;
    insn.branch_not_taken_pc = fall_through;
  }
}


SingleInstructionSleighContext::SingleInstructionSleighContext(
    std::string sla_name)
    : engine(&image, &ctx) {

  std::lock_guard<std::mutex> guard(
      SingleInstructionSleighContext::sleigh_parsing_mutex);
  const std::optional<std::filesystem::path> sla_path =
      ::sleigh::FindSpecFile(sla_name.c_str());
  if (!sla_path) {
    LOG(FATAL) << "Couldn't find required spec file: " << sla_name << '\n';
  }
  { LOG(INFO) << "Using spec at: " << sla_path->string(); }
  Element *root = storage.openDocument(sla_path->string())->getRoot();
  storage.registerTag(root);
  engine.initialize(storage);
  this->engine.allowContextSet(false);
}

std::mutex SingleInstructionSleighContext::sleigh_parsing_mutex;

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
  for (int i = 0; i < size; ++i) {
    uint64_t offset = start + i;
    if (offset >= this->current_offset) {
      auto index = offset - this->current_offset;
      if (index < this->current_bytes.length()) {
        ptr[i] = this->current_bytes[i];
      } else {
        ptr[i] = 0;
      }
    } else {
      ptr[i] = 0;
    }
  }
}

std::string CustomLoadImage::getArchType(void) const {
  return "custom";
}

void CustomLoadImage::adjustVma(long) {}


bool SleighArch::DecodeInstruction(uint64_t address,
                                   std::string_view instr_bytes,
                                   Instruction &inst) const {
  // TODO(Ian): Since we dont control sleigh we probably need DecodeInsn to be non const?
  return const_cast<SleighArch *>(this)->DecodeInstructionImpl(
      address, instr_bytes, inst);
}

SleighArch::SleighArch(llvm::LLVMContext *context_, OSName os_name_,
                       ArchName arch_name_, std::string sla_name)
    : Arch(context_, os_name_, arch_name_),
      sleigh_ctx(sla_name),
      sla_name(sla_name) {}

bool SleighArch::DecodeInstructionImpl(uint64_t address,
                                       std::string_view instr_bytes,
                                       Instruction &inst) {

  inst.bytes = instr_bytes;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.pc = address;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();

  // The SLEIGH engine will query this image when we try to decode an instruction. Append the bytes so SLEIGH has data to read.


  // Now decode the instruction.
  this->InitializeSleighContext(this->sleigh_ctx);
  PcodeDecoder pcode_handler(this->sleigh_ctx.GetEngine(), inst);
  auto instr_len =
      this->sleigh_ctx.oneInstruction(address, pcode_handler, instr_bytes);

  if (instr_len.has_value()) {
    auto fallthrough = address + *instr_len;
    pcode_handler.GetResolver()->ResolveControlFlow(fallthrough, inst);

    LOG(INFO) << "Decoded as " << inst.Serialize();
    return true;
  } else {
    return false;
  }
}


std::string SleighArch::GetSLAName() const {
  return this->sla_name;
}


Sleigh &SingleInstructionSleighContext::GetEngine() {
  return this->engine;
}

// TODO(Ian): handle decoding failures.
std::optional<int32_t> SingleInstructionSleighContext::oneInstruction(
    uint64_t address, PcodeEmit &handler, std::string_view instr_bytes) {

  this->image.SetInstruction(address, instr_bytes);

  try {
    const int32_t instr_len = this->engine.oneInstruction(
        handler, this->GetAddressFromOffset(address));


    if (instr_len > 0 &&
        static_cast<size_t>(instr_len) <= instr_bytes.length()) {
      //AssemblyLogger logger;
      //this->engine.printAssembly(logger, this->GetAddressFromOffset(address));
      return instr_len;
    } else {
      return std::nullopt;
    }
  } catch (BadDataError e) {
    LOG(ERROR) << "Bad data error";
    // NOTE (Ian): if sleigh cant find a constructor it throws an exception... yay for unrolling.
    return std::nullopt;
  } catch (UnimplError e) {
    // NOTE(Ian): Similar... except sleigh did decode we just dont have pcode semantics. unfortunately since we rely on those to correctly decode
    // the remill instruction we need to treat it as a decoding failure.
    LOG(ERROR) << "Unimplemented error";
    return std::nullopt;
  }
}


InstructionLifter::LifterPtr
SleighArch::GetLifter(const remill::IntrinsicTable &intrinsics) const {
  return std::make_unique<SleighLifter>(this, intrinsics);
}

}  // namespace remill::sleigh