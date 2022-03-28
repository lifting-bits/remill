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

namespace remill::sleigh {


PcodeDecoder::PcodeDecoder(Sleigh &engine_, Instruction &inst_)
    : engine(engine_),
      inst(inst_) {}

void PcodeDecoder::dump(const Address &, OpCode op, VarnodeData *outvar,
                        VarnodeData *vars, int32_t isize) {
  inst.function = get_opname(op);
  if (outvar) {
    DecodeOperand(*outvar);
  }
  for (int i = 0; i < isize; ++i) {
    DecodeOperand(vars[i]);
  }

  DecodeCategory(op);
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

// TODO(Ian): these are kinda fake Pcode can have a lot of random stuff in the translation of an instruction,
// We are basically categorizing by the last PcodeOp.
// THis also might be a problem for operands maybe we consume them properly have to look.
void PcodeDecoder::DecodeCategory(OpCode op) {
  switch (op) {
    case CPUI_INT_LESS:
    case CPUI_INT_SLESS:
    case CPUI_INT_EQUAL:
    case CPUI_INT_SUB:
    case CPUI_INT_SBORROW:
    case CPUI_INT_AND:
    case CPUI_BOOL_NEGATE:
    case CPUI_INT_RIGHT:
    case CPUI_SUBPIECE:
    case CPUI_COPY:
    case CPUI_POPCOUNT: inst.category = Instruction::kCategoryNormal; break;
    // NOTE(Ian): Cbranch semantics are kinda tricky. The varnode passed as an input to the branch defines the address
    // and address space to jump to. The varnode isnt a variable. Constant address spaces are treated specially and reslt in a relative
    // jump within the pcode list for this instruction. We should probably examine the cbranch params and if it is a constant adress space then this isntruction is basically normal.
    case CPUI_CBRANCH:
      inst.category = Instruction::kCategoryConditionalBranch;
      break;
    default:
      LOG(FATAL) << "Unsupported p-code opcode " << get_opname(op);
      break;
  }
}

SingleInstructionSleighContext::SingleInstructionSleighContext(
    std::string sla_name)
    : engine(&image, &ctx) {
  DocumentStorage storage;
  const std::optional<std::filesystem::path> sla_path =
      ::sleigh::FindSpecFile(sla_name.c_str());
  if (!sla_path) {
    LOG(FATAL) << "Couldn't find required spec file: " << sla_name << '\n';
  }
  Element *root = storage.openDocument(sla_path->string())->getRoot();
  storage.registerTag(root);
  engine.initialize(storage);

  // This needs to happen after engine initialization
  cur_addr = Address(engine.getDefaultCodeSpace(), 0x0);
}


CustomLoadImage::CustomLoadImage(void) : LoadImage("nofile") {}

void CustomLoadImage::AppendInstruction(std::string_view instr_bytes) {
  image_buffer.append(instr_bytes);
}

void CustomLoadImage::loadFill(unsigned char *ptr, int size,
                               const Address &addr) {
  uint8_t start = addr.getOffset();
  for (int i = 0; i < size; ++i) {
    uint64_t offset = start + i;
    ptr[i] = offset < image_buffer.size() ? image_buffer[i] : 0;
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
      sleigh_ctx(sla_name) {}

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
  PcodeDecoder pcode_handler(this->sleigh_ctx.GetEngine(), inst);
  auto instr_len = this->sleigh_ctx.oneInstruction(pcode_handler, instr_bytes);

  if (instr_len.has_value()) {
    inst.next_pc = address + *instr_len;
    return true;
  } else {
    return false;
  }
}


Sleigh &SingleInstructionSleighContext::GetEngine() {
  return this->engine;
}

// TODO(Ian): handle decoding failures.
std::optional<int32_t>
SingleInstructionSleighContext::oneInstruction(PcodeEmit &handler,
                                               std::string_view instr_bytes) {
  this->image.AppendInstruction(instr_bytes);
  const int32_t instr_len =
      this->engine.oneInstruction(handler, this->cur_addr);

  this->cur_addr = cur_addr + instr_len;
  return instr_len;
}


}  // namespace remill::sleigh