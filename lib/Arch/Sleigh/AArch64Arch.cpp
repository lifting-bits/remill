#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"
// clang-format off
#include <remill/Arch/AArch64/Runtime/State.h>

// clang-format on

#include <remill/Arch/ArchBase.h>  // For `ArchImpl`.

#include "AArch64Arch.h"

namespace remill {

// TODO(Ian): support different arm versions
SleighAArch64Decoder::SleighAArch64Decoder(const remill::Arch &arch)
    : SleighDecoder(arch, "AARCH64.sla", "AARCH64.pspec",
                    sleigh::ContextRegMappings({}, {}),
                    {{"CY", "C"}, {"NG", "N"}, {"ZR", "Z"}, {"OV", "V"}}) {}


void SleighAArch64Decoder::InitializeSleighContext(
    uint64_t addr, remill::sleigh::SingleInstructionSleighContext &ctxt,
    const ContextValues &values) const {}

llvm::Value *SleighAArch64Decoder::LiftPcFromCurrPc(
    llvm::IRBuilder<> &bldr, llvm::Value *curr_pc, size_t curr_insn_size,
    const DecodingContext &context) const {
  return bldr.CreateAdd(curr_pc, llvm::ConstantInt::get(curr_pc->getType(), 4));
}

AArch64Arch::AArch64Arch(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_),
      AArch64ArchBase(context_, os_name_, arch_name_),
      decoder(*this) {}

AArch64Arch::~AArch64Arch(void) {}

OperandLifter::OpLifterPtr AArch64Arch::DefaultLifter(
    const remill::IntrinsicTable &intrinsics_table) const {
  return std::make_shared<InstructionLifter>(this, intrinsics_table);
}

bool AArch64Arch::DecodeInstruction(uint64_t address,
                                    std::string_view inst_bytes,
                                    Instruction &inst,
                                    DecodingContext context) const {
  inst.pc = address;
  inst.next_pc = address + inst_bytes.size();  // Default fall-through.
  inst.branch_taken_pc = 0;
  inst.branch_not_taken_pc = 0;
  inst.has_branch_taken_delay_slot = false;
  inst.has_branch_not_taken_delay_slot = false;
  inst.arch_name = arch_name;
  inst.sub_arch_name = arch_name;
  inst.branch_taken_arch_name = arch_name;
  inst.arch = this;
  inst.category = Instruction::kCategoryInvalid;
  inst.operands.clear();
  inst.flows = Instruction::InvalidInsn();

  return this->decoder.DecodeInstruction(address, inst_bytes, inst, context);
}

DecodingContext AArch64Arch::CreateInitialContext(void) const {
  return DecodingContext();
}


// TODO(pag): We pretend that these are singletons, but they aren't really!
Arch::ArchPtr Arch::GetAArch64Sleigh(llvm::LLVMContext *context_,
                                     OSName os_name_, ArchName arch_name_) {
  return std::make_unique<AArch64Arch>(context_, os_name_, arch_name_);
}


}  // namespace remill