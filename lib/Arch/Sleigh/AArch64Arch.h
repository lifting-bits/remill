#include <remill/Arch/AArch64/AArch64Base.h>

#include "Arch.h"

namespace remill {

class SleighAArch64Decoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighAArch64Decoder(const remill::Arch &arch);


  virtual llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *,
                                        size_t curr_insn_size,
                                        const DecodingContext &) const final;

  void
  InitializeSleighContext(uint64_t addr,
                          remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &context_values) const final;
};

class AArch64Arch final : public AArch64ArchBase {
 public:
  AArch64Arch(llvm::LLVMContext *context_, OSName os_name_,
              ArchName arch_name_);

  virtual ~AArch64Arch(void);


  void PopulateRegisterTable(void) const override;

  virtual DecodingContext CreateInitialContext(void) const override;

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const override;


  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override;

  AArch64Arch(void) = delete;

 private:
  SleighAArch64Decoder decoder;
};

}  // namespace remill
