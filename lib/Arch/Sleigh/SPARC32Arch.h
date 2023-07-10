#include <remill/Arch/SPARC32/SPARC32Base.h>

#include "Arch.h"

namespace remill {

class SleighSPARC32Decoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighSPARC32Decoder(const remill::Arch &arch);


  virtual llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &bldr, llvm::Value *,
                                        size_t curr_insn_size,
                                        const DecodingContext &) const final;

  void
  InitializeSleighContext(uint64_t addr,
                          remill::sleigh::SingleInstructionSleighContext &ctxt,
                          const ContextValues &context_values) const final;
};

class SPARC32Arch final : public SPARC32ArchBase {
 public:
  SPARC32Arch(llvm::LLVMContext *context_, OSName os_name_,
              ArchName arch_name_);

  virtual ~SPARC32Arch(void);


  virtual DecodingContext CreateInitialContext(void) const override;

  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst,
                         DecodingContext context) const override;


  OperandLifter::OpLifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const override;

  SPARC32Arch(void) = delete;

 private:
  SleighSPARC32Decoder decoder;
};

}  // namespace remill
