#include <remill/Arch/Sleigh/SleighArch.h>
#include <remill/BC/SleighLifter.h>
namespace remill {


namespace {

class PcodeToLLVMEmitIntoBlock : public PcodeEmit {
 private:
  llvm::BasicBlock *target_block;
  llvm::Value *state_pointer;
  const Instruction &insn;
  LiftStatus status;

 public:
  PcodeToLLVMEmitIntoBlock(llvm::BasicBlock *target_block,
                           llvm::Value *state_pointer, const Instruction &insn)
      : target_block(target_block),
        state_pointer(state_pointer),
        insn(insn),
        status(remill::LiftStatus::kLiftedInvalidInstruction){};

  void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
            VarnodeData *vars, int4 isize) override {}

  LiftStatus GetStatus() {
    return this->status;
  }
};
}  // namespace

LiftStatus
SleighLifter::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                            llvm::Value *state_ptr, bool is_delayed) {

  if (!inst.IsValid()) {
    LOG(ERROR) << "Invalid function" << inst.Serialize();
    inst.operands.clear();
    return kLiftedInvalidInstruction;
  }

  PcodeToLLVMEmitIntoBlock lifter(block, state_ptr, inst);
  auto res = this->sleigh_context.oneInstruction(lifter, inst.bytes);

  //NOTE(Ian): If we made it past decoding we should be able to decode the bytes again
  assert(res.has_value());

  return lifter.GetStatus();
}
}  // namespace remill