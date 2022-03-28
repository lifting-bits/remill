#include <glog/logging.h>
#include <remill/Arch/Sleigh/SleighArch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/SleighLifter.h>

#include <unordered_map>
namespace remill {


class SleighLifter::PcodeToLLVMEmitIntoBlock : public PcodeEmit {
 private:
  llvm::BasicBlock *target_block;
  llvm::Value *state_pointer;
  llvm::LLVMContext &context;
  const Instruction &insn;
  LiftStatus status;
  SleighLifter &insn_lifter_parent;
  std::unordered_map<uint64_t, llvm::Value *> cached_unique_ptrs;


  void UpdateStatus(LiftStatus new_status, OpCode opc) {
    if (new_status != LiftStatus::kLiftedInstruction) {
      LOG(ERROR) << "Failed to lift insn with opcode: " << get_opname(opc);
      this->status = new_status;
    } else if (status == LiftStatus::kLiftedInvalidInstruction) {
      this->status = new_status;
    }
  }

 public:
  PcodeToLLVMEmitIntoBlock(llvm::BasicBlock *target_block,
                           llvm::Value *state_pointer, const Instruction &insn,
                           SleighLifter &insn_lifter_parent)
      : target_block(target_block),
        state_pointer(state_pointer),
        context(target_block->getContext()),
        insn(insn),
        status(remill::LiftStatus::kLiftedInvalidInstruction),
        insn_lifter_parent(insn_lifter_parent){};


  llvm::Value *GetUniquePtr(uint64_t offset, uint64_t size,
                            llvm::IRBuilder<> &bldr) {
    if (this->cached_unique_ptrs.find(offset) !=
        this->cached_unique_ptrs.end()) {
      return this->cached_unique_ptrs.find(offset)->second;
    }
    assert(size % 8 == 0);
    auto ptr = bldr.CreateAlloca(
        llvm::IntegerType::get(this->context, size / 8), 0, nullptr);
    this->cached_unique_ptrs.insert({offset, ptr});
    return ptr;
  }

  //TODO(Ian): Maybe this should be a failable function that returns an unsupported insn in certain failures
  llvm::Value *LiftParamPtr(llvm::IRBuilder<> &bldr, VarnodeData vnode) {
    auto space_name = vnode.getAddr().getSpace()->getName();
    if (space_name == "ram") {
      const auto mem_ptr_ref = this->insn_lifter_parent.LoadRegAddress(
          this->target_block, this->state_pointer, kMemoryVariableName);
      // compute pointer into memory at offset
      return bldr.CreateConstGEP1_64(llvm::IntegerType::get(this->context, 8),
                                     mem_ptr_ref, vnode.getAddr().getOffset());
    } else if (space_name == "register") {
      auto reg_name = this->insn_lifter_parent.GetEngine().getRegisterName(
          vnode.space, vnode.offset, vnode.size);
      LOG(INFO) << "Looking for reg name " << reg_name << " from offset "
                << vnode.offset;
      // TODO(Ian): will probably need to adjust the pointer here in certain circumstances
      return this->insn_lifter_parent.LoadRegAddress(
          bldr.GetInsertBlock(), this->state_pointer, reg_name);
    } else if (space_name == "const") {
      return llvm::ConstantInt::get(this->insn_lifter_parent.GetWordType(),
                                    vnode.offset);
    } else if (space_name == "unique") {
      return this->GetUniquePtr(vnode.offset, vnode.size, bldr);
    } else {
      LOG(FATAL) << "Unhandled memory space: " << space_name;
    }
  }

  llvm::Value *LiftInParam(llvm::IRBuilder<> &bldr, VarnodeData vnode,
                           llvm::Type *ty) {
    llvm::Value *ptr = this->LiftParamPtr(bldr, vnode);
    return bldr.CreateLoad(ty, ptr);
  }

  LiftStatus
  LiftRequireOutParam(std::function<LiftStatus(VarnodeData)> inner_lift,
                      VarnodeData *outvar) {
    if (outvar) {
      return inner_lift(*outvar);
    } else {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }
  }


  LiftStatus LiftStoreIntoOutParam(llvm::IRBuilder<> &bldr,
                                   llvm::Value *inner_lifted,
                                   VarnodeData *outvar) {
    return this->LiftRequireOutParam(
        [&bldr, this, inner_lifted](VarnodeData out_param_data) {
          auto ptr = this->LiftParamPtr(bldr, out_param_data);
          bldr.CreateStore(inner_lifted, ptr);
          return LiftStatus::kLiftedInstruction;
        },
        outvar);
  }


  LiftStatus LiftUnOp(llvm::IRBuilder<> &bldr, OpCode opc, VarnodeData *outvar,
                      VarnodeData input_var) {
    // TODO(Ian): when we lift a param we need to specify the type we want


    switch (opc) {
      case OpCode::CPUI_BOOL_NEGATE:
        auto inval = this->LiftInParam(
            bldr, input_var, llvm::IntegerType::get(this->context, 8));
        return this->LiftStoreIntoOutParam(bldr, bldr.CreateNot(inval), outvar);
    }
    return LiftStatus::kLiftedUnsupportedInstruction;
  }

  LiftStatus LiftBinOp(llvm::IRBuilder<> &bldr, OpCode opc, VarnodeData *outvar,
                       VarnodeData lhs, VarnodeData rhs) {
    return LiftStatus::kLiftedUnsupportedInstruction;
  }


  void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
            VarnodeData *vars, int4 isize) override {
    llvm::IRBuilder bldr(this->target_block);
    switch (isize) {
      case 1:
        this->UpdateStatus(this->LiftUnOp(bldr, opc, outvar, vars[0]), opc);
        break;
      case 2:
        this->UpdateStatus(this->LiftBinOp(bldr, opc, outvar, vars[0], vars[1]),
                           opc);
        break;
    }
  }

  LiftStatus GetStatus() {
    return this->status;
  }
};

LiftStatus
SleighLifter::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                            llvm::Value *state_ptr, bool is_delayed) {

  if (!inst.IsValid()) {
    LOG(ERROR) << "Invalid function" << inst.Serialize();
    inst.operands.clear();
    return kLiftedInvalidInstruction;
  }

  SleighLifter::PcodeToLLVMEmitIntoBlock lifter(block, state_ptr, inst, *this);
  auto res = this->sleigh_context.oneInstruction(lifter, inst.bytes);

  //NOTE(Ian): If we made it past decoding we should be able to decode the bytes again
  assert(res.has_value());

  return lifter.GetStatus();
}

Sleigh &SleighLifter::GetEngine() {
  return this->sleigh_context.GetEngine();
}
}  // namespace remill