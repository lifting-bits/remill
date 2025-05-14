/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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
#include <lib/Arch/Sleigh/Arch.h>
#include <lib/Arch/Sleigh/ControlFlowStructuring.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <remill/Arch/Context.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/Runtime/HyperCall.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/PCodeCFG.h>
#include <remill/BC/SleighLifter.h>
#include <remill/BC/Util.h>

#include <array>
#include <cassert>
#include <optional>
#include <sleigh/pcoderaw.hh>
#include <sleigh/sleigh.hh>
#include <sleigh/space.hh>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>


namespace remill {


namespace {


void print_vardata(Sleigh &engine, std::stringstream &s, VarnodeData &data) {
  s << '(' << data.space->getName() << ',';
  data.space->printOffset(s, data.offset);
  s << ',' << dec << data.size << ')';
  auto maybe_name = engine.getRegisterName(data.space, data.offset, data.size);
  if (!maybe_name.empty()) {
    s << ":" << maybe_name;
  }
}
std::string DumpPcode(Sleigh &engine, const remill::sleigh::RemillPcodeOp &op) {
  std::stringstream ss;
  ss << get_opname(op.op);
  if (op.outvar) {
    auto ov = *op.outvar;
    print_vardata(engine, ss, ov);
    ss << " = ";
  }
  for (size_t i = 0; i < op.vars.size(); ++i) {
    ss << ' ';
    auto iv = op.vars[i];
    print_vardata(engine, ss, iv);
  }
  return ss.str();
}

static size_t kBranchTakenArgNum = 2;
static size_t kNextPcArgNum = 3;


static const std::string kEqualityClaimName = "claim_eq";
static const std::string kSysCallName = "syscall";
static const std::string kSetCopRegName = "setCopReg";

static bool isVarnodeInConstantSpace(VarnodeData vnode) {
  auto spc = vnode.getAddr().getSpace();
  return spc->getType() == IPTR_CONSTANT;
}

static llvm::Value *ExtractOverflowBitFromCallToIntrinsic(
    llvm::Intrinsic::IndependentIntrinsics intrinsic, llvm::Value *lhs,
    llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
  llvm::Type *overloaded_types[1] = {lhs->getType()};
  llvm::Function *target_instrinsic = llvm::Intrinsic::getDeclaration(
      bldr.GetInsertBlock()->getModule(), intrinsic, overloaded_types);
  std::array<llvm::Value *, 2> intrinsic_args = {lhs, rhs};
  llvm::Value *res_val = bldr.CreateCall(target_instrinsic, intrinsic_args);
  // The value at index 1 is the overflow bit.
  return bldr.CreateExtractValue(res_val, {1});
}

using BitShiftFunction = std::function<llvm::Value *(
    llvm::Value *, llvm::Value *, llvm::IRBuilder<> &)>;

llvm::Value *CreatePcodeBitShift(llvm::Value *lhs, llvm::Value *rhs,
                                 llvm::IRBuilder<> &bldr,
                                 const BitShiftFunction &bitshift_func) {
  if (lhs->getType() != rhs->getType()) {
    rhs = bldr.CreateZExtOrTrunc(rhs, lhs->getType());
  }
  // If the number of bits we're shifting exceeds the bit width of the
  // other operand, the result should be zero.
  auto max_shift = llvm::ConstantInt::get(lhs->getType(),
                                          lhs->getType()->getIntegerBitWidth());
  return bldr.CreateSelect(bldr.CreateICmpSGE(rhs, max_shift),
                           llvm::ConstantInt::get(lhs->getType(), 0),
                           bitshift_func(lhs, rhs, bldr));
}

}  // namespace

class SleighLifter::PcodeToLLVMEmitIntoBlock {
 private:
  class Parameter {
   private:
    llvm::Type *vnode_type;
    bool allows_conversions;

   public:
    Parameter(llvm::Type *vnode_type, bool allows_conversions)
        : vnode_type(vnode_type),
          allows_conversions(allows_conversions) {}

    virtual ~Parameter(void) = default;

    virtual std::optional<llvm::Value *> LiftAsInParam(llvm::IRBuilder<> &bldr,
                                                       llvm::Type *ty) {
      auto mayberes = this->LiftAsInParamNoConvert(bldr, vnode_type);
      if (!mayberes) {
        return std::nullopt;
      }

      auto res = *mayberes;
      if (res->getType() == ty) {
        return res;
      }

      if (!allows_conversions ||
          !llvm::isa<llvm::IntegerType>(res->getType()) ||
          !llvm::isa<llvm::IntegerType>(ty)) {
        return std::nullopt;
      }

      return bldr.CreateZExtOrTrunc(res, ty);
    }

    virtual std::optional<llvm::Value *>
    LiftAsInParamNoConvert(llvm::IRBuilder<> &bldr, llvm::Type *ty) = 0;

    virtual LiftStatus StoreIntoParam(llvm::IRBuilder<> &bldr,
                                      llvm::Value *inner_lifted) = 0;
  };


  using ParamPtr = std::shared_ptr<Parameter>;

 public:
  class DecodingContextConstants {
   private:
    const sleigh::ContextRegMappings &sleigh_to_remill_reg;
    llvm::LLVMContext &context;
    const ContextValues &context_values;
    std::unordered_map<std::string, llvm::Value *> regptrs;


    void PrepareEntryBlock(llvm::BasicBlock *entry) {
      llvm::IRBuilder<> builder(entry);

      for (const auto &[k, v] : this->sleigh_to_remill_reg.GetSizeMapping()) {
        auto ity = llvm::IntegerType::get(this->context, v * 8);
        auto reg_ptr = builder.CreateAlloca(ity, nullptr, k);
        regptrs.emplace(k, reg_ptr);


        auto maybe_reg =
            this->sleigh_to_remill_reg.GetInternalRegMapping().find(k);

        if (maybe_reg ==
            this->sleigh_to_remill_reg.GetInternalRegMapping().end()) {
          continue;
        }

        auto maybe_value = context_values.find(maybe_reg->second);
        if (maybe_value == context_values.end()) {
          continue;
        }

        builder.CreateStore(llvm::ConstantInt::get(ity, maybe_value->second),
                            reg_ptr);
      }
    }

   public:
    DecodingContextConstants(
        const sleigh::ContextRegMappings &sleigh_to_remill_reg,
        llvm::LLVMContext &context, const ContextValues &context_values,
        llvm::BasicBlock *target_block)
        : sleigh_to_remill_reg(sleigh_to_remill_reg),
          context(context),
          context_values(context_values) {
      this->PrepareEntryBlock(target_block);
    }


    std::optional<ParamPtr>
    LiftRegisterFromDecodingContext(std::string target_reg,
                                    VarnodeData target_vnode) {
      auto maybe_reg = this->regptrs.find(target_reg);
      if (maybe_reg == this->regptrs.end()) {
        return std::nullopt;
      }


      return RegisterValue::CreateRegister(
          maybe_reg->second,
          llvm::IntegerType::get(this->context, target_vnode.size * 8));
    }
  };

 private:
  class RegisterValue : public Parameter {
   private:
    llvm::Value *register_pointer;

   public:
    // TODO(Ian): allow this to be fallible and have better error handling
    std::optional<llvm::Value *>
    LiftAsInParamNoConvert(llvm::IRBuilder<> &bldr, llvm::Type *ty) override {
      return bldr.CreateLoad(ty, register_pointer);
    }

    LiftStatus StoreIntoParam(llvm::IRBuilder<> &bldr,
                              llvm::Value *inner_lifted) override {
      bldr.CreateStore(inner_lifted, register_pointer);
      return LiftStatus::kLiftedInstruction;
    }

   public:
    RegisterValue(llvm::Value *register_pointer, llvm::Type *orig_type)
        : Parameter(orig_type, true),
          register_pointer(register_pointer) {}

    static ParamPtr CreateRegister(llvm::Value *register_pointer,
                                   llvm::Type *vnode_type) {
      return std::make_shared<RegisterValue>(register_pointer, vnode_type);
    }

    virtual ~RegisterValue() {}
  };


  class Memory : public Parameter {
   public:
    virtual ~Memory() {}
    Memory(llvm::Value *memory_ref_ptr, llvm::Value *index,
           const IntrinsicTable *intrinsics, llvm::Type *memory_ptr_type,
           llvm::Type *vnode_type)
        : Parameter(vnode_type, true),
          memory_ref_ptr(memory_ref_ptr),
          index(index),
          intrinsics(intrinsics),
          memory_ptr_type(memory_ptr_type) {}

    static ParamPtr
    CreateMemory(llvm::Value *memory_ref_ptr, llvm::Value *index,
                 const IntrinsicTable *intrinsics, llvm::Type *memory_ptr_type,
                 llvm::Type *vnode_type) {
      return std::make_shared<Memory>(memory_ref_ptr, index, intrinsics,
                                      memory_ptr_type, vnode_type);
    }

   private:
    llvm::Value *memory_ref_ptr;
    llvm::Value *index;
    const IntrinsicTable *intrinsics;
    llvm::Type *memory_ptr_type;

    std::optional<llvm::Value *>
    LiftAsInParamNoConvert(llvm::IRBuilder<> &bldr, llvm::Type *ty) override {
      auto mem = bldr.CreateLoad(this->memory_ptr_type, this->memory_ref_ptr);
      auto res = remill::LoadFromMemory(
          *this->intrinsics, bldr.GetInsertBlock(), ty, mem, this->index);
      if (res) {
        return res;
      } else {
        return std::nullopt;
      }
    }

    LiftStatus StoreIntoParam(llvm::IRBuilder<> &bldr,
                              llvm::Value *inner_lifted) override {
      auto mem = bldr.CreateLoad(this->memory_ptr_type, this->memory_ref_ptr);
      auto new_mem =
          remill::StoreToMemory(*this->intrinsics, bldr.GetInsertBlock(),
                                inner_lifted, mem, this->index);
      if (new_mem) {
        bldr.CreateStore(new_mem, this->memory_ref_ptr);
        return LiftStatus::kLiftedInstruction;
      } else {
        return LiftStatus::kLiftedInvalidInstruction;
      }
    }
  };

  class ConstantValue : public Parameter {
   private:
    llvm::Value *cst;

   public:
    std::optional<llvm::Value *>
    LiftAsInParamNoConvert(llvm::IRBuilder<> &bldr, llvm::Type *ty) override {
      if (ty != cst->getType()) {
        return std::nullopt;
      }
      return this->cst;
    }

    LiftStatus StoreIntoParam(llvm::IRBuilder<> &bldr,
                              llvm::Value *inner_lifted) override {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    ConstantValue(llvm::Value *cst)
        : Parameter(cst->getType(), false),
          cst(cst) {}

    static ParamPtr CreatConstant(llvm::Value *cst) {
      return std::make_shared<ConstantValue>(cst);
    }
    virtual ~ConstantValue() {}
  };


  llvm::BasicBlock *target_block;
  const sleigh::PcodeBlock *pcode_block{nullptr};
  llvm::Value *state_pointer;
  llvm::LLVMContext &context;
  const Instruction &insn;
  LiftStatus status;
  SleighLifter &insn_lifter_parent;


  class UniqueRegSpace {
   private:
    std::unordered_map<uint64_t, llvm::Value *> cached_unique_ptrs;
    llvm::LLVMContext &context;

   public:
    UniqueRegSpace(llvm::LLVMContext &context) : context(context) {}

    llvm::Value *GetUniquePtr(uint64_t offset, uint64_t size,
                              llvm::IRBuilder<> &bldr) {
      if (this->cached_unique_ptrs.find(offset) !=
          this->cached_unique_ptrs.end()) {
        return this->cached_unique_ptrs.find(offset)->second;
      }

      std::stringstream ss;
      ss << "unique_" << std::hex << offset << ":" << std::dec << size;
      auto ptr =
          bldr.CreateAlloca(llvm::IntegerType::get(this->context, 8 * size), 0,
                            nullptr, ss.str());
      this->cached_unique_ptrs.insert({offset, ptr});
      return ptr;
    }
  };

  class ConstantReplacementContext {
   private:
    std::map<uint64_t, ParamPtr> current_replacements;
    std::set<uint64_t> used_values;

   public:
    void ApplyEqualityClaim(llvm::IRBuilder<> &bldr,
                            SleighLifter::PcodeToLLVMEmitIntoBlock &lifter,
                            VarnodeData lhs_constant,
                            VarnodeData rhs_unfolded_value) {
      CHECK(isVarnodeInConstantSpace(lhs_constant));
      DLOG(INFO) << "Adding (" << lhs_constant.offset << ") to map";
      this->current_replacements.insert(
          {lhs_constant.offset, lifter.LiftParamPtr(bldr, rhs_unfolded_value)});
    }


    void ApplyNonEqualityClaim() {
      this->current_replacements.clear();
      this->used_values.clear();
    }

    // NOTE(wtan): this may end up replacing constants that shouldn't be replaced
    // if the claim_eq happens to be used on constant values that are used elsewhere
    // In practice, we don't expect this to happen since the program will be mapped
    // to a higher address space so collisions should be rare
    llvm::Value *LiftOffsetOrReplace(llvm::IRBuilder<> &bldr,
                                     VarnodeData target,
                                     llvm::Type *target_type) {
      DLOG(INFO) << "Fetching (" << target.offset << ") from map";
      if (this->current_replacements.find(target.offset) !=
          this->current_replacements.end()) {

        if (this->used_values.find(target.offset) != this->used_values.end()) {
          DLOG(ERROR) << "Ambigous value substitution via claim eq: "
                      << target.offset;
        }
        auto replacement = this->current_replacements.find(target.offset)
                               ->second->LiftAsInParam(bldr, target_type);
        if (!replacement.has_value()) {
          LOG(FATAL) << "Failure to lift replacement value for: "
                     << target.offset << " as "
                     << remill::LLVMThingToString(target_type);
        }
        this->used_values.insert(target.offset);
        return *replacement;
      }

      return llvm::ConstantInt::get(target_type, target.offset);
    }

    // Returns true if the equality claim was used or if no equality claims were declared
    // if the equality claim is not used at all when lifting an instruction,
    // this can indicate that there is a bug
    bool IsEqualityUsed() const {
      return !used_values.empty() || current_replacements.empty();
    }
  };

  UniqueRegSpace uniques;
  UniqueRegSpace unknown_regs;

  ConstantReplacementContext replacement_cont;
  // Generic sleigh arch
  std::vector<std::string> user_op_names;

  llvm::BasicBlock *entry_block;
  llvm::BasicBlock *exit_block;

  const sleigh::MaybeBranchTakenVar &to_lift_btaken;

  std::unordered_map<size_t, llvm::BasicBlock *> start_index_to_block;

  DecodingContextConstants context_reg_lifter;


  void UpdateStatus(LiftStatus new_status, OpCode opc) {
    if (new_status != LiftStatus::kLiftedInstruction) {
      this->status = new_status;
      DLOG(ERROR) << "Failed to lift insn with opcode: " << get_opname(opc)
                  << " in insn: " << std::hex << this->insn.pc
                  << llvm::toHex(this->insn.bytes);
    }
  }

  llvm::BasicBlock *GetBlock(size_t target) const {
    auto blk = start_index_to_block.find(target);
    if (blk != start_index_to_block.end()) {
      return blk->second;
    }
    return nullptr;
  }

 public:
  llvm::BasicBlock *GetOrCreateBlock(size_t target) {
    if (auto blk = GetBlock(target)) {
      return blk;
    }

    auto newblk = llvm::BasicBlock::Create(this->exit_block->getContext(), "",
                                           this->exit_block->getParent());

    this->start_index_to_block[target] = newblk;
    return newblk;
  }

  PcodeToLLVMEmitIntoBlock(
      llvm::BasicBlock *target_block, llvm::Value *state_pointer,
      const Instruction &insn, SleighLifter &insn_lifter_parent,
      std::vector<std::string> user_op_names_, llvm::BasicBlock *exit_block_,
      const sleigh::MaybeBranchTakenVar &to_lift_btaken_,
      PcodeToLLVMEmitIntoBlock::DecodingContextConstants context_reg_lifter)
      : target_block(target_block),
        state_pointer(state_pointer),
        context(target_block->getContext()),
        insn(insn),
        status(remill::LiftStatus::kLiftedInstruction),
        insn_lifter_parent(insn_lifter_parent),
        uniques(target_block->getContext()),
        unknown_regs(target_block->getContext()),
        user_op_names(user_op_names_),
        entry_block(target_block),
        exit_block(exit_block_),
        to_lift_btaken(to_lift_btaken_),
        context_reg_lifter(std::move(context_reg_lifter)) {}


  ParamPtr CreateMemoryAddress(llvm::Value *offset, VarnodeData vnode) {
    const auto mem_ptr_ref = this->insn_lifter_parent.LoadRegAddress(
        this->target_block, this->state_pointer, kMemoryVariableName);
    // compute pointer into memory at offset


    return Memory::CreateMemory(
        mem_ptr_ref.first, offset, this->insn_lifter_parent.GetIntrinsicTable(),
        this->insn_lifter_parent.GetMemoryType(),
        llvm::IntegerType::get(this->context, vnode.size * 8));
  }

  std::optional<ParamPtr> LiftNormalRegister(llvm::IRBuilder<> &bldr,
                                             std::string reg_name,
                                             VarnodeData target_vnode) {
    for (auto &c : reg_name) {
      c = toupper(c);
    }
    const auto &remappings =
        this->insn_lifter_parent.decoder.GetStateRegRemappings();

    if (auto el = remappings.find(reg_name); el != remappings.end()) {
      DLOG(INFO) << "Remapping to " << el->second;
      reg_name = el->second;
    }

    if (this->insn_lifter_parent.ArchHasRegByName(reg_name)) {
      // TODO(Ian): will probably need to adjust the pointer here in certain circumstances
      auto reg_ptr = this->insn_lifter_parent.LoadRegAddress(
          bldr.GetInsertBlock(), this->state_pointer, reg_name);
      return RegisterValue::CreateRegister(
          reg_ptr.first,
          llvm::IntegerType::get(this->context, target_vnode.size * 8));
    } else {
      return std::nullopt;
    }
  }

  ParamPtr LiftNormalRegisterOrCreateUnique(llvm::IRBuilder<> &bldr,
                                            std::string reg_name,
                                            VarnodeData target_vnode) {
    if (auto res = this->LiftNormalRegister(bldr, reg_name, target_vnode)) {
      return *res;
    }

    if (auto res = this->context_reg_lifter.LiftRegisterFromDecodingContext(
            reg_name, target_vnode)) {
      return *res;
    }

    // Uniques must be allocated in the entry block
    llvm::IRBuilder<> entry_bldr(entry_block);

    std::stringstream ss;

    auto reg_ptr = this->unknown_regs.GetUniquePtr(
        target_vnode.offset, target_vnode.size, entry_bldr);
    print_vardata(this->insn_lifter_parent.GetEngine(), ss, target_vnode);
    DLOG(ERROR) << "Creating unique for unknown register: " << ss.str() << " "
                << reg_ptr->getName().str();

    return RegisterValue::CreateRegister(
        reg_ptr, llvm::IntegerType::get(this->context, 8 * target_vnode.size));
  }

  //TODO(Ian): Maybe this should be a failable function that returns an unsupported insn in certain failures
  // So the times we need to replace an offset via a context are 3 fold.
  // 1. in Branches where the offset is retrieved directly from the varnode. This isnt handled here.
  // 2. In ram offsets
  // 3. In constant offsets
  ParamPtr LiftParamPtr(llvm::IRBuilder<> &bldr, VarnodeData vnode) {
    auto space_name = vnode.getAddr().getSpace()->getName();
    if (space_name == "ram") {
      // compute pointer into memory at offset

      auto constant_offset = this->replacement_cont.LiftOffsetOrReplace(
          bldr, vnode, this->insn_lifter_parent.GetWordType());

      return this->CreateMemoryAddress(constant_offset, vnode);
    } else if (space_name == "register") {
      auto reg_name = this->insn_lifter_parent.GetEngine().getRegisterName(
          vnode.space, vnode.offset, vnode.size);

      DLOG(INFO) << "Looking for reg name " << reg_name << " from offset "
                 << vnode.offset;
      return this->LiftNormalRegisterOrCreateUnique(bldr, reg_name, vnode);
    } else if (space_name == "const") {

      auto cst_v = this->replacement_cont.LiftOffsetOrReplace(
          bldr, vnode, llvm::IntegerType::get(this->context, vnode.size * 8));

      return ConstantValue::CreatConstant(cst_v);
    } else if (space_name == "unique") {
      // Uniques must be allocated in the entry block
      llvm::IRBuilder<> entry_bldr(entry_block);

      auto reg_ptr =
          this->uniques.GetUniquePtr(vnode.offset, vnode.size, entry_bldr);
      return RegisterValue::CreateRegister(
          reg_ptr, llvm::IntegerType::get(this->context, 8 * vnode.size));
    } else {
      LOG(FATAL) << "Unhandled memory space: " << space_name;
    }
  }


  llvm::Value *FixResultForOutVarnode(llvm::IRBuilder<> &bldr,
                                      llvm::Value *orig, VarnodeData outvnode) {
    CHECK(orig->getType()->isIntegerTy());
    auto out_bits = outvnode.size * 8;
    if (out_bits == orig->getType()->getIntegerBitWidth()) {
      return orig;
    }

    auto target_ty = llvm::IntegerType::get(bldr.getContext(), out_bits);

    return bldr.CreateZExtOrTrunc(orig, target_ty);
  }

  std::optional<llvm::Value *> LiftInParam(llvm::IRBuilder<> &bldr,
                                           VarnodeData vnode, llvm::Type *ty) {
    return this->LiftParamPtr(bldr, vnode)->LiftAsInParam(bldr, ty);
  }

  std::optional<llvm::Value *> LiftIntegerInParam(llvm::IRBuilder<> &bldr,
                                                  VarnodeData vnode) {
    return this->LiftInParam(
        bldr, vnode, llvm::IntegerType::get(this->context, vnode.size * 8));
  }

  LiftStatus
  LiftRequireOutParam(std::function<LiftStatus(VarnodeData)> inner_lift,
                      std::optional<VarnodeData> outvar) {
    if (outvar) {
      return inner_lift(*outvar);
    } else {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }
  }


  LiftStatus LiftStoreIntoOutParam(llvm::IRBuilder<> &bldr,
                                   llvm::Value *inner_lifted,
                                   std::optional<VarnodeData> outvar) {
    return this->LiftRequireOutParam(
        [&bldr, this, inner_lifted](VarnodeData out_param_data) {
          auto ptr = this->LiftParamPtr(bldr, out_param_data);
          return ptr->StoreIntoParam(bldr, inner_lifted);
        },
        outvar);
  }

  LiftStatus LiftUnaryOpWithFloatIntrinsic(
      llvm::IRBuilder<> &bldr,
      llvm::Intrinsic::IndependentIntrinsics intrinsic_id,
      std::optional<VarnodeData> outvar, VarnodeData input_var) {
    auto inval = this->LiftFloatInParam(bldr, input_var);

    if (!inval) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    llvm::Value *intrinsic_args[] = {*inval};
    llvm::Function *intrinsic =
        llvm::Intrinsic::getDeclaration(bldr.GetInsertBlock()->getModule(),
                                        intrinsic_id, {(*inval)->getType()});
    return this->LiftStoreIntoOutParam(
        bldr,
        this->CastFloatResult(bldr, *outvar,
                              bldr.CreateCall(intrinsic, intrinsic_args)),
        outvar);
  }


  LiftStatus RedirectControlFlow(llvm::IRBuilder<> &bldr,
                                 llvm::Value *target_addr) {

    bldr.CreateStore(target_addr, this->GetNextPcRef());
    this->TerminateBlock();
    return LiftStatus::kLiftedInstruction;
  }

  LiftStatus LiftFloatUnop(llvm::IRBuilder<> &bldr, OpCode opc,
                           std::optional<VarnodeData> outvar,
                           VarnodeData input_var) {
    switch (opc) {
      case OpCode::CPUI_FLOAT_NEG: {
        auto negate_inval = this->LiftFloatInParam(bldr, input_var);
        if (negate_inval.has_value()) {
          return this->LiftStoreIntoOutParam(
              bldr, bldr.CreateFNeg(*negate_inval), outvar);
        }
        break;
      }
      case OpCode::CPUI_FLOAT_ABS: {
        return this->LiftUnaryOpWithFloatIntrinsic(bldr, llvm::Intrinsic::fabs,
                                                   outvar, input_var);
      }
      case OpCode::CPUI_FLOAT_SQRT: {
        return this->LiftUnaryOpWithFloatIntrinsic(bldr, llvm::Intrinsic::sqrt,
                                                   outvar, input_var);
      }
      case OpCode::CPUI_FLOAT_CEIL: {
        return this->LiftUnaryOpWithFloatIntrinsic(bldr, llvm::Intrinsic::ceil,
                                                   outvar, input_var);
      }
      case OpCode::CPUI_FLOAT_FLOOR: {
        return this->LiftUnaryOpWithFloatIntrinsic(bldr, llvm::Intrinsic::floor,
                                                   outvar, input_var);
      }
      case OpCode::CPUI_FLOAT_ROUND: {
        return this->LiftUnaryOpWithFloatIntrinsic(bldr, llvm::Intrinsic::round,
                                                   outvar, input_var);
      }
      case OpCode::CPUI_FLOAT_NAN: {
        auto nan_inval = this->LiftFloatInParam(bldr, input_var);
        if (nan_inval.has_value()) {
          // LLVM trunk has an `isnan` intrinsic but to support older versions, I think we need to do this.
          auto isnan_check = bldr.CreateZExt(
              bldr.CreateNot(bldr.CreateFCmpORD(*nan_inval, *nan_inval)),
              llvm::IntegerType::get(this->context, outvar->size * 8));
          return this->LiftStoreIntoOutParam(bldr, isnan_check, outvar);
        }
        break;
      }
      case OpCode::CPUI_FLOAT_INT2FLOAT: {
        auto int2float_inval = this->LiftIntegerInParam(bldr, input_var);
        auto new_float_type = this->GetFloatTypeOfByteSize(outvar->size);
        if (int2float_inval.has_value() && new_float_type) {
          auto converted = bldr.CreateSIToFP(*int2float_inval, *new_float_type);
          return this->LiftStoreIntoOutParam(
              bldr, this->CastFloatResult(bldr, *outvar, converted), outvar);
        }
        break;
      }
      case OpCode::CPUI_FLOAT_FLOAT2FLOAT: {
        auto float2float_inval = this->LiftFloatInParam(bldr, input_var);
        auto new_float_type = this->GetFloatTypeOfByteSize(input_var.size);
        if (float2float_inval.has_value() && new_float_type) {
          // This is a no-op until we make a helper to select an appropriate float type for a given node size.
          return this->LiftStoreIntoOutParam(
              bldr,
              this->CastFloatResult(
                  bldr, *outvar,
                  bldr.CreateFPCast(*float2float_inval, *new_float_type)),
              outvar);
        }
        break;
      }
      case OpCode::CPUI_FLOAT_TRUNC: {
        auto trunc_inval = this->LiftFloatInParam(bldr, input_var);
        if (trunc_inval.has_value()) {
          // Should this be UI?
          auto converted = bldr.CreateFPToSI(
              *trunc_inval,
              llvm::IntegerType::get(this->context, outvar->size * 8));
          return this->LiftStoreIntoOutParam(bldr, converted, outvar);
        }
        break;
      }

      default: return LiftStatus::kLiftedUnsupportedInstruction;
    }

    return LiftStatus::kLiftedUnsupportedInstruction;
  }

  LiftStatus LiftUnaryOp(llvm::IRBuilder<> &bldr, OpCode opc,
                         std::optional<VarnodeData> outvar,
                         VarnodeData input_var) {

    auto res = this->LiftFloatUnop(bldr, opc, outvar, input_var);
    if (res != LiftStatus::kLiftedUnsupportedInstruction) {
      return res;
    }

    switch (opc) {
      case OpCode::CPUI_BOOL_NEGATE: {
        auto byte_type = llvm::IntegerType::get(this->context, 8);
        auto bneg_inval = this->LiftInParam(bldr, input_var, byte_type);
        ;
        if (bneg_inval.has_value()) {
          // TODO(Ian): is there a more optimization friendly way to get logical not on a byte?
          return this->LiftStoreIntoOutParam(
              bldr,
              bldr.CreateZExt(
                  bldr.CreateICmpEQ(*bneg_inval,
                                    llvm::ConstantInt::get(byte_type, 0)),
                  byte_type),
              outvar);
        }
        break;
      }
      case OpCode::CPUI_COPY:
      case OpCode::CPUI_CAST: {
        auto copy_inval = this->LiftInParam(
            bldr, input_var,
            llvm::IntegerType::get(this->context, input_var.size * 8));
        if (copy_inval.has_value()) {
          return this->LiftStoreIntoOutParam(bldr, *copy_inval, outvar);
        }
        break;
      }

      case OpCode::CPUI_BRANCH:
      case OpCode::CPUI_CALL: {
        // directs dont read the address of the variable, the offset is the jump
        // TODO(Ian): handle other address spaces
        if (isVarnodeInConstantSpace(input_var)) {
          this->TerminateBlock();
          return LiftStatus::kLiftedInstruction;
        }

        auto input_val = this->replacement_cont.LiftOffsetOrReplace(
            bldr, input_var,
            llvm::IntegerType::get(this->context, input_var.size * 8));

        return this->RedirectControlFlow(bldr, input_val);
      }
      case OpCode::CPUI_RETURN:
      case OpCode::CPUI_BRANCHIND:
      case OpCode::CPUI_CALLIND: {
        auto copy_inval = this->LiftInParam(
            bldr, input_var,
            llvm::IntegerType::get(this->context, input_var.size * 8));
        if (!copy_inval) {
          return LiftStatus::kLiftedUnsupportedInstruction;
        }
        return this->RedirectControlFlow(bldr, *copy_inval);
      }
        // TODO(alex): Maybe extract this into a method like `LiftIntegerUnOp`?
        // Let's see how much duplication there is.
      case OpCode::CPUI_INT_ZEXT:
      case OpCode::CPUI_INT_SEXT: {
        auto zext_inval = this->LiftIntegerInParam(bldr, input_var);
        if (zext_inval.has_value()) {
          auto zext_type =
              llvm::IntegerType::get(this->context, outvar->size * 8);
          auto zext_op = (opc == OpCode::CPUI_INT_ZEXT)
                             ? bldr.CreateZExt(*zext_inval, zext_type)
                             : bldr.CreateSExt(*zext_inval, zext_type);
          return this->LiftStoreIntoOutParam(bldr, zext_op, outvar);
        }
        break;
      }
      case OpCode::CPUI_INT_2COMP: {
        auto two_comp_inval = this->LiftIntegerInParam(bldr, input_var);
        if (two_comp_inval.has_value()) {
          return this->LiftStoreIntoOutParam(
              bldr, bldr.CreateNeg(*two_comp_inval), outvar);
        }
        break;
      }
      case OpCode::CPUI_INT_NEGATE: {
        auto negate_inval = this->LiftIntegerInParam(bldr, input_var);
        if (negate_inval.has_value()) {
          return this->LiftStoreIntoOutParam(
              bldr, bldr.CreateNot(*negate_inval), outvar);
        }
        break;
      }
      case OpCode::CPUI_POPCOUNT: {
        auto ctpop_inval = this->LiftIntegerInParam(bldr, input_var);
        if (ctpop_inval.has_value()) {
          llvm::Type *overloaded_types[1] = {(*ctpop_inval)->getType()};
          llvm::Function *ctpop_intrinsic = llvm::Intrinsic::getDeclaration(
              bldr.GetInsertBlock()->getModule(), llvm::Intrinsic::ctpop,
              overloaded_types);

          std::array<llvm::Value *, 1> ctpop_args = {*ctpop_inval};
          llvm::Value *ctpop_val = this->FixResultForOutVarnode(
              bldr, bldr.CreateCall(ctpop_intrinsic, ctpop_args), *outvar);


          return this->LiftStoreIntoOutParam(bldr, ctpop_val, outvar);
        }
        break;
      }
      default: break;
    }
    return LiftStatus::kLiftedUnsupportedInstruction;
  }
  using BinaryOperator = std::function<llvm::Value *(
      llvm::Value *, llvm::Value *, llvm::IRBuilder<> &)>;
  static std::map<OpCode, BinaryOperator> INTEGER_BINARY_OPS;
  static std::map<OpCode, BinaryOperator> BOOL_BINARY_OPS;
  static std::unordered_set<OpCode> INTEGER_COMP_OPS;


  struct VisitExit {
    PcodeToLLVMEmitIntoBlock &lifter;

    llvm::BasicBlock *operator()(const sleigh::Exit &exit) {
      return std::visit(*this, exit);
    }

    llvm::BasicBlock *operator()(const sleigh::InstrExit &exit) {
      return lifter.exit_block;
    };

    llvm::BasicBlock *operator()(const sleigh::IntrainstructionIndex &exit) {
      return lifter.GetOrCreateBlock(exit.target_block_index);
    };
  };
  struct VisitBlockExitTrue : public VisitExit {
    using VisitExit::operator();

    llvm::BasicBlock *operator()(const sleigh::ConditionalExit &exit) {
      return std::visit(*this, exit.true_branch);
    }
  };

  struct VisitBlockExitFalse : public VisitExit {
    using VisitExit::operator();

    llvm::BasicBlock *operator()(const sleigh::ConditionalExit &exit) {
      return std::visit(*this, exit.false_branch);
    }
  };

  llvm::BasicBlock *GetTrueOut() {
    return std::visit(VisitBlockExitTrue{*this}, this->pcode_block->block_exit);
  }

  llvm::BasicBlock *GetFalseOut() {
    return std::visit(VisitBlockExitFalse{*this},
                      this->pcode_block->block_exit);
  }

  LiftStatus TerminateBlockWithCondition(llvm::Value *condition) {
    if (this->target_block->getTerminator() == nullptr) {
      llvm::IRBuilder<> ir(this->target_block);

      ir.CreateCondBr(condition, GetTrueOut(), GetFalseOut());
    }
    return LiftStatus::kLiftedInstruction;
  }

  void TerminateBlock() {
    if (this->target_block->getTerminator() == nullptr) {
      llvm::IRBuilder ir(this->target_block);
      ir.CreateBr(GetTrueOut());
    }
  }


  LiftStatus LiftCBranch(llvm::IRBuilder<> &bldr,
                         std::optional<VarnodeData> outvar, VarnodeData lhs,
                         VarnodeData rhs) {
    auto should_branch = this->LiftInParam(
        bldr, rhs, llvm::IntegerType::get(this->context, rhs.size * 8));


    if (!should_branch) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    auto i1 = llvm::IntegerType::get(this->context, 1);
    // TODO(Ian): this should probably technically be != 0
    auto trunc_should_branch = bldr.CreateTrunc(
        *should_branch, i1 );
    if (!isVarnodeInConstantSpace(lhs)) {
      // directs dont read the address of the variable, the offset is the jump
      // TODO(Ian): handle other address spaces
      auto jump_addr = this->replacement_cont.LiftOffsetOrReplace(
          bldr, lhs, this->insn_lifter_parent.GetWordType());


      auto orig_pc_value = this->GetNextPc(bldr);
      //CHECK(pc_reg_param.has_value());
      auto next_pc_value =
          bldr.CreateSelect(trunc_should_branch, jump_addr, orig_pc_value);

      bldr.CreateStore(next_pc_value, this->GetNextPcRef());
    }


    return this->TerminateBlockWithCondition(trunc_should_branch);
  }

  LiftStatus LiftIntegerBinOp(llvm::IRBuilder<> &bldr, OpCode opc,
                              std::optional<VarnodeData> outvar,
                              VarnodeData lhs, VarnodeData rhs) {


    if (INTEGER_BINARY_OPS.find(opc) != INTEGER_BINARY_OPS.end()) {
      auto &op_func = INTEGER_BINARY_OPS.find(opc)->second;
      auto lifted_lhs = this->LiftIntegerInParam(bldr, lhs);
      auto lifted_rhs = this->LiftIntegerInParam(bldr, rhs);
      if (lifted_lhs.has_value() && lifted_rhs.has_value()) {
        DLOG(INFO) << "Binop op: " << get_opname(opc);
        DLOG(INFO) << "Binop with lhs: "
                   << remill::LLVMThingToString(*lifted_lhs);
        DLOG(INFO) << "Binop with rhs: "
                   << remill::LLVMThingToString(*lifted_rhs);
        auto orig_res = op_func(*lifted_lhs, *lifted_rhs, bldr);
        if (INTEGER_COMP_OPS.find(opc) != INTEGER_COMP_OPS.end()) {
          // Comparison operators always return a byte
          if (orig_res->getType()->getIntegerBitWidth() != 8) {
            orig_res = bldr.CreateZExt(
                orig_res, llvm::IntegerType::get(bldr.getContext(), 8));
          }
        }
        DLOG(INFO) << "Res: " << remill::LLVMThingToString(orig_res);
        DLOG(INFO) << "Res ty: "
                   << remill::LLVMThingToString(orig_res->getType());
        return this->LiftStoreIntoOutParam(bldr, orig_res, outvar);
      }
    }
    return LiftStatus::kLiftedUnsupportedInstruction;
  }


  LiftStatus LiftBoolBinOp(llvm::IRBuilder<> &bldr, OpCode opc,
                           std::optional<VarnodeData> outvar, VarnodeData lhs,
                           VarnodeData rhs) {

    // We make sure to only attempt to lift params for operands where we know they are booleans
    // Otherwise lifting a value as a byte could be an incorrect size for something like a unique.
    if (this->BOOL_BINARY_OPS.find(opc) == this->BOOL_BINARY_OPS.end()) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    auto lifted_lhs =
        this->LiftInParam(bldr, lhs, llvm::IntegerType::get(this->context, 8));
    auto lifted_rhs =
        this->LiftInParam(bldr, rhs, llvm::IntegerType::get(this->context, 8));
    if (!lifted_lhs.has_value() || !lifted_rhs.has_value()) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    auto computed_value =
        this->BOOL_BINARY_OPS.find(opc)->second(*lifted_lhs, *lifted_rhs, bldr);

    return this->LiftStoreIntoOutParam(bldr, computed_value, outvar);
  }

  std::optional<BinaryOperator> FindFloatBinOpFunc(OpCode opc) {
    switch (opc) {
      case CPUI_FLOAT_EQUAL: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateZExt(bldr.CreateFCmpOEQ(lhs, rhs),
                                 llvm::IntegerType::get(bldr.getContext(), 8));
        };
      }
      case CPUI_FLOAT_NOTEQUAL: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateZExt(bldr.CreateFCmpONE(lhs, rhs),
                                 llvm::IntegerType::get(bldr.getContext(), 8));
        };
      }
      case CPUI_FLOAT_LESS: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateZExt(bldr.CreateFCmpOLT(lhs, rhs),
                                 llvm::IntegerType::get(bldr.getContext(), 8));
        };
      }
      case CPUI_FLOAT_LESSEQUAL: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateZExt(bldr.CreateFCmpOLE(lhs, rhs),
                                 llvm::IntegerType::get(bldr.getContext(), 8));
        };
      }
      case CPUI_FLOAT_ADD: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateFAdd(lhs, rhs);
        };
      }
      case CPUI_FLOAT_SUB: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateFSub(lhs, rhs);
        };
      }
      case CPUI_FLOAT_MULT: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateFMul(lhs, rhs);
        };
      }
      case CPUI_FLOAT_DIV: {
        return [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
          return bldr.CreateFDiv(lhs, rhs);
        };
      }
      default: return std::nullopt;
    }
  }


  std::optional<llvm::Type *> GetFloatTypeOfByteSize(size_t byte_size) {
    switch (byte_size) {
      case 2: return llvm::Type::getHalfTy(this->context);
      case 4: return llvm::Type::getFloatTy(this->context);
      case 8: return llvm::Type::getDoubleTy(this->context);
      case 16: return llvm::Type::getFP128Ty(this->context);
      default: return std::nullopt;
    }
  }


  llvm::Value *CastFloatResult(llvm::IRBuilder<> &bldr,
                               VarnodeData output_varnode,
                               llvm::Value *maybe_float) {

    if (maybe_float->getType()->isFloatingPointTy()) {
      auto num_bits = maybe_float->getType()->getPrimitiveSizeInBits();
      maybe_float = bldr.CreateBitCast(
          maybe_float, llvm::IntegerType::get(this->context, num_bits));
    }

    return bldr.CreateZExtOrTrunc(
        maybe_float,
        llvm::IntegerType::get(this->context, output_varnode.size * 8));
  }

  std::optional<llvm::Value *> LiftFloatInParam(llvm::IRBuilder<> &bldr,
                                                VarnodeData vnode) {
    auto float_ty = this->GetFloatTypeOfByteSize(vnode.size);
    if (!float_ty) {
      DLOG(ERROR) << "Could not create llvm float type of size " << vnode.size;
      return std::nullopt;
    }

    auto int_ty = llvm::IntegerType::get(this->context, vnode.size * 8);

    auto int_in_param = this->LiftInParam(bldr, vnode, int_ty);

    if (!int_in_param) {
      return std::nullopt;
    }

    return bldr.CreateBitCast(*int_in_param, *float_ty);
  }

  LiftStatus LiftFloatBinOp(llvm::IRBuilder<> &bldr, OpCode opc,
                            std::optional<VarnodeData> outvar, VarnodeData lhs,
                            VarnodeData rhs) {
    std::optional<BinaryOperator> op_func = this->FindFloatBinOpFunc(opc);
    if (!op_func) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }


    // TODO(alex): I think we need some helper here to achieve something similar to what `llvm::IntegerType::get`
    // gives us, except for floating point types.
    //
    // So we need to check the size of the node and return either a 32-bit float, brain float, double, etc.

    auto lifted_lhs = this->LiftFloatInParam(bldr, lhs);
    auto lifted_rhs = this->LiftFloatInParam(bldr, rhs);

    if (!lifted_lhs || !lifted_rhs) {
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    auto res = (*op_func)(*lifted_lhs, *lifted_rhs, bldr);
    return this->LiftStoreIntoOutParam(
        bldr, this->CastFloatResult(bldr, *outvar, res), outvar);
  }


  LiftStatus LiftBinOp(llvm::IRBuilder<> &bldr, OpCode opc,
                       std::optional<VarnodeData> outvar, VarnodeData lhs,
                       VarnodeData rhs) {

    if (opc == OpCode::CPUI_CBRANCH) {
      return this->LiftCBranch(bldr, outvar, lhs, rhs);
    }

    auto res = this->LiftIntegerBinOp(bldr, opc, outvar, lhs, rhs);
    if (res == LiftStatus::kLiftedInstruction) {
      return res;
    }

    auto sres = this->LiftBoolBinOp(bldr, opc, outvar, lhs, rhs);
    if (sres == LiftStatus::kLiftedInstruction) {
      return sres;
    }

    sres = this->LiftFloatBinOp(bldr, opc, outvar, lhs, rhs);
    if (sres == LiftStatus::kLiftedInstruction) {
      return sres;
    }

    if (opc == OpCode::CPUI_LOAD && outvar) {
      auto out_op = *outvar;
      auto addr_operand = rhs;
      auto lifted_addr_offset = this->LiftInParam(
          bldr, addr_operand, this->insn_lifter_parent.GetWordType());

      if (!lifted_addr_offset) {
        return LiftStatus::kLiftedUnsupportedInstruction;
      }
      auto out_type = llvm::IntegerType::get(this->context, out_op.size * 8);
      auto lifted_addr = this->CreateMemoryAddress(*lifted_addr_offset, out_op);

      auto loaded_value = lifted_addr->LiftAsInParam(bldr, out_type);

      if (!loaded_value) {
        return LiftStatus::kLiftedUnsupportedInstruction;
      }


      auto lifted_out = this->LiftParamPtr(bldr, out_op);
      return lifted_out->StoreIntoParam(bldr, *loaded_value);
    }

    if (opc == OpCode::CPUI_PIECE && outvar) {
      CHECK(rhs.size + lhs.size == outvar->size);

      // Treat them as integers
      auto lifted_lhs = this->LiftInParam(
          bldr, lhs, llvm::IntegerType::get(this->context, lhs.size * 8));
      auto lifted_rhs = this->LiftInParam(
          bldr, rhs, llvm::IntegerType::get(this->context, rhs.size * 8));

      if (lifted_lhs.has_value() && lifted_rhs.has_value()) {
        // Widen the most significant operand and then left shift it to make room for the least significant operand.
        auto ms_operand = bldr.CreateZExt(
            *lifted_lhs, llvm::IntegerType::get(this->context, outvar->size));
        auto shifted_ms_operand = bldr.CreateShl(
            ms_operand, llvm::ConstantInt::get(
                            llvm::Type::getInt8Ty(this->context), rhs.size));

        // Now concatenate them with an OR.
        auto concat = bldr.CreateOr(shifted_ms_operand, *lifted_rhs);
        return this->LiftStoreIntoOutParam(bldr, concat, outvar);
      }
    }

    if (opc == OpCode::CPUI_SUBPIECE && outvar) {
      auto lifted_lhs = this->LiftInParam(
          bldr, lhs, llvm::IntegerType::get(this->context, lhs.size * 8));

      if (lifted_lhs.has_value()) {
        DLOG(INFO) << "SUBPIECE: " << remill::LLVMThingToString(*lifted_lhs);
        auto subpiece_lhs = bldr.CreateLShr(*lifted_lhs, rhs.offset * 8);

        if (lhs.size < outvar->size) {
          subpiece_lhs = bldr.CreateZExt(
              subpiece_lhs,
              llvm::IntegerType::get(this->context, 8 * outvar->size));
        } else if (lhs.size > outvar->size) {
          subpiece_lhs = bldr.CreateTrunc(
              subpiece_lhs,
              llvm::IntegerType::get(this->context, 8 * outvar->size));
        }

        return this->LiftStoreIntoOutParam(bldr, subpiece_lhs, outvar);
      }
    }

    if (opc == OpCode::CPUI_INDIRECT && outvar) {
      // TODO(alex): This isn't clear to me from the documentation.
      // I'll probably need to find some code that generates this op in order to understand how to handle it.
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    if (opc == OpCode::CPUI_NEW && outvar) {
      // NOTE(alex): We shouldn't encounter this op as it only get generated when lifting Java or
      // Dalvik bytecode
      return LiftStatus::kLiftedUnsupportedInstruction;
    }

    return LiftStatus::kLiftedUnsupportedInstruction;
  }

  LiftStatus LiftThreeOperandOp(llvm::IRBuilder<> &bldr, OpCode opc,
                                std::optional<VarnodeData> outvar,
                                VarnodeData param0, VarnodeData param1,
                                VarnodeData param2) {
    switch (opc) {
      case OpCode::CPUI_STORE: {
        auto addr_operand = param1;
        auto lifted_addr_offset = this->LiftInParam(
            bldr, addr_operand, this->insn_lifter_parent.GetWordType());

        if (lifted_addr_offset) {
          auto store_param = this->LiftInParam(
              bldr, param2,
              llvm::IntegerType::get(this->context, param2.size * 8));

          if (store_param.has_value()) {
            auto lifted_addr =
                this->CreateMemoryAddress(*lifted_addr_offset, param2);
            return lifted_addr->StoreIntoParam(bldr, *store_param);
          }
        }
        break;
      }
      case OpCode::CPUI_PTRADD: {
        auto lifted_addr = this->LiftInParam(
                 bldr, param0, this->insn_lifter_parent.GetWordType()),
             lifted_index = this->LiftIntegerInParam(bldr, param1);
        auto elem_size = llvm::ConstantInt::get(
            llvm::IntegerType::get(this->context, param2.size * 8),
            param2.offset);
        if (lifted_addr.has_value() && lifted_index.has_value()) {
          auto *offset = bldr.CreateMul(*lifted_index, elem_size),
               *ptr_add = bldr.CreateAdd(*lifted_addr, offset);
          return this->LiftStoreIntoOutParam(bldr, ptr_add, outvar);
        }
        break;
      }
      case OpCode::CPUI_PTRSUB: {
        auto lifted_addr = this->LiftInParam(
                 bldr, param0, this->insn_lifter_parent.GetWordType()),
             lifted_offset = this->LiftIntegerInParam(bldr, param1);
        if (lifted_addr.has_value() && lifted_offset.has_value()) {
          return this->LiftStoreIntoOutParam(
              bldr, bldr.CreateAdd(*lifted_addr, *lifted_offset), outvar);
        }
        break;
      }
      default: break;
    }

    return LiftStatus::kLiftedUnsupportedInstruction;
  }

  LiftStatus LiftVariadicOp(llvm::IRBuilder<> &bldr, OpCode opc,
                            std::optional<VarnodeData> outvar,
                            VarnodeData *vars, int4 isize) {
    switch (opc) {
      // We shouldnt encounter this afaik MULTIEQUAL is a decompiler concept?
      case OpCode::CPUI_MULTIEQUAL: {
        llvm::Type *phi_type =
            llvm::IntegerType::get(this->context, vars[0].size * 8);
        llvm::PHINode *phi_node = bldr.CreatePHI(phi_type, isize);
        for (int4 i = 0; i < isize; ++i) {
          VarnodeData &var = vars[i];
          auto inval = this->LiftInParam(
              bldr, var, llvm::IntegerType::get(this->context, var.size * 8));
          if (!inval.has_value()) {
            return LiftStatus::kLiftedUnsupportedInstruction;
          }
          // TODO(alex): This isn't right, just using the current block to get things building.
          // We need to track the incoming basic blocks for each value.
          phi_node->addIncoming(*inval, bldr.GetInsertBlock());
        }
        return this->LiftStoreIntoOutParam(bldr, phi_node, outvar);
      }
      case OpCode::CPUI_CPOOLREF: {
        // NOTE(alex): We shouldn't encounter this op as it only get generated when lifting Java or
        // Dalvik bytecode
        return LiftStatus::kLiftedUnsupportedInstruction;
      }
      default: break;
    }

    return LiftStatus::kLiftedUnsupportedInstruction;
  }


  std::optional<std::string> GetOtherFuncName(VarnodeData *ivars, int4 isize) {
    if (isize < 1 || ivars[0].offset >= this->user_op_names.size()) {
      return std::nullopt;
    }

    return this->user_op_names[ivars[0].offset];
  }

  static const size_t kEqualityClaimArity = 3;
  LiftStatus HandleCallOther(llvm::IRBuilder<> &bldr,
                             std::optional<VarnodeData> outvar,
                             VarnodeData *vars, int4 isize) {
    auto other_func_name = this->GetOtherFuncName(vars, isize);
    if (other_func_name.has_value()) {
      if (other_func_name == kEqualityClaimName &&
          isize == kEqualityClaimArity) {
        DLOG(INFO) << "Applying eq claim";
        this->replacement_cont.ApplyEqualityClaim(bldr, *this, vars[1],
                                                  vars[2]);
        return kLiftedInstruction;
      }
      if (other_func_name == kSysCallName &&
          insn.arch_name == ArchName::kArchPPC) {
        DLOG(INFO) << "Invoking syscall";

        const auto mem_ptr_ref = LoadMemoryPointerRef(bldr.GetInsertBlock());

        // Get a LLVM value for the sync hyper call enumeration.
        auto hyper_call_int =
            static_cast<uint32_t>(SyncHyperCall::Name::kPPCSysCall);
        auto hyper_call = llvm::ConstantInt::get(
            llvm::IntegerType::get(this->context, 32), hyper_call_int);
        std::array<llvm::Value *, 3> args = {state_pointer, mem_ptr_ref,
                                             hyper_call};

        bldr.CreateCall(insn_lifter_parent.GetIntrinsicTable()->sync_hyper_call,
                        args);

        return kLiftedInstruction;
      } else if (other_func_name == kSetCopRegName &&
                 insn.arch_name == ArchName::kArchMIPS) {
        DLOG(INFO) << "Invoking setCopReg";

        if (isize == 5) {
          VarnodeData &cop_num = vars[1];
          VarnodeData &reg_num = vars[2];
          VarnodeData &value = vars[3];
          VarnodeData &sel = vars[4];

          auto inval_cop_num = this->LiftIntegerInParam(bldr, cop_num);
          auto inval_reg_num = ConstantValue::CreatConstant(
              this->replacement_cont.LiftOffsetOrReplace(
                  bldr, reg_num,
                  llvm::IntegerType::get(this->context, reg_num.size * 8)));
          auto inval_value = LiftIntegerInParam(bldr, value);
          auto inval_sel = this->LiftIntegerInParam(bldr, sel);

          std::array<llvm::Value *, 5> args = {
              state_pointer, inval_cop_num.value(),
              inval_reg_num.get()
                  ->LiftAsInParam(bldr, llvm::IntegerType::get(
                                            this->context, reg_num.size * 8))
                  .value(),
              inval_value.value(), inval_sel.value()};

          bldr.CreateCall(
              insn_lifter_parent.GetIntrinsicTable()->set_coprocessor_reg,
              args);
        }
        return kLiftedInstruction;
      }
      DLOG(ERROR) << "Unsupported pcode intrinsic: " << *other_func_name;
    }
    return kLiftedUnsupportedInstruction;
  }

  llvm::Argument *GetBranchTakenRef() {
    return this->exit_block->getParent()->getArg(kBranchTakenArgNum);
  }

  llvm::Argument *GetNextPcRef() {
    return this->exit_block->getParent()->getArg(kNextPcArgNum);
  }

  llvm::Value *GetNextPc(llvm::IRBuilder<> &ir) {
    return ir.CreateLoad(this->insn_lifter_parent.GetWordType(),
                         this->GetNextPcRef());
  }

  LiftStatus LiftBranchTaken(llvm::IRBuilder<> &bldr,
                             const sleigh::BranchTakenVar &btaken_var) {


    auto maybe_should_branch =
        this->LiftIntegerInParam(bldr, btaken_var.target_vnode);
    if (!maybe_should_branch) {
      DLOG(ERROR) << "Failed to lift iparam branch taken var";
      return LiftStatus::kLiftedLifterError;
    }

    if (btaken_var.invert) {
      // Branch taken evaluation is inverted
      *maybe_should_branch = bldr.CreateICmpEQ(
          *maybe_should_branch,
          llvm::ConstantInt::get(llvm::IntegerType::get(this->context, 8), 0));
    }

    auto should_branch = bldr.CreateZExtOrTrunc(
        *maybe_should_branch, llvm::IntegerType::get(this->context, 8));
    auto branch_taken_ref = this->GetBranchTakenRef();
    bldr.CreateStore(should_branch, branch_taken_ref);
    return LiftStatus::kLiftedInstruction;
  }


  void LiftBtakenIfReached(llvm::IRBuilder<> &bldr, OpCode opc, size_t index) {

    if (this->to_lift_btaken && index == this->to_lift_btaken->index) {
      this->UpdateStatus(this->LiftBranchTaken(bldr, *this->to_lift_btaken),
                         opc);
    }
  }

  void LiftPcodeOp(llvm::IRBuilder<> &bldr, OpCode opc,
                   std::optional<VarnodeData> outvar, VarnodeData *vars,
                   int4 isize) {
    // The MULTIEQUAL op has variadic operands
    if (opc == OpCode::CPUI_MULTIEQUAL || opc == OpCode::CPUI_CPOOLREF) {
      this->UpdateStatus(this->LiftVariadicOp(bldr, opc, outvar, vars, isize),
                         opc);
      return;
    }

    if (opc == OpCode::CPUI_CALLOTHER) {
      this->UpdateStatus(this->HandleCallOther(bldr, outvar, vars, isize), opc);
      return;
    }

    switch (isize) {
      case 1: {
        this->UpdateStatus(this->LiftUnaryOp(bldr, opc, outvar, vars[0]), opc);
        break;
      }
      case 2: {
        this->UpdateStatus(this->LiftBinOp(bldr, opc, outvar, vars[0], vars[1]),
                           opc);
        return;
      }
      case 3: {
        this->UpdateStatus(this->LiftThreeOperandOp(bldr, opc, outvar, vars[0],
                                                    vars[1], vars[2]),
                           opc);

        return;
      }
      default:
        this->UpdateStatus(LiftStatus::kLiftedUnsupportedInstruction, opc);
        return;
    }
  }


  void VisitBlock(const sleigh::PcodeBlock &blk) {
    this->target_block = GetOrCreateBlock(blk.base_index);
    this->pcode_block = &blk;
    llvm::IRBuilder bldr(this->target_block);

    // we have a problem with block terminators where a cbranch <relative> -> fallthrough, need to either exit to the exit block
    // or transfer to a block. So really our cfg needs to tell us how to terminate a block
    // either exit (means real control flow), to block (fake control flow)
    size_t index = 0;
    for (auto pc : blk.ops) {
      this->LiftBtakenIfReached(bldr, pc.op, index);
      this->LiftPcodeOp(bldr, pc.op, pc.outvar, pc.vars.data(), pc.vars.size());
      index += 1;
    }

    this->TerminateBlock();
  }

  bool ClaimEqualityUsed() const {
    return this->replacement_cont.IsEqualityUsed();
  }

  LiftStatus GetStatus() {
    return this->status;
  }
};  // namespace remill

std::unordered_set<OpCode>
    SleighLifter::PcodeToLLVMEmitIntoBlock::INTEGER_COMP_OPS = {
        CPUI_INT_EQUAL,   CPUI_INT_NOTEQUAL,  CPUI_INT_LESS,
        CPUI_INT_SLESS,   CPUI_INT_LESSEQUAL, CPUI_INT_SLESSEQUAL,
        CPUI_INT_SBORROW, CPUI_INT_SCARRY,    CPUI_INT_CARRY};

// NOTE(Ian): we store a mapping from pcode op to supported boolean operation so that we can easily check if
// we want to lift the operands to this op as a boolean and also find the right post lifting operation to apply.
std::map<OpCode, SleighLifter::PcodeToLLVMEmitIntoBlock::BinaryOperator>
    SleighLifter::PcodeToLLVMEmitIntoBlock::BOOL_BINARY_OPS = {
        {OpCode::CPUI_BOOL_AND,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateAnd(lhs, rhs);
         }},
        {OpCode::CPUI_BOOL_OR,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateOr(lhs, rhs);
         }},
        {OpCode::CPUI_BOOL_XOR,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateXor(lhs, rhs);
         }}};
std::map<OpCode, SleighLifter::PcodeToLLVMEmitIntoBlock::BinaryOperator>
    SleighLifter::PcodeToLLVMEmitIntoBlock::INTEGER_BINARY_OPS = {
        {OpCode::CPUI_INT_AND,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateAnd(lhs, rhs);
         }},
        {OpCode::CPUI_INT_OR,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateOr(lhs, rhs);
         }},
        {OpCode::CPUI_INT_XOR,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateXor(lhs, rhs);
         }},
        {OpCode::CPUI_INT_LEFT,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return CreatePcodeBitShift(
               lhs, rhs, bldr,
               [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
                 return bldr.CreateShl(lhs, rhs);
               });
         }},
        {OpCode::CPUI_INT_RIGHT,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return CreatePcodeBitShift(
               lhs, rhs, bldr,
               [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
                 return bldr.CreateLShr(lhs, rhs);
               });
         }},
        {OpCode::CPUI_INT_SRIGHT,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           if (lhs->getType() != rhs->getType()) {
             rhs = bldr.CreateZExtOrTrunc(rhs, lhs->getType());
           }
           return bldr.CreateAShr(lhs, rhs);
         }},
        {OpCode::CPUI_INT_ADD,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateAdd(lhs, rhs);
         }},
        {OpCode::CPUI_INT_SUB,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateSub(lhs, rhs);
         }},
        {OpCode::CPUI_INT_MULT,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateMul(lhs, rhs);
         }},
        {OpCode::CPUI_INT_DIV,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateUDiv(lhs, rhs);
         }},
        {OpCode::CPUI_INT_SDIV,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateSDiv(lhs, rhs);
         }},
        {OpCode::CPUI_INT_REM,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateURem(lhs, rhs);
         }},
        {OpCode::CPUI_INT_SREM,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateSRem(lhs, rhs);
         }},
        {OpCode::CPUI_INT_EQUAL,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           // TODO(alex): Should these by using `trunc`?
           // The docs seem to indicate that it's not ok to `zext` to a smaller type.
           return bldr.CreateZExt(bldr.CreateICmpEQ(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_NOTEQUAL,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateZExt(bldr.CreateICmpNE(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_LESS,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateZExt(bldr.CreateICmpULT(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_SLESS,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateZExt(bldr.CreateICmpSLT(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_LESSEQUAL,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateZExt(bldr.CreateICmpSLE(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_SLESSEQUAL,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return bldr.CreateZExt(bldr.CreateICmpULE(lhs, rhs),
                                  llvm::IntegerType::get(bldr.getContext(), 8));
         }},
        {OpCode::CPUI_INT_CARRY,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return ExtractOverflowBitFromCallToIntrinsic(
               llvm::Intrinsic::uadd_with_overflow, lhs, rhs, bldr);
         }},
        {OpCode::CPUI_INT_SCARRY,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return ExtractOverflowBitFromCallToIntrinsic(
               llvm::Intrinsic::sadd_with_overflow, lhs, rhs, bldr);
         }},
        {OpCode::CPUI_INT_SBORROW,
         [](llvm::Value *lhs, llvm::Value *rhs, llvm::IRBuilder<> &bldr) {
           return ExtractOverflowBitFromCallToIntrinsic(
               llvm::Intrinsic::ssub_with_overflow, lhs, rhs, bldr);
         }},
};

SleighLifter::SleighLifter(const remill::Arch &arch_,
                           const remill::sleigh::SleighDecoder &dec_,
                           const IntrinsicTable &intrinsics_)
    : InstructionLifter(&arch_, intrinsics_),
      sleigh_context(new sleigh::SingleInstructionSleighContext(
          dec_.GetSLAName(), dec_.GetPSpec())),
      decoder(dec_),
      arch(arch_) {}


const std::string_view SleighLifter::kInstructionFunctionPrefix =
    "sleigh_remill_instruction_function";

void SleighLifter::SetISelAttributes(llvm::Function *target_func) {
  target_func->setLinkage(llvm::GlobalValue::InternalLinkage);
  target_func->removeFnAttr(llvm::Attribute::NoInline);
  target_func->addFnAttr(llvm::Attribute::InlineHint);
  target_func->addFnAttr(llvm::Attribute::AlwaysInline);
}


llvm::Function *
SleighLifter::DefineInstructionFunction(Instruction &inst,
                                        llvm::Module *target_mod) {

  std::stringstream nm;
  nm << SleighLifter::kInstructionFunctionPrefix << "_" << std::hex << inst.pc;
  auto &context = target_mod->getContext();
  auto ptr_ty = llvm::PointerType::get(context, 0);
  std::array<llvm::Type *, 4> params = {inst.arch->StatePointerType(),
                                        inst.arch->MemoryPointerType(), ptr_ty,
                                        ptr_ty};
  auto ty =
      llvm::FunctionType::get(inst.arch->MemoryPointerType(), params, false);
  auto func = target_mod->getFunction(nm.str());

  if (!func || func->getFunctionType() != ty) {
    func = llvm::Function::Create(ty, llvm::GlobalValue::ExternalLinkage, 0,
                                  nm.str(), target_mod);
  } else if (func->isDeclaration()) {
    func->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
  }

  auto memory = remill::NthArgument(func, 1);
  auto state = remill::NthArgument(func, 0);
  memory->setName("memory");
  state->setName("state");
  func->getArg(kBranchTakenArgNum)->setName("btaken");
  func->getArg(kNextPcArgNum)->setName("npc");
  auto block = llvm::BasicBlock::Create(context, "entry_block", func);
  llvm::IRBuilder<> ir(block);

  ir.CreateStore(memory, ir.CreateAlloca(memory->getType(), nullptr, "MEMORY"));

  return func;
}

std::pair<LiftStatus, std::optional<llvm::Function *>>
SleighLifter::LiftIntoInternalBlockWithSleighState(
    Instruction &inst, llvm::Module *target_mod, bool is_delayed,
    const sleigh::MaybeBranchTakenVar &btaken,
    const ContextValues &context_values) {

  this->sleigh_context->resetContext();
  this->decoder.InitializeSleighContext(inst.pc, *this->sleigh_context,
                                        context_values);

  sleigh::PcodeDecoder pcode_record(this->GetEngine());
  sleigh_context->oneInstruction(inst.pc, pcode_record, inst.bytes);
  for (const auto &op : pcode_record.ops) {
    DLOG(INFO) << "Pcodeop: " << DumpPcode(this->GetEngine(), op);
  }

  DLOG(INFO) << "Secondary lift of bytes: " << llvm::toHex(inst.bytes);
  auto target_func = this->DefineInstructionFunction(inst, target_mod);

  llvm::BasicBlock *target_block = &target_func->getEntryBlock();
  llvm::IRBuilder<> ir(target_block);
  auto internal_state_pointer =
      remill::NthArgument(target_func, kStatePointerArgNum);


  auto exit_block = llvm::BasicBlock::Create(target_mod->getContext(),
                                             "exit_block", target_func);

  llvm::IRBuilder<> exit_builder(exit_block);


  exit_builder.CreateRet(remill::LoadMemoryPointer(
      exit_builder.GetInsertBlock(), *this->GetIntrinsicTable()));


  //TODO(Ian): make a safe to use sleighinstruction context that wraps a context with an arch to preform reset reinits


  auto cfg = sleigh::CreateCFG(pcode_record.ops, this->arch);


  SleighLifter::PcodeToLLVMEmitIntoBlock::DecodingContextConstants
      decoding_context_lifter(this->decoder.GetContextRegisterMapping(),
                              target_mod->getContext(), context_values,
                              target_block);

  SleighLifter::PcodeToLLVMEmitIntoBlock lifter(
      target_block, internal_state_pointer, inst, *this,
      this->sleigh_context->getUserOpNames(), exit_block, btaken,
      std::move(decoding_context_lifter));


  for (auto blk : cfg.blocks) {
    lifter.VisitBlock(blk.second);
  }

  // Log error if claim_eq values that were declared saw no uses
  if (!lifter.ClaimEqualityUsed()) {
    LOG(ERROR) << "claim_eq value not used when lifting " << inst.Serialize();
  }

  ir.CreateBr(lifter.GetOrCreateBlock(0));


  // Setup like an ISEL
  SleighLifter::SetISelAttributes(target_func);
  remill::InitFunctionAttributes(target_func);

  CHECK(remill::VerifyFunction(target_func));
  return {lifter.GetStatus(), target_func};
}

LiftStatus SleighLifter::LiftIntoBlockWithSleighState(
    Instruction &inst, llvm::BasicBlock *block, llvm::Value *state_ptr,
    bool is_delayed, const sleigh::MaybeBranchTakenVar &btaken,
    const ContextValues &context_values) {
  if (!inst.IsValid()) {
    DLOG(ERROR) << "Invalid function" << inst.Serialize();
    return kLiftedInvalidInstruction;
  }


  // Call the instruction function
  auto res = this->LiftIntoInternalBlockWithSleighState(
      inst, block->getModule(), is_delayed, btaken, context_values);

  if (res.first != LiftStatus::kLiftedInstruction || !res.second.has_value()) {
    return res.first;
  }

  auto target_func = *res.second;


  // Setup PC and NEXT_PC
  const auto [pc_ref, pc_ref_type] =
      LoadRegAddress(block, state_ptr, kPCVariableName);
  const auto [next_pc_ref, next_pc_ref_type] =
      LoadRegAddress(block, state_ptr, kNextPCVariableName);


  llvm::IRBuilder<> intoblock_builer(block);


  const auto next_pc =
      intoblock_builer.CreateLoad(this->GetWordType(), next_pc_ref);


  intoblock_builer.CreateStore(intoblock_builer.CreateZExtOrTrunc( this->decoder.LiftPcFromCurrPc(
                                   intoblock_builer, next_pc, inst.bytes.size(),
                                   DecodingContext(context_values)), pc_ref_type),
                               pc_ref);
                               
  intoblock_builer.CreateStore(
      intoblock_builer.CreateAdd(
          next_pc,
          llvm::ConstantInt::get(this->GetWordType(), inst.bytes.size())),
      next_pc_ref);

  ///////////////////////////////////////////////////////////////////////////////////////////
  // Handle COUNT Reg approximation
  // May be prefered here over patches to sleigh definitions for now
  // TODO(M4xw): Implement exact cycle count per opcode according to the optimization manual
  if (inst.arch->IsMIPS()) {
    const auto [count_ref, count_ref_type] =
        LoadRegAddress(block, state_ptr, "COUNT");

    const auto count =
        intoblock_builer.CreateLoad(this->GetWordType(), count_ref);

    intoblock_builer.CreateStore(
        intoblock_builer.CreateAdd(
            count, llvm::ConstantInt::get(
                       this->GetWordType(),
                       4)),  // Historically approximated Count per Opcode
        count_ref);
  }
  LOG(INFO) << inst.Serialize();
  //////////////////////////////////////////////////////////////////////////////////////////

  // TODO(Ian): THIS IS AN UNSOUND ASSUMPTION THAT RETURNS ALWAYS RETURN TO THE FALLTHROUGH, this is just to make things work
  intoblock_builer.CreateStore(
      intoblock_builer.CreateLoad(this->GetWordType(), next_pc_ref),
      LoadReturnProgramCounterRef(block));


  std::array<llvm::Value *, 4> args = {
      state_ptr, remill::LoadMemoryPointer(block, *this->GetIntrinsicTable()),
      remill::LoadBranchTakenRef(block),
      remill::LoadNextProgramCounterRef(block)};

  intoblock_builer.CreateStore(intoblock_builer.CreateCall(target_func, args),
                               remill::LoadMemoryPointerRef(block));

  //NOTE(Ian): If we made it past decoding we should be able to decode the bytes again
  DLOG(INFO) << res.first;

  return res.first;
}

Sleigh &SleighLifter::GetEngine(void) const {
  return this->sleigh_context->GetEngine();
}

SleighLifterWithState::SleighLifterWithState(
    sleigh::MaybeBranchTakenVar btaken_, ContextValues context_values_,
    std::shared_ptr<SleighLifter> lifter_)
    : btaken(btaken_),
      context_values(std::move(context_values_)),
      lifter(std::move(lifter_)) {}

// Lift a single instruction into a basic block. `is_delayed` signifies that
// this instruction will execute within the delay slot of another instruction.
LiftStatus
SleighLifterWithState::LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                     llvm::Value *state_ptr, bool is_delayed) {
  return this->lifter->LiftIntoBlockWithSleighState(
      inst, block, state_ptr, is_delayed, this->btaken, this->context_values);
}


// Load the address of a register.
std::pair<llvm::Value *, llvm::Type *>
SleighLifterWithState::LoadRegAddress(llvm::BasicBlock *block,
                                      llvm::Value *state_ptr,
                                      std::string_view reg_name) const {
  return this->lifter->LoadRegAddress(block, state_ptr, reg_name);
}

// Load the value of a register.
llvm::Value *
SleighLifterWithState::LoadRegValue(llvm::BasicBlock *block,
                                    llvm::Value *state_ptr,
                                    std::string_view reg_name) const {
  return this->lifter->LoadRegValue(block, state_ptr, reg_name);
}

llvm::Type *SleighLifterWithState::GetMemoryType() {
  return this->lifter->GetMemoryType();
}

void SleighLifterWithState::ClearCache(void) const {
  this->lifter->ClearCache();
}

}  // namespace remill
