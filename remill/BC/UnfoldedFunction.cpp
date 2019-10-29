#include "remill/BC/UnfoldedFunction.h"

#include <llvm/ADT/APSInt.h>

#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Annotate.h"
#include "remill/BC/Util.h"

#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/Instructions.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Compat/DerivedTypes.h"


namespace remill {

llvm::Type *MostInnerSimpleType(llvm::Type *t) {
  while (std::next(t->subtype_begin()) == t->subtype_end()) {
    t = *t->subtype_begin();
  }
  return t;
}

// For each register that is passed as separate argument do
//
// %RAX_ALLOCA = alloca i64
// store i64 %RAX, i64* %RAX_ALLOCA
//
// llvm opt passes should do what you would expect them
// and eliminate allocas altogether
void UnfoldedFunction::CreateAllocas() {

  allocas.clear();

  auto &entry_block = unfolded_func->getEntryBlock();
  llvm::IRBuilder<> ir(&entry_block, entry_block.begin());

  // Create allocas for all registers
  for (auto i = 0U; i < regs.size(); ++i)
    allocas.push_back(ir.CreateAlloca(MostInnerSimpleType(regs[i]->type)));

  auto store_args = [&](uint64_t index, auto arg_it) {
    CHECK(arg_it != unfolded_func->arg_end())
      << "Not enough parameters when creating alloca.";
    ir.CreateStore(&*arg_it, allocas[index]);
  };

  t_mask.params_m().apply(store_args, ArgBegin());

}


// Creates new function with proper name
llvm::Function* UnfoldedFunction::UnfoldState(const std::string &prefix) {

  // Copy originals
  std::vector<llvm::Type *> new_params;
  for (auto orig_param : Params(sub_func.getFunctionType())) {
    new_params.emplace_back(orig_param);
  }

  LOG_IF(WARNING, new_params != type_prefix)
    << "Unfolded function has different prefix than specified type_prefix: "
    << sub_func.getName().str();

  // Add new ones based on regs and their size
  for (const auto &reg : t_mask.params) {
    auto size = static_cast<unsigned int>(reg->size);
    new_params.push_back(llvm::Type::getIntNTy(context, size * 8));
  }

  // Create appropriate return type
  std::vector<llvm::Type *> unit_types = type_prefix;

  for (const auto &reg : t_mask.rets) {
    unit_types.push_back(MostInnerSimpleType(reg->type));
  }

  // Create new function
  auto impl_func_type = llvm::FunctionType::get(
      llvm::StructType::get(context, unit_types),
      new_params, sub_func.isVarArg());

  // TODO: Address space?
  std::string impl_name = prefix + sub_func.getName().str();

  auto impl_func = llvm::Function::Create(
      impl_func_type, sub_func.getLinkage(),
      impl_name, &module);

  impl_func->setAttributes(sub_func.getAttributes());

  // Value to value mapping
  llvm::ValueToValueMapTy v_map;
  auto impl_func_arg_it = impl_func->arg_begin();
  for (auto &arg : sub_func.args()) {
    v_map[&arg] = &(*impl_func_arg_it);
    impl_func_arg_it->setName(arg.getName());
    ++impl_func_arg_it;
  }

  // Now impl_func_arg_it points to the first of register arguments
  for (auto reg : t_mask.params) {
    impl_func_arg_it->setName(reg->name);
    ++impl_func_arg_it;
  }

  // TODO: What is this for?
  llvm::SmallVector<llvm::ReturnInst *, 8> returns;
  llvm::CloneFunctionInto(impl_func, &sub_func, v_map, false, returns, "");

  // Remove returned from Memory
  auto mem = std::next(impl_func->arg_begin(), kMemoryPointerArgNum);
  mem->removeAttr( llvm::Attribute::AttrKind::Returned );

  // Remove bunch of other attributes from return type of function, that got there
  // by opt probably
  impl_func->removeAttribute(
      llvm::AttributeLoc::ReturnIndex,
      llvm::Attribute::AttrKind::NoAlias);
  impl_func->removeAttribute(
      llvm::AttributeLoc::ReturnIndex,
      llvm::Attribute::AttrKind::NonNull);

  return impl_func;
}


// Create Ret instruction for new function with proper
// aggregate type
void UnfoldedFunction::FoldRets() {
  for (auto &bb : *unfolded_func) {
    for (auto &inst : bb) {
      if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
        llvm::IRBuilder<> ir(ret);
        FoldAggregate(unfolded_func->getReturnType(), ir);
        ret->eraseFromParent();
        break;
      }
    }
  }
}

// Fold unfolded values back into one value to be returned
void UnfoldedFunction::FoldAggregate(
                   llvm::Type* ret_ty,
                   llvm::IRBuilder<> &ir) {

  llvm::Value *ret_val = llvm::UndefValue::get(ret_ty);

  // Fill in type_prefix
  for (auto i = 0U; i < type_prefix.size(); ++i) {
    ret_val = ir.CreateInsertValue(ret_val, NthArgument(unfolded_func, i), i);
  }

  // Fill in values from allocas present in return type mask
  auto createAllocas = [&](uint64_t index, uint64_t j) {
    auto load = ir.CreateLoad(allocas[index],
                              t_mask.regs[index]->name + "L");
    ret_val = ir.CreateInsertValue(ret_val, load, j++);
  };

  t_mask.rets_m().apply(createAllocas, type_prefix.size());
  ir.CreateRet(ret_val);
}

void UnfoldedFunction::ReplaceBitCast(llvm::Value* allocas,
                                      llvm::Value* instruction) {

  for (const auto &inst : instruction->users()) {

    if (auto bitcast = llvm::dyn_cast<llvm::BitCastInst>(inst)) {

      llvm::IRBuilder<> ir(bitcast);
      auto casted = ir.CreateBitCast(allocas, bitcast->getDestTy());
      bitcast->replaceAllUsesWith(casted);

    } else if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(inst)) {

      llvm::IRBuilder<> ir(gep);
      allocas = ir.CreateBitCast(allocas, gep->getType());
      gep->replaceAllUsesWith(allocas);
    }
  }
}


void UnfoldedFunction::ReplaceGEPs() {

  auto state = NthArgument(unfolded_func, kStatePointerArgNum);
  Constant C(context);

  for (const auto &inst : state->users()) {

    if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(inst)) {

      llvm::APSInt offset(64, 0);
      if (gep->accumulateConstantOffset(llvm::DataLayout(&module), offset)) {

        for (auto i = 0U; i < allocas.size(); ++i) {

          if (offset >= regs[i]->offset &&
              offset < (regs[i]->offset + regs[i]->size)) {

            int64_t diff = offset.getExtValue() - regs[i]->offset;
            llvm::Value *ptr = allocas[i];

            if (diff != 0) {
              llvm::IRBuilder<> ir(gep);
              ptr = ir.CreateGEP(
                  ir.CreateBitCast(allocas[i], C.i8PtrTy()),
                  C.i64(diff));
            }
            // There can be a bunch of bitcasts thanks to complexity of llvm type
            // that represents state
            auto result_ty = GetResultElementType(gep);
            if (!result_ty->isIntegerTy()) {
              ReplaceBitCast(ptr, gep);
              continue;
            }

            llvm::IRBuilder<> ir(gep);
            ptr = ir.CreateBitCast(ptr, gep->getType());
            gep->replaceAllUsesWith(ptr);
            break;
          }
        }
      }
    }
  }
}


} // namespace remill
