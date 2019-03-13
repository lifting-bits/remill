/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <algorithm>
#include <future>
#include <iostream>
#include <iterator>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/ADT/APSInt.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"

#include "remill/BC/ABI.h"
#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/Instructions.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Compat/DerivedTypes.h"
#include "remill/BC/Mask.h"
#include "remill/BC/StateUnfolder.h"
#include "remill/BC/Util.h"

namespace remill {

namespace {

static bool IsLiftedFunction(llvm::Function *func,
                             const llvm::Function *bb_func) {
  // __remill_* family is declaration and has the same type
  if (!func || func == bb_func || func->isDeclaration()) {
    return false;
  }
  if (func->getFunctionType() == bb_func->getFunctionType()) {
    return true;
  }
  // Lifted function can also have a type that is same as
  // `__remill_basic_block` with some other params appended
  const auto &func_type = func->getFunctionType();
  const auto &bb_func_type = bb_func->getFunctionType();

  if (func_type->getNumParams() < bb_func_type->getNumParams()) {
    return false;
  }

  for (auto i = 0U; i < 3; ++i) {
    if (bb_func_type->getParamType(i) != func_type->getParamType(i)) {
      return false;
    }
  }
  return true;
}

// Returns lifted function or nullptr in case func is not an entrypoint
template<typename F>
static llvm::Function *IsEntrypoint(llvm::Function &func, F is_lifted) {

  // There must be exactly one call
  llvm::CallInst *call = nullptr;
  for (auto &bb : func) {
    for (auto &inst : bb) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        if (call) {
          return nullptr;
        }
        call = call_inst;
      }
    }
  }
  if (!call) {
    return nullptr;
  }
  auto callee = call->getCalledFunction();

  return (is_lifted(callee)) ? callee : nullptr;
}

// Returns mapping of entrypoints -> lifted function
template<typename F>
static std::map<llvm::Function *, llvm::Function *>
EntrypointsToSubs(llvm::Module &module, F is_lifted) {

  std::map<llvm::Function *, llvm::Function *> sub_to_entrypoint;
  for (auto &func : module) {
    if (func.isDeclaration() || is_lifted(&func)) {
      continue;
    }

    auto sub = IsEntrypoint(func, is_lifted);
    if (sub) {
      if (sub_to_entrypoint.count(sub)) {
        LOG(ERROR) << "Double entrypoint was detected" << std::endl;
      }
      sub_to_entrypoint.emplace(sub, &func);
    }
  }
  return sub_to_entrypoint;
}

// TODO: Remove once we are C++17
template<typename T, typename U>
static void insert_or_assign(std::map<T, U> &map, const T &key, U val) {
  auto old_val = map.find(key);
  if (old_val != map.end()) {
    map.erase(old_val);
  }
  map.emplace(key, std::move(val));
}


// This expects
// 1) There is a global stack named __mcsema_stack
// 2) Global stack has type llvm::ArrayType with reasonable size
// Then it replaces global stack with local alloca in every entrypoint
static void CreateLocalStack(llvm::Module &module, llvm::Function &func) {
  auto c = Constant(module.getContext());
  auto &entry = func.getEntryBlock();
  if (auto load = llvm::dyn_cast<llvm::LoadInst>(&entry.front())) {
    auto g_stack = module.getNamedGlobal("__mcsema_stack");
    if (!g_stack) {
      return;
    }
    auto g_stack_ty = llvm::dyn_cast<llvm::ArrayType>(GetValueType(g_stack));
    if (!g_stack_ty) {
      return;
    }

    llvm::IRBuilder<> ir(load);
    auto l_stack = ir.CreateAlloca(g_stack_ty);
    auto gep = ir.CreateGEP(
        l_stack,
        {c.i64(0), c.i64(g_stack_ty->getNumElements() - 8)});
    auto bitcast = ir.CreateBitCast(
        gep, c.i64PtrTy());
    auto int_to_ptr = ir.CreatePtrToInt(bitcast, c.i64Ty());
    ir.CreateStore(int_to_ptr, load->getPointerOperand());
  }
}

static llvm::Type *MostInnerSimpleType(llvm::Type *t) {
  while (std::next(t->subtype_begin()) == t->subtype_end()) {
    t = *t->subtype_begin();
  }
  return t;
}

void UnsafeErase(llvm::Function *func) {
  func->replaceAllUsesWith(
      llvm::UndefValue::get(llvm::PointerType::getUnqual(func->getFunctionType())));
  func->eraseFromParent();
}

} // namespace

constexpr const int bitset_size = 32;
using Container = std::bitset<bitset_size>;
using ResultMask = TMask<Container>;


// Holds information about unfolded function
struct UnfoldedFunction {
  // original lifted function
  llvm::Function *sub_func;
  llvm::Function *unfolded_func;

  // allocas, that are at the beginning of the function, for each register that is being
  // unfolded. Order is corresponding to order in type_mask
  std::vector<llvm::AllocaInst *> allocas;

  // Hold information about currently used registers in function type
  TypeMask<Container> type_mask;
};

std::ostream &operator<<(std::ostream &os, const UnfoldedFunction &func) {
  os << func.sub_func->getName().str() << " -> "
     << func.unfolded_func->getName().str() << std::endl;
  os << func.type_mask;
  return os;
}

// For each caller of unfolded function, check which part of return type are used.
// If there are some that no caller uses, mark it as false
static ResultMask CallerUnusedRet(
    const UnfoldedFunction &func, std::size_t size, uint64_t prefix_size,
    const std::map<llvm::Function *, llvm::Function *> &sub_to_entrypoint) {

  const auto &old_mask = func.type_mask.ret_type_mask;

  ResultMask res(size);
  res &= old_mask;

  // Check if function is entrypoint, if it is, make no assumptions
  auto it = sub_to_entrypoint.find(func.sub_func);
  if (it != sub_to_entrypoint.end() && it->second->hasAddressTaken()) {
    return res;
  }

  std::vector<uint32_t> mask(size, 0);

  uint32_t users = 0;

  for (const auto &u : func.unfolded_func->users()) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(u)) {

      for (const auto &call_ret : call->users()) {
        auto extract = llvm::dyn_cast<llvm::ExtractValueInst>(call_ret);
        if (!extract) {
          return res;
        }
        while (extract) {
          uint64_t i = 0;
          if (*(extract->idx_begin()) >= prefix_size) {
            if (!NthIndex(old_mask, true, *(extract->idx_begin()) - prefix_size, i)) {
              return res;
            }
            ++mask[i];
          }
          extract = llvm::dyn_cast<llvm::ExtractValueInst>(
              extract->getAggregateOperand());
        }
      }
      ++users;
    }
  }

  res &= ResultMask::RType::cc(mask, [=](uint32_t m) {
      return m;
      });
  return res;
}

// Set all parameters that are not used by function itself to false
static ResultMask UnusedParameters(
    const UnfoldedFunction &func,
    uint64_t size, uint64_t prefix_size) {

  const auto &unfolded_func = func.unfolded_func;
  const auto &old_mask = func.type_mask.param_type_mask;
  ResultMask result(size);

  uint64_t i = 0;
  NextIndex(old_mask, true, i);
  for (auto it = std::next(unfolded_func->arg_begin(), prefix_size);
      it != unfolded_func->arg_end();
      ++it, NextIndex(old_mask, true, ++i)) {
    if (it->user_begin() == it->user_end()) {
      result.param_type_mask[i] = false;
    }
  }
  result &= old_mask;
  return result;
}

// Check all ret instructions of a function
// If the parameter value is being returned at all returns,
// there is no need to return it at all, as caller has it already
static ResultMask GetReturnMask(
    const UnfoldedFunction& func,
    uint64_t size, uint64_t prefix_size) {
  ResultMask res(size);

  std::vector<uint32_t> mask(size, 0);
  PMask<Container> unused_p(size);
  uint32_t counter = 0;

  const auto &old_mask = func.type_mask.ret_type_mask;
  const auto &param_mask = func.type_mask.param_type_mask;

  for (auto &bb : *func.unfolded_func) {
    for (auto &inst : bb) {
      auto ret = llvm::dyn_cast<llvm::ReturnInst>(&inst);
      if (!ret) {
        continue;
      }

      for (auto &use_inst : ret->getReturnValue()->uses()) {
        auto insert = llvm::dyn_cast<llvm::InsertValueInst>(&use_inst);

        while (insert) {
          auto inserted = insert->getInsertedValueOperand();
          for (auto it = std::next(func.unfolded_func->arg_begin(), prefix_size);
              it != func.unfolded_func->arg_end();
              ++it) {
            if (&*it == inserted) {
              uint64_t i = 0;
              NthIndex(old_mask, true, *(insert->idx_begin()) - prefix_size, i);

              uint64_t p = 0;
              NthIndex(param_mask, true, it->getArgNo() - prefix_size, p);

              // To avoid getting ptr in %RDI and then returning it in %RAX
              // It must be exactly the same register
              if (i == p) {
                mask[i]++;

                // If it is not used anywhere else, we migh just not pass it in at all
                if (!(*it).hasNUsesOrMore(2)) {
                  unused_p[i] = false;
                }
                break;
              }
            }
          }
          insert = llvm::dyn_cast<llvm::InsertValueInst>(insert->getAggregateOperand());
        }
      }

      ++counter;
    }
  }

  // We need to check if it is truly unused everywhere, if not, it cannot be removed
  for (auto i = 0U; i < mask.size(); ++i) {
    if (mask[i] != counter) {
      unused_p[i] = true;
    }
  }

  res &= ResultMask::RType::cc(mask, [&](uint32_t m){
      return m != counter;
      });
  res &= unused_p;

  return res;
}

// Check all callers of function
// If they all set some parameter to undef, set it to false as well
static ResultMask GetParamMask(
    const UnfoldedFunction &func, uint64_t size, uint64_t prefix_size,
    const std::map<llvm::Function *, llvm::Function *> &sub_to_entrypoint) {

  const auto &old_mask = func.type_mask.param_type_mask;

  ResultMask res(size);
  res &= old_mask;
  auto it = sub_to_entrypoint.find(func.sub_func);
  if (it != sub_to_entrypoint.end() && it->second->hasAddressTaken()) {
    return res;
  }
  if (func.unfolded_func->hasAddressTaken()) {
    return res;
  }

  // Count all the undefs
  std::vector<uint32_t> undefs(size, 0);
  uint32_t users = 0;

  for (const auto &u : func.unfolded_func->users()) {
    if (auto call = llvm::dyn_cast<llvm::CallInst>(u)) {

      uint64_t i = 0;
      NextIndex(old_mask, true, i);
      for (auto it = prefix_size; it != call->getNumArgOperands();
          ++it, NextIndex(old_mask, true, ++i)) {
        auto type = call->getArgOperand(it)->getType();
        llvm::Value *undef = llvm::UndefValue::get(type);
        if (&*(call->getArgOperand(it)) == undef) {
          ++undefs[i];
        }
      }
    } else {
      return res;
    }
    ++users;
  }

  res &= ResultMask::PType::cc(undefs, [=](uint32_t undef){
        return !(users && undef == users);
      });

  return res;
}

// Structure responsible for unfolding
struct StateUnfolder {
  using OptCallback = void (*)(void);

  llvm::Module &module;
  llvm::LLVMContext &context;
  const Arch &arch;
  OptCallback opt_callback;

  std::vector<const Register *> regs;

  std::vector<llvm::Type *> type_prefix;

  // All the unfolded function with some basic information
  std::map<llvm::Function *, UnfoldedFunction> unfolded;

  std::map<llvm::Function *, llvm::Function *> sub_to_unfold;

  StateUnfolder(llvm::Module &module, const Arch &arch, OptCallback opt=nullptr) :
      module(module), context(module.getContext()), arch(arch), opt_callback(opt) {

    // Temporal solution, ideally que Arch for it
    static const std::vector<std::string> reg_names = {
      "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP",
      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP",
      "CF", "PF", "AF", "ZF", "SF", "DF", "OF"
    };

    regs.reserve(reg_names.size());
    for (const auto &name : reg_names) {
      regs.push_back(arch.RegisterByName(name));
    }

    // Prefix of type for every lifted function parameters as well as return type
    auto bb_func = BasicBlockFunction(&module);
    type_prefix.push_back(NthArgument(bb_func, kStatePointerArgNum)->getType());
    type_prefix.push_back(NthArgument(bb_func, kPCArgNum)->getType());
    type_prefix.push_back(NthArgument(bb_func, kMemoryPointerArgNum)->getType());
  }

  ~StateUnfolder() {
    // We do not need blueprints anymore
    for (auto &func : unfolded) {
      UnsafeErase(func.first);
    }

    auto bb_func = BasicBlockFunction(&module);
    auto assoc_map = EntrypointsToSubs(module, [=](llvm::Function *f) -> bool {
        return IsLiftedFunction(f, bb_func);
    });
    for (auto &a : assoc_map) {
      if (!a.second->hasAddressTaken() &&
          a.second->getName() != "main") {
        UnsafeErase(a.second);
      }
    }

  }

  // Get vector of all lifted functions, e.g sub_* or callback_*
  std::vector<llvm::Function *> ToUnfold() {
    std::vector<llvm::Function *> to_unfold;

    auto bb_func = remill::BasicBlockFunction(&module);
    for (auto &func : module) {
      if (IsLiftedFunction(&func, bb_func) &&
          !func.isDeclaration() &&
          func.getName().substr(0, 8) != "__mcsema" &&
          func.getName().substr(0, 8) != "__remill" &&
          func.getName().substr(0, 10) != "breakpoint") {
        to_unfold.push_back(&func);
      } else if (func.getName() == "__mcsema_detach_call_value") {
        to_unfold.push_back(&func);
      }
    }
    return to_unfold;
  }

  void UnfoldFunction(llvm::Function *func, TypeMask<Container> mask,
                      const std::string& prefix="") {
    // Create new function with proper type
    auto unfolded_func = UnfoldState(func, mask, prefix);
    // Create allocas for each register
    auto allocas = CreateAllocas(*unfolded_func, mask);

    // Modify returns
    FoldRets(allocas, *unfolded_func, mask);
    ReplaceGEPs(allocas, *unfolded_func, mask);

    insert_or_assign(
        unfolded, func,
        {func, unfolded_func, std::move(allocas), std::move(mask)});
    insert_or_assign(sub_to_unfold, func, unfolded_func);

  }

  // Partially unfolds the reg_state into separate parameters
  void Unfold() {
    // We need to get the list of all functions before as we will modify module
    auto to_unfold = ToUnfold();

    // Handle sub_*
    for (const auto &func: to_unfold) {
      UnfoldFunction(func, TypeMask<Container>(regs), "unfold_");
    }

    for (auto &func : unfolded) {
      HandleCallSites(func.second, unfolded);
    }

    // Try to create better function types
    Optimize();

    auto bb_func = remill::BasicBlockFunction(&module);
    for (auto &func : module) {
      if (!IsLiftedFunction(&func, bb_func) &&
          !func.isDeclaration() &&
          func.getName().substr(0, 8) != "__remill" &&
          func.getName().substr(0, 8) != "__mcsema" &&
          func.getName().substr(0, 10) != "breakpoint") {
        ReplaceEntrypoints(func, unfolded);
      }
    }
  }

  void OptimizeIteration(const std::string &prefix="") {
    (*opt_callback)();

    std::map<llvm::Function *, TypeMask<Container>> func_to_mask;
    auto bb_func = BasicBlockFunction(&module);
    auto assoc_map = EntrypointsToSubs(module, [=](llvm::Function *f) -> bool {
          return IsLiftedFunction(f, bb_func);
        });

    // TODO: This can be certainly done much smarter that it is
    std::vector<llvm::Function *> old_iter;
    std::set<llvm::Function *> to_change;

    // Get better masks where possible
    for (const auto &func : unfolded) {
      if (func.second.type_mask.Empty()) {
        continue;
      }

      auto tm =
        CallerUnusedRet(func.second, regs.size(), type_prefix.size(), assoc_map);
      tm &= GetReturnMask(func.second, regs.size(), type_prefix.size());

      tm &= GetParamMask(func.second, regs.size(), type_prefix.size(), assoc_map);
      tm &= UnusedParameters(func.second, regs.size(), type_prefix.size());

      auto mask = tm.Build(regs);

      func_to_mask.emplace(
          func.first,
          std::move(mask));

      old_iter.push_back(func.second.unfolded_func);
      to_change.insert(func.first);
    }

    // We no longer need older iteration as we already got all the info needed
    for (auto &func : old_iter) {
      UnsafeErase(func);
    }

    for (auto &func : func_to_mask) {
      UnfoldFunction(func.first, std::move(func.second), prefix);
    }

    for (auto &func : unfolded) {
      // TODO: Dependent on McSema naming conventions
      if (func.first->getName().substr(0, 4) != "ext_") continue;
      func.second.unfolded_func->removeFnAttr(llvm::Attribute::NoInline);
      func.second.unfolded_func->addFnAttr(llvm::Attribute::InlineHint);
      func.second.unfolded_func->addFnAttr(llvm::Attribute::AlwaysInline);
    }

    for (auto &func : unfolded) {
      if (!to_change.count(func.first)) {
        continue;
      }
      HandleCallSites(func.second, unfolded);
    }
  }

  void Optimize(void) {
    if (!opt_callback) {
      LOG(INFO) << "No opt pass was chosen";
      return;
    }

    // Running more iterations may improve the produced bitcode, since it profits
    // from llvm optimization passes
    for (auto i = 0U; i < 5; ++i) {
      OptimizeIteration("opt." + std::to_string(i) + "_");
    }

    // We did bunch of unfolding again, clean it up
    (*opt_callback)();
  }

  // Creates new function with proper name
  llvm::Function* UnfoldState(llvm::Function *func, const TypeMask<Container> &mask,
                              const std::string &prefix="") {
    // Copy originals
    std::vector<llvm::Type *> new_params;
    for (auto orig_param : Params(func->getFunctionType())) {
      new_params.emplace_back(orig_param);
    }

    // Add new ones based on regs and their size
    for (const auto &reg : mask.params) {
      auto size = static_cast<unsigned int>(reg->size);
      new_params.push_back(llvm::Type::getIntNTy(context, size * 8));
    }

    // Create appropriate return type
    std::vector<llvm::Type *> unit_types = type_prefix;

    for (const auto &reg : mask.rets) {
      unit_types.push_back(MostInnerSimpleType(reg->type));
    }

    // Create new function
    auto impl_func_type = llvm::FunctionType::get(
        llvm::StructType::get(context, unit_types),
        new_params, func->isVarArg());

    // TODO: Address space?
    std::string impl_name = prefix + func->getName().str();

    auto impl_func = llvm::Function::Create(
        impl_func_type, func->getLinkage(),
        impl_name, &module);

    impl_func->setAttributes(func->getAttributes());

    // Value to value mapping
    llvm::ValueToValueMapTy v_map;
    auto impl_func_arg_it = impl_func->arg_begin();
    for (auto &arg : func->args()) {
      v_map[&arg] = &(*impl_func_arg_it);
      impl_func_arg_it->setName(arg.getName());
      ++impl_func_arg_it;
    }

    // Now impl_func_arg_it points to the first of register arguments
    for (auto reg : mask.params) {
      impl_func_arg_it->setName(reg->name);
      ++impl_func_arg_it;
    }

    // TODO: What is this for?
    llvm::SmallVector<llvm::ReturnInst *, 8> returns;
    llvm::CloneFunctionInto(impl_func, func, v_map, false, returns, "");

    // Remove returned from Memory
    auto mem = std::next(impl_func->arg_begin(), kMemoryPointerArgNum);
    mem->removeAttr(
        llvm::AttributeSet::get(context, mem->getArgNo(), llvm::Attribute::Returned));

    // Remove bunch of other attributes from return type of function, that got there
    // by opt probably
    impl_func->removeAttributes(
        llvm::AttributeLoc::ReturnIndex,
        llvm::AttributeSet::get(context, 0, llvm::Attribute::NoAlias));
    impl_func->removeAttributes(
        llvm::AttributeLoc::ReturnIndex,
        llvm::AttributeSet::get(context, 0, llvm::Attribute::NonNull));

    return impl_func;
  }

  // For each register that is passed as separate argument do
  //
  // %RAX_ALLOCA = alloca i64
  // store i64 %RAX, i64* %RAX_ALLOCA
  //
  // llvm opt passes should do what you would expect them
  // and eliminate allocas altogether
  std::vector<llvm::AllocaInst *> CreateAllocas(
      llvm::Function &func, const TypeMask<Container> &mask) {

    auto &entry_block = func.getEntryBlock();
    llvm::IRBuilder<> ir(&entry_block, entry_block.begin());
    std::vector<llvm::AllocaInst *> allocas;

    auto arg_it = std::next(func.arg_begin(), type_prefix.size());

    for (auto i = 0U; i < regs.size(); ++i) {
      auto alloca_reg = ir.CreateAlloca(MostInnerSimpleType(regs[i]->type));
      if (mask.param_type_mask[i]) {
        CHECK(arg_it != func.arg_end()) << "Not enough parameters when creating alloca";
        ir.CreateStore(&*arg_it, alloca_reg);
        ++arg_it;
      }
      allocas.push_back(alloca_reg);
    }
    return allocas;
  }

  // Create Ret instruction for new function with proper
  // aggregate type
  void FoldRets(std::vector<llvm::AllocaInst *> &allocas,
                llvm::Function &func, const TypeMask<Container> &mask) {
    for (auto &bb : func) {
      for (auto &inst : bb) {
        if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
          llvm::IRBuilder<> ir(ret);
          FoldAggregate(
              allocas, func.getReturnType(), ir,
              func, mask);
          ret->eraseFromParent();
          break;
        }
      }
    }
  }

  void FoldAggregate(std::vector<llvm::AllocaInst *> &allocas,
                     llvm::Type* ret_ty,
                     llvm::IRBuilder<> &ir,
                     llvm::Function &func,
                     const TypeMask<Container> &mask) {
    llvm::Value *ret_val = llvm::UndefValue::get(ret_ty);
    for (auto i = 0U; i < type_prefix.size(); ++i) {
      ret_val = ir.CreateInsertValue(ret_val, NthArgument(&func, i), i);
    }

    for (uint64_t i = 0U, j = type_prefix.size(); i < mask.ret_type_mask.size(); ++i) {
      if (mask.ret_type_mask[i]) {
        auto load =
          ir.CreateLoad(allocas[i], mask.rets[j - type_prefix.size()]->name + "_L");

        ret_val = ir.CreateInsertValue(ret_val, load, j);
        ++j;
      }
    }
    ir.CreateRet(ret_val);
  }

  void ReplaceBitCast(llvm::Value* allocas,
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


  void ReplaceGEPs(std::vector<llvm::AllocaInst *> &allocas,
                   llvm::Function &func, const TypeMask<Container> &mask) {

    auto state = NthArgument(&func, kStatePointerArgNum);
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

  void HandleCallSites(
      UnfoldedFunction &func,
      const std::map<llvm::Function *, UnfoldedFunction> &sub_to_unfold) {

    const auto &allocas = func.allocas;
    std::vector<llvm::CallInst *> to_change;

    // Retrieve all calls as we will modify function later
    for (auto &bb : *(func.unfolded_func)) {
      for (auto &inst: bb) {
        if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          auto callee = sub_to_unfold.find(call->getCalledFunction());
          if (callee != sub_to_unfold.end()) {
            to_change.push_back(call);
          }
        }
      }
    }

    for (const auto &old_call : to_change) {
      llvm::IRBuilder<> ir(old_call);
      std::vector<llvm::Value *> args;

      for (auto &op: old_call->arg_operands()) {
        args.push_back(op);
      }

      auto callee = sub_to_unfold.find(old_call->getCalledFunction())->second;
      const auto &param_mask = callee.type_mask.param_type_mask;
      for (auto i = 0U; i < param_mask.size(); ++i) {
        if (param_mask[i]) {
          auto load = ir.CreateLoad(allocas[i]);
          args.push_back(load);
        }
      }
      auto ret = ir.CreateCall(callee.unfolded_func, args);

      auto mem = ir.CreateExtractValue(ret, kMemoryPointerArgNum);
      old_call->replaceAllUsesWith(mem);

      const auto &ret_mask = callee.type_mask.ret_type_mask;
      for (uint64_t i = 0U, j = type_prefix.size(); i < ret_mask.size(); ++i) {
        if (ret_mask[i]) {
          auto val = ir.CreateExtractValue(ret, j);
          ir.CreateStore(val, allocas[i]);
          ++j;
        }
      }
    }

    for (auto &old_call : to_change) {
      old_call->eraseFromParent();
    }
  }

  void ReplaceEntrypoints(
      llvm::Function &func,
      std::map<llvm::Function *, UnfoldedFunction> sub_to_unfold) {

    CreateLocalStack(module, func);
    // Expects that entrypoint contains only one call instruction
    for (auto &bb: func) {
      for (auto &inst: bb) {
        if (auto call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          auto it = sub_to_unfold.find(call->getCalledFunction());

          // Probably remill or mcsema function
          if (call->getCalledFunction()->getName().str().substr(0, 2) == "__") {
            continue;
          }

          if (it == sub_to_unfold.end()) {
            LOG(INFO) << "Could not find unfolded variant of function";
            return;
          }

          // TODO: Dependent on internal naming convention
          auto state = module.getNamedGlobal("__mcsema_reg_state");
          if (!state) {
            LOG(ERROR) << "State was not found";
            return;
          }

          llvm::IRBuilder<> ir(call);
          auto casted_state = ir.CreateBitCast(
              state,
              llvm::Type::getInt8PtrTy(module.getContext()));

          std::vector<llvm::Value *> args;
          for (auto &op : call->arg_operands()) {
            args.push_back(op);
          }

          const auto &params = it->second.type_mask.params;
          Constant c(module.getContext());

          for (auto &reg : params) {
            auto gep = ir.CreateGEP(
                casted_state,
                c.i64(reg->offset));
            auto bitcast = ir.CreateBitCast(
                gep, llvm::PointerType::get(MostInnerSimpleType(reg->type), 0));
            args.push_back(ir.CreateLoad(bitcast));
          }

          auto ret = ir.CreateCall(it->second.unfolded_func, args);
          const auto &ret_mask = it->second.type_mask.ret_type_mask;
          for (uint64_t i = 0U, j = type_prefix.size(); i < ret_mask.size(); ++i) {
            if (ret_mask[i]) {
              auto val = ir.CreateExtractValue(ret, j);
              ++j;
              auto gep = ir.CreateGEP(
                  casted_state,
                  c.i64(regs[i]->offset));
              auto bitcast = ir.CreateBitCast(
                  gep, llvm::PointerType::get(MostInnerSimpleType(regs[i]->type), 0));
              ir.CreateStore(val, bitcast);
            }
          }

          call->replaceAllUsesWith(ir.CreateExtractValue(ret, kMemoryPointerArgNum));
          call->eraseFromParent();
          return;
        }
      }
    }
  }
};

void UnfoldState(llvm::Module *module, void(*opt)(void)) {
  if (!GetTargetArch()->IsAMD64()) {
    LOG(INFO) << "Unfolding is not supported for chosen architecture.";
  }
  StateUnfolder(*module, *GetTargetArch(), opt).Unfold();
}

} // namespace remill
