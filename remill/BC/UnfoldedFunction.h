#pragma once

#include <vector>
#include <string>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>

#include "remill/Arch/Arch.h"

#include "remill/BC/Color.h"
#include "remill/BC/Mask.h"
#include "remill/BC/UnfoldUtils.h"

namespace remill {

struct UnfoldedFunction {

  static constexpr const int bitset_size = 32;

  using Mask = TypeMask<std::bitset<bitset_size>>;
  using RegisterList = std::vector<const remill::Register *>;
  using TypePrefix = std::vector<llvm::Type *>;

  const RegisterList &regs;
  const TypePrefix &type_prefix;

  // original lifted function
  llvm::Function &sub_func;
  llvm::Function *unfolded_func;

  // allocas, that are at the beginning of the function, for each register that is being
  // unfolded. Order is corresponding to order in type_mask
  std::vector<llvm::AllocaInst *> allocas;

  // Hold information about currently used registers in function type
  Mask t_mask;

  std::vector<Mask> _history;

  llvm::Module &module = *sub_func.getParent();
  llvm::LLVMContext &context = module.getContext();

  UnfoldedFunction(
      llvm::Function *func, const RegisterList &all_regs, const TypePrefix &t_prefix,
      const std::string &prefix="_unfold)") : regs(all_regs), type_prefix(t_prefix),
                                              sub_func(*func), t_mask(regs) {
    Update(std::move(t_mask), prefix);
  }

  void UpdateMask(Mask mask) {
    t_mask = mask;
    _history.push_back(std::move(mask));
  }

  std::string History(const RegisterList &regs) const {
    std::stringstream out;

    out << sub_func.getName().str() << std::endl;
    for (auto i = 1U; i < _history.size(); ++i) {
      out << std::to_string(i) << std::endl
          << Peek(_history[i - 1], _history[i], regs);
    }
    return out.str();
  }

  template<typename M>
  std::string Peek(const M &lhs, const M &rhs, const RegisterList &regs,
                   const std::string &prefix=" ") const {
    std::stringstream out;
    for (auto i = 0U; i < lhs.size(); ++i) {

      if (lhs[i] == rhs[i]) {
          if (lhs[i])
            out << prefix << regs[i]->name;
      } else if (!lhs[i])
        out << prefix << green(regs[i]->name)();
      else
        out << prefix << red(regs[i]->name)();
    }

    return out.str();
  }

  std::string Peek(const Mask &lhs, const Mask &rhs, const RegisterList &regs) const {
    std::stringstream out;

    auto params = Peek(lhs.param_type_mask, rhs.param_type_mask, regs);
    if (params.size()) {
      out << "P:" << params << std::endl;
    }

    auto rets = Peek(lhs.ret_type_mask, rhs.ret_type_mask, regs);
    if (rets.size()) {
      out << "R:" << rets << std::endl;
    }

    return out.str();
  }

  std::string Peek(const Mask &rhs, const RegisterList &regs) {
    return Peek(t_mask, rhs, regs);
  }

  // Returns old version of unfolded function and forfeits its ownership
  llvm::Function *Update(Mask mask, const std::string &prefix="") {
    auto old = unfolded_func;

    UpdateMask(std::move(mask));
    unfolded_func = UnfoldState(prefix);
    CreateAllocas();

    FoldRets();
    ReplaceGEPs();

    return old;
  }

  auto ArgBegin() const {
    return std::next(unfolded_func->arg_begin(), type_prefix.size());
  }

  auto ArgBegin() {
    return std::next(unfolded_func->arg_begin(), type_prefix.size());
  }

  llvm::Function *UnfoldState(const std::string &prefix="");
  void CreateAllocas();

  void ReplaceGEPs();
  void ReplaceBitCast(llvm::Value *allocas, llvm::Value *instruction);
  void FoldAggregate(llvm::Type *ret_ty, llvm::IRBuilder<> &ir);
  void FoldRets();
};

static inline std::ostream &operator<<(std::ostream &os, const UnfoldedFunction &func) {
  os << func.sub_func.getName().str() << " -> "
     << func.unfolded_func->getName().str() << std::endl;
  os << func.t_mask;
  return os;
}

} // namespace remill
