/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define DEBUG_TYPE "IntrinsicOptimizer"

#include <iostream>
#include <set>
#include <sstream>
#include <vector>

#include <llvm/Pass.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>

#include <llvm/Transforms/Utils/Local.h>

namespace mcsema {
namespace {

// Require that if `function` is invoked, then it is treated as a tail call.
static void ForceTailCall(llvm::Function *function) {
  for (auto callers : function->users()) {
    auto call_instr = llvm::dyn_cast<llvm::CallInst>(callers);
    if (!call_instr) continue;
    if (call_instr->isInlineAsm()) continue;
    if (llvm::isa<llvm::IntrinsicInst>(call_instr)) continue;

    // Make sure the caller "looks" like a lifted basic block.
    auto caller = call_instr->getParent()->getParent();
    if (!caller->getName().startswith("__lifted")) continue;

    llvm::Instruction *next_instr = &*(++(call_instr->getIterator()));

    if (llvm::isa<llvm::BranchInst>(next_instr)) {
      next_instr->eraseFromParent();
      llvm::ReturnInst::Create(function->getContext(), call_instr->getParent());

    } else if (!llvm::isa<llvm::ReturnInst>(next_instr)) {
      llvm::errs()
          << "Call to " << function->getName() << " cannot safely be "
          << "converted into a tail call because it is not followed by "
          << "either a branch or a return.";

      continue;  // Not good :-/
    }

    call_instr->setAttributes(function->getAttributes());
    call_instr->setTailCallKind(llvm::CallInst::TCK_MustTail);
    call_instr->setCallingConv(llvm::CallingConv::Fast);
  }
}


// Looks for a function by name. If we can't find it, try to find an underscore
// prefixed version, just in case this is Mac or Windows.
static llvm::Function *GetFunction(llvm::Module &module, const char *name) {
  if (auto function = module.getFunction(name)) {
    return function;
  } else {
    std::stringstream ss;
    ss << "_" << name;  // Underscorilize (Mac OS X, Windows).
    return module.getFunction(ss.str());
  }
}

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceIntrinsic(llvm::Module &module, const char *name,
                             unsigned undef_size_bits) {
  auto function = GetFunction(module, name);
  if (!function) return;

  std::vector<llvm::CallInst *> call_instrs;
  for (auto callers : function->users()) {
    if (auto call_instr = llvm::dyn_cast<llvm::CallInst>(callers)) {
      call_instrs.push_back(call_instr);
    }
  }

  // Eliminate calls
  auto undef_val = llvm::UndefValue::get(
      llvm::Type::getIntNTy(function->getContext(), undef_size_bits));
  for (auto call_instr : call_instrs) {
    call_instr->replaceAllUsesWith(undef_val);
    call_instr->removeFromParent();
    delete call_instr;
  }
}

// Remove calls to the undefined intrinsics. The goal here is to improve dead
// store elimination by peppering the instruction semantics with assignments
// to the return values of special `__mcsema_undefined_*` intrinsics. It's hard
// to reliably produce an `undef` LLVM value from C/C++, so we use our trick
// of declaring (but never defining) a special "intrinsic" and then we replace
// all such uses with `undef` values.
void RemoveUndefinedIntrinsics(llvm::Module &module) {
  ReplaceIntrinsic(module, "__mcsema_undefined_bool", 1);
  ReplaceIntrinsic(module, "__mcsema_undefined_8", 8);
  ReplaceIntrinsic(module, "__mcsema_undefined_16", 16);
  ReplaceIntrinsic(module, "__mcsema_undefined_32", 32);
  ReplaceIntrinsic(module, "__mcsema_undefined_64", 64);

  // Eliminate stores of undefined values.
  for (auto &function : module) {
    std::vector<llvm::Instruction *> dead_instrs;
    for (auto &basic_block : function) {
      for (auto &instr : basic_block) {
        if (auto store_instr = llvm::dyn_cast<llvm::StoreInst>(&instr)) {
          if (llvm::isa<llvm::UndefValue>(store_instr->getValueOperand())) {
            dead_instrs.push_back(store_instr);
          }
        }
      }
    }

    // Done after we've collected the stores so that we don't affect
    // the iterators.
    for (auto dead_instr : dead_instrs) {
      llvm::RecursivelyDeleteTriviallyDeadInstructions(dead_instr);
    }
  }
}

// Enable inlining of functions whose inlining has been deferred.
static void EnableInlining(llvm::Module &module) {
  auto defer_inlining_func = GetFunction(module, "__mcsema_defer_inlining");
  if (!defer_inlining_func) return;

  std::vector<llvm::CallInst *> call_instrs;
  std::set<llvm::Function *> processed_funcs;

  // Find all calls to the inline defer intrinsic.
  for (auto caller : defer_inlining_func->users()) {
    if (auto call_instr = llvm::dyn_cast_or_null<llvm::CallInst>(caller)) {
      call_instrs.push_back(call_instr);
    }
  }

  // Remove the calls to the inline defer intrinsic, and mark the functions
  // containing those calls as inlinable.
  for (auto call_instr : call_instrs) {
    auto basic_block = call_instr->getParent();
    auto caller_func = basic_block->getParent();

    processed_funcs.insert(caller_func);

    caller_func->removeFnAttr(llvm::Attribute::NoInline);
    caller_func->addFnAttr(llvm::Attribute::AlwaysInline);
    caller_func->addFnAttr(llvm::Attribute::InlineHint);

    call_instr->replaceAllUsesWith(llvm::UndefValue::get(call_instr->getType()));
    call_instr->eraseFromParent();
  }

  // Emulate the `flatten` attribute by finding all calls to functions that
  // containing the inline defer intrinsic, and mark the call instructions
  // as requiring inlining.
  for (auto function : processed_funcs) {
    for (auto callers : function->users()) {
      if (auto call_instr = llvm::dyn_cast_or_null<llvm::CallInst>(callers)) {
        call_instr->addAttribute(llvm::AttributeSet::FunctionIndex,
                                 llvm::Attribute::AlwaysInline);
      }
    }
  }
}

}  // namespace

// Implements the deferred inlining optimization. McSema2 uses a special
// `__mcsema_defer_inlining` intrinsic to mark functions as needing to be
// "late" inlined. The idea is that we want some functions to be optimized
// away (flag computation functions), but the ones that stick around should
// then be inlined into their callers for further optimization.
class IntrinsicOptimizer : public llvm::ModulePass {
 public:
  IntrinsicOptimizer(void);
  ~IntrinsicOptimizer(void);

  virtual const char *getPassName(void) const override;
  virtual bool runOnModule(llvm::Module &) override;

  static char ID;

 private:
};

IntrinsicOptimizer::IntrinsicOptimizer(void)
    : llvm::ModulePass(ID) {}

IntrinsicOptimizer::~IntrinsicOptimizer(void) {}

const char *IntrinsicOptimizer::getPassName(void) const {
  return "IntrinsicOptimizer";
}

bool IntrinsicOptimizer::runOnModule(llvm::Module &module) {
  RemoveUndefinedIntrinsics(module);
  ForceTailCall(GetFunction(module, "__mcsema_error"));
  ForceTailCall(GetFunction(module, "__mcsema_jump"));
  ForceTailCall(GetFunction(module, "__mcsema_function_call"));
  ForceTailCall(GetFunction(module, "__mcsema_function_return"));
  ForceTailCall(GetFunction(module, "__mcsema_system_call"));
  ForceTailCall(GetFunction(module, "__mcsema_system_return"));
  ForceTailCall(GetFunction(module, "__mcsema_interrupt_call"));
  ForceTailCall(GetFunction(module, "__mcsema_interrupt_return"));
  ForceTailCall(GetFunction(module, "__mcsema_missing_block"));
  EnableInlining(module);

  return true;
}

char IntrinsicOptimizer::ID = 0;

static llvm::RegisterPass<IntrinsicOptimizer> X(
    "intrinsic_optimizer",
    "Removes `__mcsema_defer_inlining` and `__mcsema_undefined_*` intrinsics.",
    false,  // Only looks at CFG.
    false);  // Analysis Pass.


}  // namespace mcsema
