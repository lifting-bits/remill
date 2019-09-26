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

#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/Module.h>

#include <remill/BC/Util.h>

#include <unordered_set>

namespace remill {

static inline void UnsafeErase(llvm::Function *func) {
  if (!func) {
    return;
  }

  func->replaceAllUsesWith(
    llvm::UndefValue::get(llvm::PointerType::getUnqual(func->getFunctionType())));
  func->eraseFromParent();
}

template< unsigned i, typename... Empty >
struct _Get { };

template< typename _T, typename... Ts >
struct _Get< 0, _T, Ts... > { using T = _T; };

template< unsigned i, typename _T, typename... Ts >
struct _Get< i, _T, Ts... > { using T = typename _Get< i - 1, Ts... >::T; };

template< unsigned, typename >
struct MethodArg { };

template< unsigned i, typename Obj, typename R, typename... Args >
struct MethodArg< i, R (Obj::*)( Args... ) > {
    using T = typename _Get< i, Args... >::T;
};

template< unsigned i, typename Obj, typename R, typename... Args >
struct MethodArg< i, R (Obj::*)( Args... ) const > {
    using T = typename _Get< i, Args... >::T;
};

template< typename What >
bool llvmcase( What * ) { return false; }

template< typename What, typename Lambda, typename... Lambdas >
bool llvmcase( What *w, Lambda lambda, Lambdas &&...lambdas ) {
    if ( auto val = llvm::dyn_cast<
            typename std::remove_pointer<
                typename MethodArg< 0, decltype( &Lambda::operator() ) >::T
            >::type >( w ) )
    {
        return lambda( val );
    }
    return llvmcase( w, std::forward< Lambdas >( lambdas )... );
}

template< typename What, typename... Lambdas >
bool llvmcase( What &w, Lambdas &&...lambdas ) {
    return llvmcase( &w, std::forward< Lambdas >( lambdas )... );
}

template<typename LLVMFunc, typename Filter, typename Apply>
void FilterAndApply(LLVMFunc *func, Filter &&filter, Apply apply) {
  for (auto &bb : *func) {
    for (auto &inst : bb) {
      if (auto casted = filter(&inst)) {
        apply(casted);
      }
    }
  }
}

template<typename LLVMModule>
auto GetExplicitState(LLVMModule &module) {
  auto state = module.getNamedGlobal("__mcsema_reg_state");
  return state;
}

static inline const llvm::GlobalVariable *GetExplicitState(const llvm::Function *func) {
  return GetExplicitState(*func->getParent());
}

template<typename T>
std::vector<T *> Filter(llvm::Function *func) {
  std::vector<T *> out;
  for (auto &bb : *func) {
    for (auto &inst : bb) {
      if (auto casted = llvm::dyn_cast<T>(&inst)) {
        out.push_back(casted);
      }
    }
  }
  return out;
}

template< typename ... Next >
struct In {

  template<typename Callback>
  static bool Walk(llvm::Value *value, Callback CB) {
    return false;
  }

};

template< typename Head, typename ... Next >
struct In< Head, Next ... > {

  template<typename Callback>
  static bool Walk(llvm::Value *value, Callback CB) {
    if (auto head = llvm::dyn_cast<Head>(value)) {
      return CB(head);
    }
    return In<Next...>::Walk(value, CB);
  }
};


template<typename Inst, typename Begin>
Begin *GetBeginOfChain(Inst *val) {
  if (!val) {
    return nullptr;
  }

  if (auto end = llvm::dyn_cast<Begin>(val->getAggregateOperand())) {
    return end;
  }

  return GetBeginOfChain<Inst, Begin>(llvm::dyn_cast<Inst>(val->getAggregateOperand()));
}

template<typename Inst, typename End>
End *GetEndOfChain(llvm::Value *val) {
  if (!val) {
    return nullptr;
  }

  if (!val->hasOneUse()) {
    return nullptr;
  }

  if (auto end = llvm::dyn_cast<End>(*val->user_begin())) {
     return end;
  }
  return GetEndOfChain<Inst, End>(llvm::dyn_cast<Inst>(*val->user_begin()));

}

// Checks if value can escape into different function
struct _EscapeArgument {

  std::unordered_set<llvm::Value *> _seen;
  llvm::Function *_func;

  llvm::Value *_origin = nullptr;
  uint64_t _arg_idx = -1;

  _EscapeArgument(llvm::Function *func) : _func(func) {}

  bool SpreadForward(llvm::Value *val) {
    bool acc = true;
    for (auto user : val->users()) {
      acc &= Forward(user);
    }
    return acc;
  }

  bool SpreadBackward(llvm::Value *val) {
    bool acc = true;
    for (auto &use : val->uses()) {
      acc &= Backward(use);
    }
    return acc;
  }


  bool Forward(llvm::Value *val) {

    if (_seen.count(val)) {
      return true;
    }
    _seen.insert(val);

    bool out = llvmcase(val,
        [&](llvm::PHINode *phi)
        {
          bool acc = SpreadForward(phi);
          for (auto &use: phi->incoming_values()) {
            acc &= Backward(use);
          }
          return acc;
        },
        [&](llvm::CallInst *call)
        {
          return llvm::CallSite(call).getCalledFunction() == _func &&
                 NthArgument(_func, _arg_idx) == _origin;
        },
        [&](llvm::InsertValueInst *insert)
        {
          return GetEndOfChain<llvm::InsertValueInst, llvm::ReturnInst>(insert) &&
                 *insert->idx_begin() == _arg_idx;
        }
    );

    return out;
  }


  bool Backward(llvm::Value *val) {

    if (_seen.count(val)) {
      return true;
    }
    _seen.insert(val);

    bool out = llvmcase(val,
        [&](llvm::Argument *arg)
        {
          return arg == _origin;
        },
        [&](llvm::PHINode *phi)
        {
          bool acc = true;
          for (auto &use: phi->incoming_values()) {
            if (use == llvm::UndefValue::get(use->getType())) {
              continue;
            }
            acc &= Backward(use);
          }
          return acc;
        },
        [&](llvm::ExtractValueInst *extract)
        {
          auto call = GetBeginOfChain<llvm::ExtractValueInst, llvm::CallInst>(extract);
          return call &&
                 llvm::CallSite(call).getCalledFunction() == _func &&
                 *extract->idx_begin() == _arg_idx;
        }
    );

    return out;
  }

  bool Run(llvm::Value *origin, uint64_t arg_idx) {
    _arg_idx = arg_idx;
    _origin = origin;
    return SpreadForward(origin);
  }
};


struct _EscapeArgumentFromReturn : _EscapeArgument {
 using _EscapeArgument::_EscapeArgument;

  bool Run(llvm::Value *origin, uint64_t arg_idx) {
    _arg_idx = arg_idx;
    _origin = NthArgument(_func, _arg_idx);
    return SpreadBackward(origin);
  }
};

} // namespace remill
