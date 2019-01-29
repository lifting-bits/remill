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

#include <algorithm>
#include <iterator>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/DerivedTypes.h"

namespace remill {

// CRTP that expects attribute llvm::LLVMContext &context
// Provides some short wrappers around llvm::ConstantInt and llvm::Type
template <typename Self>
struct IntegerUtil {

  llvm::ConstantInt *i32(int32_t value) {
    return GetConstantInt(value, 32);
  }

  llvm::ConstantInt *i64(int64_t value) {
    return GetConstantInt(value, 64);
  }

  llvm::ConstantInt *GetConstantInt(int64_t value, int64_t size) {
    return llvm::ConstantInt::get(
        llvm::Type::getIntNTy(static_cast<Self &>(*this).context, size), value);
  }

  llvm::Type *i64Ty() {
    return llvm::Type::getInt64Ty(static_cast<Self &>(*this).context);
  }

  llvm::Type *i64PtrTy() {
    return llvm::Type::getInt64PtrTy(static_cast<Self &>(*this).context);
  }

  llvm::Type *iNPtrTy(uint64_t size) {
    return llvm::Type::getIntNPtrTy(static_cast<Self &>(*this).context, size);
  }

  llvm::Type *i8Ty() {
    return llvm::Type::getInt8Ty(static_cast<Self &>(*this).context);
  }

  llvm::Type *i8PtrTy() {
    return llvm::Type::getInt8PtrTy(static_cast<Self &>(*this).context);
  }

  llvm::Type *iNTy(uint64_t size) {
    return llvm::Type::getIntNTy(static_cast<Self &>(*this).context, size);
  }
};

struct Constant : IntegerUtil<Constant> {
  llvm::LLVMContext &context;

  Constant(llvm::LLVMContext &c) : context(c) {}
};

using RegisterList = std::vector<const Register *>;
using Mask = std::vector<bool>;

// TODO: std::optional
// Retrieves next index from offset (including) that has value equal to val
// Returns true if such index was found, with value stored in offset
// If index was not found, offset is preserved
template<typename U, typename T>
bool NextIndex(const U &mask, const T& val, uint64_t &offset) {
  for (uint64_t i = offset; i < mask.size(); ++i) {
    if (mask[i] == val) {
      offset = i;
      return true;
    }
  }
  return false;
}

// TODO: std::optional
// Retrieve n-th index from offset (including) that has value equal to val
// Returns true if such index was found, with value stored in offset
// If index was not found, offset is preserved
template<typename U, typename T>
bool NthIndex(const U &mask, const T& val, int64_t n,  uint64_t &offset) {
  if (n < 0) {
    return false;
  }

  int64_t counter = -1;
  for (uint64_t i = 0; i < mask.size(); ++i) {
    if (mask[i] == val && ++counter == n) {
      offset = i;
      return true;
    }
  }
  return false;
}

/* Utility functions for transformations on Masks */
template<class U, class BinaryOp>
Mask &ZipMasks(Mask &mask, const U &other, BinaryOp binary_op) {
  std::transform(mask.begin(), mask.end(), other.begin(), mask.begin(), binary_op);
  return mask;
}

template<class ForwardIt1, class ForwardIt2, class BinaryOp>
Mask ZipMasks(ForwardIt1 first1, ForwardIt1 last1,
              ForwardIt2 first2, BinaryOp binary_op) {
  Mask result;
  result.reserve(std::distance(first1, last1));
  std::transform(first1, last1, first2, std::back_inserter(result), binary_op);
  return result;
}

inline Mask operator||(const Mask &lhs, const Mask &rhs) {
  return ZipMasks(lhs.cbegin(), lhs.cend(), rhs.cbegin(), [](bool l, bool r){
      return l || r;
    });
}

inline Mask operator&&(const Mask &lhs, const Mask &rhs) {
  return ZipMasks(lhs.cbegin(), lhs.cend(), rhs.cbegin(), [](bool l, bool r){
      return l && r;
    });
}

// Mapping Register -> bool
// True means that the register is present in a type
struct TypeMask {
  Mask ret_type_mask;
  Mask param_type_mask;

  RegisterList rets;
  RegisterList params;

  TypeMask(const RegisterList &regs) :
    ret_type_mask(regs.size(), true), param_type_mask(regs.size(), true),
    rets(regs), params(regs) {}

  TypeMask(const RegisterList &regs, Mask ret, Mask param) :
    ret_type_mask(std::move(ret)), param_type_mask(std::move(param)) {
      for (auto i = 0U; i < regs.size(); ++i) {
        if (ret_type_mask[i]) {
          rets.push_back(regs[i]);
        }
        if (param_type_mask[i]) {
          params.push_back(regs[i]);
        }
      }
    }
};

inline std::ostream &operator<<(std::ostream &os, const TypeMask &mask) {
  os << "Ret_type:" << std::endl;
  for (const auto &reg : mask.rets) {
    os << "\t" << reg->name << std::endl;
  }

  os << "Param_type:" << std::endl;
  for (const auto &reg : mask.params) {
    os << "\t" << reg->name << std::endl;
  }
  return os;
}

inline llvm::Function *AppendParams(
    llvm::Module &module,
    llvm::Function &func,
    const std::vector<llvm::Type *> types,
    const std::string &prefix) {

  std::vector<llvm::Type *> new_type = Params(func.getFunctionType());
  new_type.insert(new_type.end(), types.begin(), types.end());

  auto appended_type = llvm::FunctionType::get(
      func.getFunctionType()->getReturnType(), new_type, func.isVarArg());

  auto appended_func = llvm::Function::Create(
    appended_type, func.getLinkage(), prefix + func.getName(), &module);

  appended_func->setAttributes(func.getAttributes());
  llvm::ValueToValueMapTy v_map;
  auto appended_func_arg_it = appended_func->arg_begin();
  for (auto &arg : func.args()) {
    v_map[&arg] = &(*appended_func_arg_it);
    appended_func_arg_it->setName(arg.getName());
    ++appended_func_arg_it;
  }

  llvm::SmallVector<llvm::ReturnInst *, 8> returns;
  llvm::CloneFunctionInto(appended_func, &func, v_map, false, returns);


  return appended_func;
}

} // namespace remill
