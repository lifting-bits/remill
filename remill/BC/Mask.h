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


// This is good only to convert std::vector<bool> to Container for historic reasons
template<typename Container>
struct GMask : public Container {

  // Tag dispatch, to make sure bitset gets its own pretty fast ctor
  explicit GMask(std::size_t used) : GMask(used, tag<Container>{}) {}

  // std::bitset
  explicit GMask(std::size_t used, const std::true_type &) :
    Container(std::pow(2, used) - 1) {}

  // Everything else
  explicit GMask(std::size_t used, const std::false_type &) : Container(used, true) {}

private:

  template<typename>
  struct tag : std::false_type {};

  template<std::size_t N>
  struct tag<std::bitset<N>> : std::true_type {};

};

// This is not using iterators since std::bitset does not have any
// CRTP to provide conversion from other collections
template<typename Self>
struct Converter {

  Self &self() {
    return static_cast<Self &>(*this);
  }

  // T must support T::size(), T::operator[size_t]
  template<typename T, typename Op>
  static Self cc(const T &other, Op op) {
    Self self(other.size());
    for (auto i = 0U; i < other.size(); ++i) {
      self[i] = op(other[i]);
    }
    return self;
  }

  // T must support T::size(), T::operator[size_t]
  template<typename T>
  static Self cc(const T &other) {
    Self self(other.size());
    for (auto i = 0U; i < other.size(); ++i) {
      self[i] = other[i];
    }
    return self;
  }
};

// Special type for mask of return type of function
template<typename Container>
struct RMask : public GMask<Container>, Converter<RMask<Container>> {
  using Base = GMask<Container>;
  using Base::Base;

};

// Special type for mask of parameters of function
template<typename Container>
struct PMask : public GMask<Container>, Converter<PMask<Container>> {
  using Base = GMask<Container>;
  using Base::Base;
};

// Mapping Register -> bool
// True means that the register is present in a type
template<typename Container>
struct TypeMask {
  using RType = RMask<Container>;
  using PType = PMask<Container>;

  RType ret_type_mask;
  PType param_type_mask;

  RegisterList rets;
  RegisterList params;

  TypeMask(const RegisterList &regs) :
    ret_type_mask(regs.size()), param_type_mask(regs.size()),
    rets(regs), params(regs) {}

  TypeMask(const RegisterList &regs, RType ret, PType param) :
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


  llvm::FunctionType *GetFunctionType(
      llvm::LLVMContext &ctx, const std::vector<llvm::Type *> &prefix) const {
    auto ret_subtypes = prefix;
    for (auto &r : rets) {
      ret_subtypes.push_back(r->type);
    }

    auto param_subtypes = prefix;
    for (auto &p : params) {
      param_subtypes.push_back(p->type);
    }

    return llvm::FunctionType::get(
        llvm::StructType::get(ctx, std::move(ret_subtypes)),
        std::move(param_subtypes),
        false);
  }

  // There are no registers present
  bool Empty() const {
    return rets.empty() && params.empty();
  }
};

// So that std::vector<bool> can be used as Container in GMask
std::vector<bool> &operator&=(std::vector<bool> &l, const std::vector<bool> &r) {
  for (auto i = 0U; i < l.size(); ++i) {
    l[i] = l[i] && r[i];
  }
  return l;
}

// Intermediate type that does not work with registers themselves, only with masks
template<typename Container>
struct TMask {
  using RType = RMask<Container>;
  using PType = PMask<Container>;

  RType ret_type_mask;
  PType param_type_mask;

  TMask(std::size_t used) : ret_type_mask(used), param_type_mask(used) {
    // Empty
  }

  template<typename T>
  TMask &operator&=(const PMask<T> &param) {
    param_type_mask &= param;
    return *this;
  }

  template<typename T>
  TMask &operator&=(const RMask<T> &ret) {
    ret_type_mask &= ret;
    return *this;
  }

  template<typename T>
  TMask &operator&=(const TMask<T> &mask) {
    param_type_mask &= mask.param_type_mask;
    ret_type_mask &= mask.ret_type_mask;
    return *this;
  }

  TypeMask<Container> Build(const RegisterList &regs) {
    return TypeMask<Container>(regs, ret_type_mask, param_type_mask);
  }

};

template<typename Container>
inline std::ostream &operator<<(std::ostream &os, const TypeMask<Container> &mask) {
  os << "Ret_type:" << std::endl;
  for (const auto &reg : mask.rets) {
    os << "\t" << reg->name;
  }
  os << std::endl;

  os << "Param_type:" << std::endl;
  for (const auto &reg : mask.params) {
    os << "\t" << reg->name;
  }
  os << std::endl;

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
