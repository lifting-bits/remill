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

#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>


namespace remill {

// Unfolds state in function types.
void UnfoldState(llvm::Module *module, void(*opt)(void)=nullptr);

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

  llvm::Type *i8Ty() {
    return llvm::Type::getInt8Ty(static_cast<Self &>(*this).context);
  }

  llvm::Type *iNTy(uint64_t size) {
    return llvm::Type::getIntNTy(static_cast<Self &>(*this).context, size);
  }
};

struct Constant : IntegerUtil<Constant> {
  llvm::LLVMContext &context;

  Constant(llvm::LLVMContext &c) : context(c) {}
};

} // namespace remill
