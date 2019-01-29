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

#include <llvm/IR/DerivedTypes.h>

namespace remill {

inline static llvm::ArrayRef<llvm::Type *> Params(llvm::FunctionType *type) {
#if LLVM_VERSION_NUMBER > LLVM_VERSION(4, 0)
  return type->params();
#else
  return llvm::makeArrayRef(type->param_begin(), type->param_end());
#endif
}

} // namespace remill
