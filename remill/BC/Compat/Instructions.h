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

namespace remill {

inline static llvm::Type *GetResultElementType(llvm::GetElementPtrInst *gep) {
#if LLVM_VERSION_NUMBER > LLVM_VERSION(4, 0)
  return gep->getResultElementType();
#else
  std::vector<llvm::Value *> idxs;
  auto range = llvm::iterator_range<llvm::GetElementPtrInst::op_iterator>(
    gep->idx_begin(), gep->idx_end());
  for (auto &u : range) {
    idxs.push_back(u);
  }
  auto base_ty = llvm::dyn_cast<llvm::PointerType>(gep->getPointerOperandType());
  return llvm::GetElementPtrInst::getIndexedType(base_ty->getElementType(), idxs);

#endif
}

} // namespace remill
