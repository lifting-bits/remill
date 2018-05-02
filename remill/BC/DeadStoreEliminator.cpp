/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <utility>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Module.h>

#include "remill/BC/DeadStoreEliminator.h"
#include "remill/BC/Util.h"

/* TODO(tim):
 * - Retrieve a State struct
 * - Recursively visit the struct's members and produce a flattened list of slots
 */

namespace remill {
// Return a vector of state slot records, where each
// "slot" of the State structure has its own SlotRecord.
std::vector<StateSlot> StateSlots(llvm::Module *module) {
  // get the state
  auto slots = std::vector<StateSlot>();
  auto state_ptr_type = StatePointerType(module);
  llvm::Type *type = state_ptr_type->getElementType();
  llvm::DataLayout dl = module->getDataLayout();
  StateVisitor vis(&dl);
  vis.visit(type);
  return vis.slots;
}

StateSlot::StateSlot(uint64_t begin_offset_, uint64_t end_offset_)
  : begin_offset(begin_offset_), end_offset(end_offset_) { }

StateVisitor::StateVisitor(llvm::DataLayout *dl_)
  : slots(std::vector<StateSlot>()), offset(0), dl(dl_) { }

void StateVisitor::visit(llvm::Type *ty) {
  if (ty == nullptr) {
    // skip
  } else if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(ty)) {
    for (auto elem_ty : struct_ty->elements()) {
      visit(elem_ty);
    }
  } else if (auto seq_ty = llvm::dyn_cast<llvm::SequentialType>(ty)) {
    auto first_ty = seq_ty->getElementType();
    for (unsigned int i=0; i < seq_ty->getNumElements(); i++) {
      // repeat NumContained times
      // NOTE: will recalculate every time, rather than memoizing
      visit(first_ty);
    }
  } else {  // BASE CASE
    ty->dump();
    uint64_t len = dl->getTypeAllocSize(ty);
    slots.push_back(remill::StateSlot(offset, offset + len));
    offset += len;
  }
}
}
