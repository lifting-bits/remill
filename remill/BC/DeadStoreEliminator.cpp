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
    auto slots = std::vector<StateSlot>();
    auto state_ptr_type = StatePointerType(module);
    auto struct_type = llvm::dyn_cast<llvm::StructType>(state_ptr_type);
    CHECK(struct_type != nullptr);
    uint64_t offset = 0;
    for (auto elem_type : struct_type->elements()) {
      auto slot = VisitField(elem_type, offset);
      offset = slot.end_offset;
      slots.push_back(slot);
    }
    return slots;
  }
}  // namespace remill

namespace {
  // Return a new StateSlot based on the Type of the given value,
  // and the starting offset provided.
  StateSlot VisitField(llvm::Type *ty, uint64_t offset) {
    auto end = llvm::DataLayout::getTypeAllocSize(ty) + offset;
    // TODO(tim): change to properly recurse if given type is non-primitive
    return StateSlot(offset, end);
  }
}  // namespace
