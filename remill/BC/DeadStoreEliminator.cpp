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
    auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
    CHECK(struct_type != nullptr);
    uint64_t offset = 0;
    return VisitStruct(struct_type, offset, &dl);
  }
}  // namespace remill

namespace {
  std::vector<remill::StateSlot> VisitStruct(llvm::StructType *struct_type,
                                             uint64_t offset,
                                             llvm::DataLayout *dl) {
    auto slots = std::vector<remill::StateSlot>();
    for (auto elem_type : struct_type->elements()) {
      if (auto struct_type = llvm::dyn_cast<llvm::StructType>(elem_type)) {
        // TODO(tim): other CompositeTypes: arrays, vectors
        auto struct_slots = VisitStruct(struct_type, offset, dl);
        offset = struct_slots.end()->end_offset;
        // flatten into existing list
        slots.insert(slots.end(), struct_slots.begin(), struct_slots.end());
      } else {
        remill::StateSlot slot = VisitField(elem_type, offset, dl);
        CHECK(slot.end_offset > offset);
        offset = slot.end_offset;
        slots.push_back(slot);
      }
    }
    return slots;
  }
  // Return a new StateSlot based on the Type of the given value,
  // and the starting offset provided.
  remill::StateSlot VisitField(llvm::Type *ty, uint64_t offset, llvm::DataLayout *dl) {
    uint64_t end = dl->getTypeAllocSize(ty) + offset;
    return remill::StateSlot(offset, end);
  }
}  // namespace
