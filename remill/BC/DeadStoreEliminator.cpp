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

// Return a vector of state slot records, where each
// "slot" of the State structure has its own SlotRecord.
vector<StateSlot> StateSlots(llvm::Module *module) {
  // get the state corresponding to the module
  // start at offset 0 and begin visiting State
  // iterate and visit fields, returning StateSlots
  // update offset with the .end_offset of each new StateSlot
}

// Return a new StateSlot based on the Type of the given value,
// and the starting offset provided.
StateSlot VisitField(llvm::Value *value, uint64_t offset) {
  // get the value's type (llvm::Type*)
  // get the value's name and use it as the comment
  // return a StateSlot
}

