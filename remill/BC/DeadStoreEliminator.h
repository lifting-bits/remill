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

#pragma once

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {

// A field or region of the state structure at a particular offset from
// the top of the state structure (offset 0) with a given size. You can think
// of a slot as logically being the storage location of a machine register.
// For example, a single slot will cover the range of bytes in the `State`
// structure associated with the amd64 RAX, EAX, AX, AH, and AL registers.
class StateSlot {
 public:
  inline StateSlot(uint64_t i_, uint64_t offset_, uint64_t size_)
      : index(i_),
        offset(offset_),
        size(size_) {}

  // Slot index.
  uint64_t index;

  // Inclusive beginning byte offset.
  uint64_t offset;

  // Size of the slot in bytes.
  uint64_t size;
};

// Returns a covering vector of `StateSlots` for the module's `State` type.
// This vector contains one entry per byte of the `State` type.
std::vector<StateSlot> StateSlots(llvm::Module *module);

// Analyze a module, discover aliasing loads and stores, and remove dead
// stores into the `State` structure.
void RemoveDeadStores(llvm::Module *module, llvm::Function *bb_func,
                      const std::vector<StateSlot> &slots, llvm::Function *ds_func=nullptr);

}  // namespace remill
