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

#ifndef REMILL_BC_DSELIM_H_
#define REMILL_BC_DSELIM_H_

namespace llvm {
class BasicBlock;
class Module;
class Value;
}  // namespace llvm

class StateSlot {
  protected:
    // Inclusive beginning byte offset
    uint64_t begin_offset;
    // Exclusive end byte offset
    uint64_t end_offset;
    // Slot "name"
    StringRef comment;
};

vector<StateSlot> StateSlots(llvm::Module *module);

StateSlot VisitField(llvm::Value *value, uint64_t offset);
#endif  // REMILL_BC_DSELIM_H_
