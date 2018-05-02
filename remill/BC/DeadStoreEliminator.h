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
class Type;
class StructType;
class Module;
class DataLayout;
}  // namespace llvm

namespace remill {
  class StateSlot {
    public:
      StateSlot(uint64_t begin, uint64_t end) {
        begin_offset = begin;
        end_offset = end;
      }
      //StateSlot(const StateSlot& other);
      // Inclusive beginning byte offset
      uint64_t begin_offset;
      // Exclusive end byte offset
      uint64_t end_offset;

      // Increment the offset of both begin and end by the given offset.
      void increment_offset(const uint64_t offset) {
        begin_offset += offset;
        end_offset += offset;
      }
  };

  class StateVisitor {
    public:
      std::vector<remill::StateSlot> slots;
      // the current offset in the state structure
      uint64_t offset;

      StateVisitor(llvm::DataLayout *dl) {
        slots = std::vector<remill::StateSlot>();
        offset = 0;
      }

    private:
      // the LLVM datalayout used for calculating type allocation size
      llvm::DataLayout *dl;

    public:
      // visit a type and record it (and any children) in the slots vector
      void visit(llvm::Type *ty) {
        if (ty == nullptr) {
          // skip
        } else if (auto struct_ty = llvm::dyn_cast<llvm::StructType>(ty)) {
          for (auto elem_ty : struct_ty->elements()) {
            this->visit(elem_ty);
          }
        } else if (auto seq_ty = llvm::dyn_cast<llvm::SequentialType>(ty)) {
          auto first_ty = seq_ty->getSequentialElementType();
          for (unsigned int i=0; i < seq_ty->getNumContainedTypes(); i++) {
            // repeat NumContained times
            // NOTE: will recalculate every time, rather than memoizing
            this->visit(first_ty);
          }
        } else {  // BASE CASE
          uint64_t len = dl->getTypeAllocSize(ty);
          slots.push_back(remill::StateSlot(offset, offset + len));
          offset += len;
        }
      }
  };

std::vector<StateSlot> StateSlots(llvm::Module *module);
}  // namespace remill

namespace {
std::vector<remill::StateSlot> VisitStruct(llvm::StructType *struct_type,
                                           uint64_t offset,
                                           llvm::DataLayout *dl);

remill::StateSlot VisitField(llvm::Type *ty,
                             uint64_t offset,
                             llvm::DataLayout *dl);

std::vector<remill::StateSlot> VisitSequential(llvm::SequentialType *seq_ty,
                                               uint64_t offset,
                                               llvm::DataLayout *dl);
}
#endif  // REMILL_BC_DSELIM_H_
