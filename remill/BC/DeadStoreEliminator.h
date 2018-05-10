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

#include <llvm/IR/InstVisitor.h>

namespace llvm {
class Type;
class StructType;
class Module;
class DataLayout;
class Value;
class AllocaInst;
class LoadInst;
class StoreInst;
class GetElementPtrInst;
class GetPtrToIntInst;
class GetIntToPtrInst;
class BitCastInst;
//template<typename SubClass> class InstVisitor;
}  // namespace llvm

namespace remill {

class StateSlot {
public:
  StateSlot(uint64_t begin, uint64_t end);
  // Inclusive beginning byte offset
  uint64_t begin_offset;
  // Exclusive end byte offset
  uint64_t end_offset;
};

class StateVisitor {
  public:
    std::vector<StateSlot> slots;
    // the current offset in the state structure
    uint64_t offset;

    StateVisitor(llvm::DataLayout *dl_);

  private:
    // the LLVM datalayout used for calculating type allocation size
    llvm::DataLayout *dl;

  public:
    // visit a type and record it (and any children) in the slots vector
    virtual void visit(llvm::Type *ty);
};

std::vector<StateSlot> StateSlots(llvm::Module *module);

void AnalyzeAliases(llvm::Module *module);

struct ForwardAliasVisitor : public llvm::InstVisitor<ForwardAliasVisitor> {
  public:
    std::unordered_map<llvm::Value *, uint64_t> offset_map;
    std::unordered_map<llvm::Instruction *, uint64_t> alias_map;
    std::unordered_set<llvm::Value *> exclude;
    std::unordered_set<llvm::Instruction *> curr_wl;
    std::unordered_set<llvm::Instruction *> next_wl;

    ForwardAliasVisitor(llvm::DataLayout *dl_);
    void addInstructions(std::vector<llvm::Instruction *> &insts);
    void analyze();

    virtual void visitAllocaInst(llvm::AllocaInst &I);
    virtual void visitLoadInst(llvm::LoadInst &I);
    virtual void visitStoreInst(llvm::StoreInst &I);
    virtual void visitGetElementPtrInst(llvm::GetElementPtrInst &I);
    virtual void visitGetPtrToIntInst(llvm::GetPtrToIntInst &I);
    virtual void visitGetIntToPtrInst(llvm::GetIntToPtrInst &I);
    virtual void visitBitCastInst(llvm::BitCastInst &I);
    virtual void visitAdd(llvm::BinaryOperator &I);
    virtual void visitSub(llvm::BinaryOperator &I);

  private:
    const llvm::DataLayout *dl;
    virtual void visitBinaryOp_(llvm::BinaryOperator &I);
};

}  // namespace remill
#endif  // REMILL_BC_DSELIM_H_
