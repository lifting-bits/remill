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
  StateSlot(uint64_t i, uint64_t offset, uint64_t size);
  // slot index
  uint64_t i;
  // Inclusive beginning byte offset
  uint64_t offset;
  // Size of the slot
  uint64_t size;
};

class StateVisitor {
  public:
    std::vector<StateSlot> slots;
    // the current index in the state structure
    uint64_t idx;
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

typedef std::unordered_map<llvm::Instruction *, uint64_t> AliasMap;

std::vector<StateSlot> StateSlots(llvm::Module *module);

std::pair<std::unordered_map<llvm::MDNode *, uint64_t>, std::vector<llvm::AAMDNodes>> generateAAMDInfo(
        std::vector<StateSlot> slots,
        llvm::LLVMContext &context);

void addAAMDNodes(AliasMap alias_map, std::vector<StateSlot> slots);

std::unordered_map<llvm::MDNode *, uint64_t> AnalyzeAliases(llvm::Module *module, std::vector<StateSlot> slots);

enum class AliasResult;

struct ForwardAliasVisitor : public llvm::InstVisitor<ForwardAliasVisitor, AliasResult> {
  public:
    std::unordered_map<llvm::Value *, uint64_t> offset_map;
    AliasMap alias_map;
    std::unordered_set<llvm::Value *> exclude;
    std::unordered_set<llvm::Instruction *> curr_wl;
    std::unordered_set<llvm::Instruction *> next_wl;
    llvm::Value *state_ptr;

    ForwardAliasVisitor(llvm::DataLayout *dl_, llvm::Value *sp_);
    void addInstructions(std::vector<llvm::Instruction *> &insts);
    void analyze();

    virtual AliasResult visitInstruction(llvm::Instruction &I); 
    virtual AliasResult visitAllocaInst(llvm::AllocaInst &I);
    virtual AliasResult visitLoadInst(llvm::LoadInst &I);
    virtual AliasResult visitStoreInst(llvm::StoreInst &I);
    virtual AliasResult visitGetElementPtrInst(llvm::GetElementPtrInst &I);
    virtual AliasResult visitCastInst(llvm::CastInst &I);
    virtual AliasResult visitAdd(llvm::BinaryOperator &I);
    virtual AliasResult visitSub(llvm::BinaryOperator &I);
    virtual AliasResult visitPHINode(llvm::PHINode &I);

  private:
    const llvm::DataLayout *dl;
    virtual AliasResult visitBinaryOp_(llvm::BinaryOperator &I, bool plus);
};

llvm::MDNode *GetScopeFromInst(llvm::Instruction &I);

std::vector<bool> GenerateLiveSet(llvm::Module *module, std::unordered_map<llvm::MDNode *, uint64_t> &scopes);

}  // namespace remill
#endif  // REMILL_BC_DSELIM_H_
