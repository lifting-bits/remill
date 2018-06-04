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
    virtual void Visit(llvm::Type *ty);
};

std::vector<StateSlot> StateSlots(llvm::Module *module);

typedef std::unordered_map<llvm::Value *, uint64_t> ValueToOffset;
typedef std::unordered_map<llvm::MDNode *, uint64_t> ScopeMap;

enum class VisitResult;

enum class OpType {
  Plus,
  Minus,
};

struct ForwardAliasVisitor : public llvm::InstVisitor<ForwardAliasVisitor, VisitResult> {
  public:
    const std::vector<StateSlot> &state_slots;
    ValueToOffset offset_map;
    ValueToOffset alias_map;
    std::unordered_set<llvm::Value *> exclude;
    std::unordered_set<llvm::Instruction *> curr_wl;
    std::unordered_set<llvm::Instruction *> next_wl;
    llvm::Value *state_ptr;

    ForwardAliasVisitor(const std::vector<StateSlot> &state_slots_, llvm::DataLayout *dl_, llvm::Value *sp_);
    void AddInstruction(llvm::Instruction *inst);
    bool Analyze();

    virtual VisitResult visitInstruction(llvm::Instruction &I); 
    virtual VisitResult visitAllocaInst(llvm::AllocaInst &I);
    virtual VisitResult visitLoadInst(llvm::LoadInst &I);
    virtual VisitResult visitStoreInst(llvm::StoreInst &I);
    virtual VisitResult visitGetElementPtrInst(llvm::GetElementPtrInst &I);
    virtual VisitResult visitCastInst(llvm::CastInst &I);
    virtual VisitResult visitAdd(llvm::BinaryOperator &I);
    virtual VisitResult visitSub(llvm::BinaryOperator &I);
    virtual VisitResult visitPHINode(llvm::PHINode &I);

  private:
    const llvm::DataLayout *dl;
    virtual VisitResult visitBinaryOp_(llvm::BinaryOperator &I, OpType op);
};

// A struct representing the information derived from StateSlots:
// - a map of MDNodes designating AAMDNode scope to the corresponding byte offset
// - a vector of AAMDNodes for each byte offset
struct AAMDInfo {
  ScopeMap slot_scopes;
  std::vector<llvm::AAMDNodes> slot_aamds;

  AAMDInfo(const std::vector<StateSlot> &slots, llvm::LLVMContext &context);
};

void AddAAMDNodes(const ValueToOffset &inst_to_offset, const std::vector<llvm::AAMDNodes> &offset_to_aamd);

ScopeMap AnalyzeAliases(llvm::Module *module, const std::vector<StateSlot> &slots);

typedef std::bitset<4096> LiveSet;

llvm::MDNode *GetScopeFromInst(llvm::Instruction &I);

class LiveSetBlockVisitor {
  public:
    llvm::Function &func;
    const ScopeMap &scope_to_offset;
    const std::vector<StateSlot> &state_slots;
    std::vector<llvm::BasicBlock *> curr_wl;
    std::vector<llvm::BasicBlock *> next_wl;
    std::unordered_map<llvm::BasicBlock *, LiveSet> block_map;
    std::unordered_set<llvm::Instruction *> to_remove;
    const llvm::FunctionType *lifted_func_ty;
    LiveSet func_used;
    bool on_remove_pass;

    LiveSetBlockVisitor(llvm::Function &func_, const std::vector<StateSlot> &state_slots_, const ScopeMap &scope_to_offset_, const llvm::FunctionType *lifted_func_ty_);
    void Visit();

    virtual bool VisitBlock(llvm::BasicBlock *B);
    virtual void RemoveDeadStores(void);
    virtual void CreateDOTDigraph(const llvm::DataLayout *dl);
};

static std::ostream &DOT(void);

void GenerateLiveSet(llvm::Module *module, const std::vector<StateSlot> &state_slots, const ScopeMap &scopes);

}  // namespace remill
#endif  // REMILL_BC_DSELIM_H_
