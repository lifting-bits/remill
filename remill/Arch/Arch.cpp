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

#include "remill/Arch/Arch.h"

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>

#include <algorithm>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

DEFINE_string(arch, REMILL_ARCH,
              "Architecture of the code being translated. "
              "Valid architectures: x86, amd64 (with or without "
              "`_avx` or `_avx512` appended), aarch64");

DECLARE_string(os);

namespace remill {

class Arch::Impl {
 public:
  // State type.
  llvm::StructType *state_type{nullptr};

  // Memory pointer type.
  llvm::PointerType *memory_type{nullptr};

  // Lifted function type.
  llvm::FunctionType *lifted_function_type{nullptr};

  std::vector<Register> registers;
  std::vector<const Register *> reg_by_offset;
  std::unordered_map<std::string, const Register *> reg_by_name;
};

namespace {

static unsigned AddressSize(ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      LOG(FATAL) << "Cannot get address size for invalid arch.";
      return 0;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512: return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchAArch64LittleEndian: return 64;
  }
  return 0;
}

}  // namespace

Arch::Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(AddressSize(arch_name_)),
      context(context_) {}

Arch::~Arch(void) {}

bool Arch::LazyDecodeInstruction(uint64_t address, std::string_view instr_bytes,
                                 Instruction &inst) const {
  return DecodeInstruction(address, instr_bytes, inst);
}

// Returns `true` if memory access are little endian byte ordered.
bool Arch::MemoryAccessIsLittleEndian(void) const {
  return true;
}

// Returns `true` if a given instruction might have a delay slot.
bool Arch::MayHaveDelaySlot(const Instruction &) const {
  return false;
}

// Returns `true` if a given instruction might have a delay slot.
bool Arch::NextInstructionIsDelayed(const Instruction &, const Instruction &,
                                    bool) const {
  return false;
}

llvm::Triple Arch::BasicTriple(void) const {
  llvm::Triple triple;
  switch (os_name) {
    case kOSInvalid: LOG(FATAL) << "Cannot get triple OS."; break;

    case kOSLinux:
      triple.setOS(llvm::Triple::Linux);
      triple.setEnvironment(llvm::Triple::GNU);
      triple.setVendor(llvm::Triple::PC);
      triple.setObjectFormat(llvm::Triple::ELF);
      break;

    case kOSmacOS:
      triple.setOS(llvm::Triple::MacOSX);
      triple.setEnvironment(llvm::Triple::UnknownEnvironment);
      triple.setVendor(llvm::Triple::Apple);
      triple.setObjectFormat(llvm::Triple::MachO);
      break;

    case kOSWindows:
      triple.setOS(llvm::Triple::Win32);
      triple.setEnvironment(llvm::Triple::MSVC);
      triple.setVendor(llvm::Triple::UnknownVendor);
      triple.setObjectFormat(llvm::Triple::COFF);
      break;

    case kOSSolaris:
      triple.setOS(llvm::Triple::Solaris);
      triple.setEnvironment(llvm::Triple::UnknownEnvironment);
      triple.setVendor(llvm::Triple::UnknownVendor);
      triple.setObjectFormat(llvm::Triple::ELF);
      break;
  }
  return triple;
}

auto Arch::Build(llvm::LLVMContext *context_, OSName os_name_,
                 ArchName arch_name_) -> ArchPtr {

  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchAArch64LittleEndian: {
      DLOG(INFO) << "Using architecture: AArch64, feature set: Little Endian";
      return GetAArch64(context_, os_name_, arch_name_);
    }

    case kArchX86: {
      DLOG(INFO) << "Using architecture: X86";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchX86_AVX: {
      DLOG(INFO) << "Using architecture: X86, feature set: AVX";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchX86_AVX512: {
      DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchAMD64: {
      DLOG(INFO) << "Using architecture: AMD64";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchAMD64_AVX: {
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchAMD64_AVX512: {
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
      return GetX86(context_, os_name_, arch_name_);
    }
  }
}

const Arch *Arch::Get(llvm::LLVMContext &context, OSName os,
                      ArchName arch_name) {
  return Arch::Build(&context, os, arch_name).release();
}

auto Arch::GetHostArch(llvm::LLVMContext &ctx) -> ArchPtr {
  return Arch::Build(&ctx, GetOSName(REMILL_OS), GetArchName(REMILL_ARCH));
}

auto Arch::GetTargetArch(llvm::LLVMContext &ctx) -> ArchPtr {
  return Arch::Build(&ctx, GetOSName(FLAGS_os), GetArchName(FLAGS_arch));
}

// Return the type of the state structure.
llvm::StructType *Arch::StateStructType(void) const {
  CHECK(impl)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return impl->state_type;
}

// Return the type of an address, i.e. `addr_t` in the semantics.
llvm::IntegerType *Arch::AddressType(void) const {
  return llvm::IntegerType::get(*context, address_size);
}

// The type of memory.
llvm::PointerType *Arch::MemoryPointerType(void) const {
  CHECK(impl)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return impl->memory_type;
}

// Return the type of a lifted function.
llvm::FunctionType *Arch::LiftedFunctionType(void) const {
  CHECK(impl)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return impl->lifted_function_type;
}

// Return information about the register at offset `offset` in the `State`
// structure.
const Register *Arch::RegisterAtStateOffset(uint64_t offset) const {
  auto &reg_by_offset = impl->reg_by_offset;
  if (offset >= reg_by_offset.size()) {
    return nullptr;
  } else {
    return reg_by_offset[offset];  // May be `nullptr`.
  }
}

// Apply `cb` to every register.
void Arch::ForEachRegister(std::function<void(const Register *)> cb) const {
  for (const auto &reg : impl->registers) {
    cb(&reg);
  }
}

// Return information about a register, given its name.
const Register *Arch::RegisterByName(const std::string &name) const {
  auto reg_it = impl->reg_by_name.find(name);
  if (reg_it == impl->reg_by_name.end()) {
    return nullptr;
  } else {
    return reg_it->second;
  }
}

namespace {

// NOTE(lukas): Structure that allows global caching of `Arch` objects,
//              as key llvm::LLVMContext * is used. Eventually this should
//              be removed in favor of Arch::Build/Get* but some old code may
//              depend on this caching behaviour.
struct AvailableArchs {
  using ArchMap =
      std::unordered_map<llvm::LLVMContext *, std::unique_ptr<const Arch>>;

  static ArchMap cached;

  static const Arch *GetOrCreate(llvm::LLVMContext *ctx, OSName os,
                                 ArchName name) {
    auto &arch = cached[ctx];
    if (!arch) {
      arch = Create(ctx, os, name);
    }
    return arch.get();
  }

  static const Arch *Get(llvm::LLVMContext *ctx) {
    if (auto arch_it = cached.find(ctx); arch_it != cached.end())
      return arch_it->second.get();
    return nullptr;
  }

  static Arch::ArchPtr Create(llvm::LLVMContext *ctx, OSName os,
                              ArchName name) {
    return Arch::Build(ctx, os, name);
  }
};

AvailableArchs::ArchMap AvailableArchs::cached = {};

static const Arch *GetOrCreate(llvm::LLVMContext &ctx, OSName os,
                               ArchName name) {
  return AvailableArchs::GetOrCreate(&ctx, os, name);
}

}  // namespace

const Arch *GetHostArch(llvm::LLVMContext &ctx) {
  return GetOrCreate(ctx, GetOSName(REMILL_OS), GetArchName(REMILL_ARCH));
}

const Arch *GetTargetArch(llvm::LLVMContext &ctx) {
  return GetOrCreate(ctx, GetOSName(FLAGS_os), GetArchName(FLAGS_arch));
}

remill::Arch::ArchPtr Arch::GetModuleArch(const llvm::Module &module) {
  const llvm::Triple triple = llvm::Triple(module.getTargetTriple());
  return remill::Arch::Build(&module.getContext(), GetOSName(triple),
                             GetArchName(triple));
}

bool Arch::IsX86(void) const {
  switch (arch_name) {
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512: return true;
    default: return false;
  }
}

bool Arch::IsAMD64(void) const {
  switch (arch_name) {
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512: return true;
    default: return false;
  }
}

bool Arch::IsAArch64(void) const {
  return remill::kArchAArch64LittleEndian == arch_name;
}

bool Arch::IsWindows(void) const {
  return remill::kOSWindows == os_name;
}

bool Arch::IsLinux(void) const {
  return remill::kOSLinux == os_name;
}

bool Arch::IsMacOS(void) const {
  return remill::kOSmacOS == os_name;
}

bool Arch::IsSolaris(void) const {
  return remill::kOSSolaris == os_name;
}

namespace {

// These variables must always be defined within `__remill_basic_block`.
static bool BlockHasSpecialVars(llvm::Function *basic_block) {
  return FindVarInFunction(basic_block, "STATE", true) &&
         FindVarInFunction(basic_block, "MEMORY", true) &&
         FindVarInFunction(basic_block, "PC", true) &&
         FindVarInFunction(basic_block, "BRANCH_TAKEN", true);
}

// Iteratively accumulate the offset, following through GEPs and bitcasts.
static bool GetRegisterOffset(llvm::Module *module, llvm::Type *state_ptr_type,
                              llvm::Value *reg, uint64_t *offset) {

  auto val_name = reg->getName().str();
  const auto &dl = module->getDataLayout();
  *offset = 0;
  do {
    if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(reg)) {
      llvm::APInt gep_offset(dl.getPointerSizeInBits(0), 0);
      if (!gep->accumulateConstantOffset(dl, gep_offset)) {
        DLOG(INFO) << "Named variable " << val_name
                   << " is not a register in the "
                   << "state structure";
      }
      *offset += gep_offset.getZExtValue();
      reg = gep->getPointerOperand();

    } else if (auto c = llvm::dyn_cast<llvm::CastInst>(reg)) {
      reg = c->getOperand(0);

    // Base case.
    } else if (reg->getType() == state_ptr_type) {
      break;

    } else {
      DLOG(INFO) << "Named variable " << val_name
                 << " is not a register in the "
                 << "state structure";
      return false;
    }
  } while (reg);

  DLOG(INFO) << "Offset of register " << val_name << " in state structure is "
             << *offset;

  return true;
}

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` intrinsic with the same names as we find in the
// C++ definition of that function. However, we compile that function with
// debug information, and so we will try to recover the variables names for
// later lookup.
static void FixupBasicBlockVariables(llvm::Function *basic_block) {
  std::unordered_map<llvm::Value *, std::string> names;
  std::unordered_map<llvm::Value *, std::string> preferred_names;
  std::unordered_set<std::string> used_names;
  std::vector<llvm::StoreInst *> stores;
  std::vector<llvm::Instruction *> remove_insts;

  std::unordered_map<llvm::AllocaInst *, llvm::Value *> stored_val;

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (inst.hasName()) {
        names[&inst] = inst.getName().str();
      }
    }
  }

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
        if (auto decl_inst = llvm::dyn_cast<llvm::DbgDeclareInst>(debug_inst)) {
          auto addr = decl_inst->getAddress();
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 7)
          names[addr] = decl_inst->getVariable()->getName().str();
#else
          llvm::DIVariable var(decl_inst->getVariable());
          names[addr] = var.getName().str();
#endif
        }
        remove_insts.push_back(debug_inst);

      // Get stores.
      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
        auto dst_alloca =
            llvm::dyn_cast<llvm::AllocaInst>(store_inst->getPointerOperand());
        if (dst_alloca) {
          stored_val[dst_alloca] = store_inst->getValueOperand();
        }
        stores.push_back(store_inst);

      // Forward stores to loads.
      } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
        auto src_alloca =
            llvm::dyn_cast<llvm::AllocaInst>(load_inst->getPointerOperand());
        if (src_alloca) {
          if (auto val = stored_val[src_alloca]) {
            load_inst->replaceAllUsesWith(val);
            remove_insts.push_back(load_inst);
          }
        }

      } else if (llvm::isa<llvm::BranchInst>(&inst) ||
                 llvm::isa<llvm::CallInst>(&inst) ||
                 llvm::isa<llvm::InvokeInst>(&inst)) {
        LOG(FATAL) << "Unsupported instruction in __remill_basic_block: "
                   << LLVMThingToString(&inst);
      }
    }
  }

  // At this point, the instructions should have this form:
  //
  //  %BH = alloca i8*, align 8
  //  ...
  //  %24 = getelementptr inbounds ...
  //  store i8* %24, i8** %BH, align 8
  //
  // Our goal is to eliminate the double indirection and get:
  //
  //  %BH = getelementptr inbounds ...

  for (auto inst : stores) {
    auto val = llvm::dyn_cast<llvm::Instruction>(inst->getValueOperand());
    auto ptr = llvm::dyn_cast<llvm::AllocaInst>(inst->getPointerOperand());

    if (val && ptr && val->getType()->isPointerTy() && names.count(ptr)) {
      preferred_names[val] = names[ptr];
      remove_insts.push_back(ptr);
      remove_insts.push_back(inst);
    }
  }

  // Remove links between instructions.
  for (auto inst : remove_insts) {
    if (!inst->getType()->isVoidTy()) {
      inst->replaceAllUsesWith(llvm::UndefValue::get(inst->getType()));
    }
  }

  // Remove unneeded instructions.
  for (auto inst : remove_insts) {
    for (auto &operand : inst->operands()) {
      operand = nullptr;
    }
    inst->eraseFromParent();
  }

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (!inst.getType()->isVoidTy()) {
        inst.setName("");
      }
    }
  }

  // First, apply names to preferred names, which are propagated.
  for (auto &block : *basic_block) {
    auto it = block.rbegin();
    auto end = block.rend();
    for (; it != end; ++it) {
      auto &inst = *it;
      auto name_it = preferred_names.find(&inst);
      if (name_it != preferred_names.end()) {
        auto &entry = *name_it;
        if (!entry.first->getType()->isVoidTy() &&
            !used_names.count(entry.second)) {
          entry.first->setName(entry.second);
          used_names.insert(entry.second);
        }
      }
    }
  }

  // Finally, apply the previous names. These may conflict with the preferred
  // names, but that
  for (auto &block : *basic_block) {
    auto it = block.rbegin();
    auto end = block.rend();
    for (; it != end; ++it) {
      auto &inst = *it;
      auto name_it = names.find(&inst);
      if (name_it != names.end()) {
        auto &entry = *name_it;
        if (!entry.first->hasName() && !entry.first->getType()->isVoidTy() &&
            !used_names.count(entry.second)) {
          entry.first->setName(entry.second);
          used_names.insert(entry.second);
        }
      }
    }
  }

  CHECK(BlockHasSpecialVars(basic_block))
      << "Unable to locate required variables in `__remill_basic_block`.";
}

// Add attributes to llvm::Argument in a way portable across LLVMs
static void AddNoAliasToArgument(llvm::Argument *arg) {
  IF_LLVM_LT_390(arg->addAttr(llvm::AttributeSet::get(
      arg->getContext(), arg->getArgNo() + 1, llvm::Attribute::NoAlias)););

  IF_LLVM_GTE_390(arg->addAttr(llvm::Attribute::NoAlias););
}

// ensures that mandatory remill functions have the correct
// type signature and variable names
static void PrepareModuleRemillFunctions(llvm::Module *mod) {
  auto basic_block = BasicBlockFunction(mod);

  InitFunctionAttributes(basic_block);
  FixupBasicBlockVariables(basic_block);

  basic_block->setLinkage(llvm::GlobalValue::ExternalLinkage);
  basic_block->setVisibility(llvm::GlobalValue::DefaultVisibility);
  basic_block->removeFnAttr(llvm::Attribute::AlwaysInline);
  basic_block->removeFnAttr(llvm::Attribute::InlineHint);
  basic_block->addFnAttr(llvm::Attribute::OptimizeNone);
  basic_block->addFnAttr(llvm::Attribute::NoInline);
  basic_block->setVisibility(llvm::GlobalValue::DefaultVisibility);

  auto memory = remill::NthArgument(basic_block, kMemoryPointerArgNum);
  auto state = remill::NthArgument(basic_block, kStatePointerArgNum);

  memory->setName("");
  state->setName("");
  remill::NthArgument(basic_block, kPCArgNum)->setName("");

  AddNoAliasToArgument(state);
  AddNoAliasToArgument(memory);
}

// Compare two registers for sorting.
static bool RegisterComparator(const Register &lhs, const Register &rhs) {

  // Bigger to appear later in the array. E.g. RAX before EAX.
  if (lhs.size > rhs.size) {
    return true;

  } else if (lhs.size < rhs.size) {
    return false;

  // Registers earlier in the state struct appear earlier in the
  // sort.
  } else if (lhs.offset < rhs.offset) {
    return true;

  } else if (lhs.offset > rhs.offset) {
    return false;

  } else {
    return lhs.complexity < rhs.complexity;
  }
}

}  // namespace

Register::Register(const std::string &name_, uint64_t offset_, uint64_t size_,
                   uint64_t complexity_, llvm::Type *type_)
    : name(name_),
      offset(offset_),
      size(size_),
      complexity(complexity_),
      type(type_),
      constant_name(
          llvm::ConstantDataArray::getString(type->getContext(), name_)) {}

// Returns the enclosing register of size AT LEAST `size`, or `nullptr`.
const Register *Register::EnclosingRegisterOfSize(uint64_t size_) const {
  auto enclosing = this;
  for (; enclosing && enclosing->size < size_; enclosing = enclosing->parent) {
    /* Empty. */;
  }
  return enclosing;
}

// Returns the largest enclosing register containing the current register.
const Register *Register::EnclosingRegister(void) const {
  auto enclosing = this;
  while (enclosing->parent) {
    enclosing = enclosing->parent;
  }
  return enclosing;
}

// Returns the list of directly enclosed registers. For example,
// `RAX` will directly enclose `EAX` but nothing else. `AX` will directly
// enclose `AH` and `AL`.
const std::vector<const Register *> &Register::EnclosedRegisters(void) const {
  return children;
}

namespace {

// Return the complexity of this state indexing operation.
static unsigned Complexity(llvm::Value *base, llvm::Type *state_ptr_type) {
  unsigned complexity = 0;
  while (base) {
    if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(base)) {
      complexity += gep->getNumOperands();
      base = gep->getPointerOperand();

    } else if (auto bc = llvm::dyn_cast<llvm::BitCastInst>(base)) {
      base = bc->getOperand(0);
      complexity += 1;

    } else if (base->getType() == state_ptr_type) {
      break;

    } else {
      LOG(FATAL) << "Unexpected value " << LLVMThingToString(base)
                 << " in State structure indexing chain";
      base = nullptr;
    }
  }
  return complexity;
}

// Compute the total offset of a GEP chain.
static uint64_t TotalOffset(const llvm::DataLayout &dl, llvm::Value *base,
                            llvm::Type *state_ptr_type) {
  uint64_t total_offset = 0;
  const auto state_size =
      dl.getTypeAllocSize(state_ptr_type->getPointerElementType());
  while (base) {
    if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(base); gep) {
      llvm::APInt accumulated_offset(dl.getPointerSizeInBits(0), 0, false);
      CHECK(gep->accumulateConstantOffset(dl, accumulated_offset));
      auto curr_offset = accumulated_offset.getZExtValue();
      CHECK_LT(curr_offset, state_size);
      total_offset += curr_offset;
      CHECK_LT(total_offset, state_size);

      base = gep->getPointerOperand();

    } else if (auto bc = llvm::dyn_cast<llvm::BitCastOperator>(base); bc) {
      base = bc->getOperand(0);

    } else if (auto itp = llvm::dyn_cast<llvm::IntToPtrInst>(base); itp) {
      base = itp->getOperand(0);

    } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(base); pti) {
      base = pti->getOperand(0);

    } else if (base->getType() == state_ptr_type) {
      break;

    } else {
      LOG(FATAL) << "Unexpected value " << LLVMThingToString(base)
                 << " in State structure indexing chain";
      base = nullptr;
    }
  }
  return total_offset;
}

static llvm::Value *
FinishAddressOf(llvm::IRBuilder<> &ir, const llvm::DataLayout &dl,
                llvm::Type *state_ptr_type, size_t state_size,
                const Register *reg, unsigned addr_space, llvm::Value *gep) {

  auto gep_offset = TotalOffset(dl, gep, state_ptr_type);
  auto gep_type_at_offset = gep->getType()->getPointerElementType();

  CHECK_LT(gep_offset, state_size);

  const auto index_type = reg->gep_index_list[0]->getType();
  const auto goal_ptr_type = llvm::PointerType::get(reg->type, addr_space);

  // Best case: we've found a value field in the structure that
  // is located at the correct byte offset.
  if (gep_offset == reg->offset) {
    if (gep_type_at_offset == reg->type) {
      return gep;

    } else if (auto const_gep = llvm::dyn_cast<llvm::Constant>(gep);
               const_gep) {
      return llvm::ConstantExpr::getBitCast(const_gep, goal_ptr_type);

    } else {
      return ir.CreateBitCast(gep, goal_ptr_type);
    }
  }

  const auto diff = reg->offset - gep_offset;

  // Next best case: the difference between what we want and what we have
  // is a multiple of the size of the register, so we can cast to the
  // `goal_ptr_type` and index.
  if (((diff / reg->size) * reg->size) == diff) {
    llvm::Value *elem_indexes[] = {
        llvm::ConstantInt::get(index_type, diff / reg->size, false)};

    if (auto const_gep = llvm::dyn_cast<llvm::Constant>(gep); const_gep) {
      const_gep = llvm::ConstantExpr::getBitCast(const_gep, goal_ptr_type);
      return llvm::ConstantExpr::getGetElementPtr(reg->type, const_gep,
                                                  elem_indexes);

    } else {
      const auto arr = ir.CreateBitCast(gep, goal_ptr_type);
      return ir.CreateGEP(reg->type, arr, elem_indexes);
    }
  }

  // Worst case is that we have to fall down to byte-granularity
  // pointer arithmetic.
  const auto byte_type =
      llvm::IntegerType::getInt8Ty(goal_ptr_type->getContext());
  llvm::Value *elem_indexes[] = {
      llvm::ConstantInt::get(index_type, diff, false)};

  if (auto const_gep = llvm::dyn_cast<llvm::Constant>(gep); const_gep) {
    const_gep = llvm::ConstantExpr::getBitCast(
        const_gep, llvm::PointerType::get(byte_type, addr_space));
    const_gep = llvm::ConstantExpr::getGetElementPtr(byte_type, const_gep,
                                                     elem_indexes);
    return llvm::ConstantExpr::getBitCast(const_gep, goal_ptr_type);

  } else {
    gep = ir.CreateBitCast(gep, llvm::PointerType::get(byte_type, addr_space));
    gep = ir.CreateGEP(byte_type, gep, elem_indexes);
    return ir.CreateBitCast(gep, goal_ptr_type);
  }
}

}  // namespace

// Generate a GEP that will let us load/store to this register, given
// a `State *`.
llvm::Value *Register::AddressOf(llvm::Value *state_ptr,
                                 llvm::BasicBlock *add_to_end) const {
  CHECK_EQ(&(type->getContext()), &(state_ptr->getContext()));
  const auto state_ptr_type =
      llvm::dyn_cast<llvm::PointerType>(state_ptr->getType());
  CHECK_NOTNULL(state_ptr_type);
  const auto addr_space = state_ptr_type->getAddressSpace();

  const auto state_type =
      llvm::dyn_cast<llvm::StructType>(state_ptr_type->getPointerElementType());
  CHECK_NOTNULL(state_type);

  const auto module = add_to_end->getParent()->getParent();
  const auto &dl = module->getDataLayout();
  llvm::IRBuilder<> ir(add_to_end);
  llvm::Value *gep = nullptr;
  if (auto const_state_ptr = llvm::dyn_cast<llvm::Constant>(state_ptr);
      const_state_ptr) {
    gep = llvm::ConstantExpr::getInBoundsGetElementPtr(
        state_type, const_state_ptr, gep_index_list);
  } else {
    gep = llvm::GetElementPtrInst::CreateInBounds(
        state_type, state_ptr, gep_index_list, "", add_to_end);
  }

  auto state_size = dl.getTypeAllocSize(state_type);
  return FinishAddressOf(ir, dl, state_ptr_type, state_size, this, addr_space,
                         gep);
}

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
//
void Arch::PrepareModuleDataLayout(llvm::Module *mod) const {
  mod->setDataLayout(DataLayout().getStringRepresentation());
  mod->setTargetTriple(Triple().str());

  // Go and remove compile-time attributes added into the semantics. These
  // can screw up later compilation. We purposefully compile semantics with
  // things like auto-vectorization disabled so that it keeps the bitcode
  // to a simpler subset of the available LLVM instuction set. If/when we
  // compile this bitcode back into machine code, we may want to use those
  // features, and clang will complain if we try to do so if these metadata
  // remain present.
  auto &context = mod->getContext();

  llvm::AttributeSet target_attribs;
  target_attribs = target_attribs.addAttribute(
      context,
      IF_LLVM_LT_500_(llvm::AttributeSet::FunctionIndex) "target-features");
  target_attribs = target_attribs.addAttribute(
      context, IF_LLVM_LT_500_(llvm::AttributeSet::FunctionIndex) "target-cpu");

  for (llvm::Function &func : *mod) {
    auto attribs = func.getAttributes();
    attribs = attribs.removeAttributes(
        context, llvm::AttributeLoc::FunctionIndex, target_attribs);
    func.setAttributes(attribs);
  }
}

void Arch::PrepareModule(llvm::Module *mod) const {
  CHECK_EQ(&(mod->getContext()), context);
  llvm::Triple orig_mod_triple(mod->getTargetTriple());
  PrepareModuleRemillFunctions(mod);
  PrepareModuleDataLayout(mod);
  if (!impl) {
    impl.reset(new Impl);
    CollectRegisters(mod);
  }
  llvm::Triple new_mod_triple(mod->getTargetTriple());

  //  // If `mod` was compiled on macOS, but we're targeting Linux, then strip
  //  // off leading underscore prefixes.
  //  if (orig_mod_triple.isMacOSX() && new_mod_triple.isOSLinux()) {
  //    for (auto &func : *mod) {
  //      if (!func.hasExternalLinkage() ||
  //          !func.getName().startswith("_") ||
  //          func.getName() == "main" ||
  //          func.getName().startswith("__remill")) {
  //        continue;
  //      }
  //
  //      auto unprefixed_name = func.getName().substr(1).str();
  //      if (!mod->getFunction(unprefixed_name)) {
  //        func.setName(unprefixed_name);
  //      }
  //    }
  //
  //    for (auto &var : mod->globals()) {
  //      if (!var.hasExternalLinkage() || !var.getName().startswith("_")) {
  //        continue;
  //      }
  //
  //      auto unprefixed_name = var.getName().substr(1).str();
  //      if (!mod->getGlobalVariable(unprefixed_name, false)) {
  //        var.setName(unprefixed_name);
  //      }
  //    }
  //
  //  // If `mod` was compiled on Linux, but we're targeting macOS, then prefix
  //  // the external symbol names with underscores.
  //  } else if (orig_mod_triple.isOSLinux() && new_mod_triple.isMacOSX()) {
  //    for (auto &func : *mod) {
  //      if (!func.hasExternalLinkage() ||
  //          !func.hasName() ||
  //          func.getName() == "main" ||
  //          func.getName().startswith("__remill")) {
  //        continue;
  //      }
  //
  //      std::stringstream ss;
  //      ss << "_" << func.getName().str();
  //      const auto prefixed_name = ss.str();
  //
  //      if (!mod->getFunction(prefixed_name)) {
  //        func.setName(prefixed_name);
  //      }
  //    }
  //
  //    for (auto &var : mod->globals()) {
  //      if (!var.hasExternalLinkage() || !var.hasName()) {
  //        continue;
  //      }
  //
  //      std::stringstream ss;
  //      ss << "_" << var.getName().str();
  //      const auto prefixed_name = ss.str();
  //
  //      if (!mod->getGlobalVariable(prefixed_name, false)) {
  //        var.setName(prefixed_name);
  //      }
  //    }
  //  }
}

// Get all of the register information from the prepared module.
void Arch::CollectRegisters(llvm::Module *module) const {
  CHECK(!impl->state_type);

  llvm::DataLayout dl(module);
  const auto basic_block = BasicBlockFunction(module);
  const auto state_ptr_type = ::remill::StatePointerType(module);
  const auto state_type =
      llvm::dyn_cast<llvm::StructType>(state_ptr_type->getElementType());
  const auto state_size = dl.getTypeAllocSize(state_type);
  const auto index_type = llvm::Type::getInt32Ty(module->getContext());

  impl->state_type = state_type;
  impl->memory_type = ::remill::MemoryPointerType(module);
  impl->lifted_function_type = basic_block->getFunctionType();

  std::unordered_map<std::string, llvm::Instruction *> prev_reg_by_name;

  llvm::Instruction *insert_loc = nullptr;

  // Collect all registers.
  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (llvm::isa<llvm::ReturnInst>(&inst)) {
        insert_loc = &inst;
      }

      uint64_t offset = 0;
      if (!inst.hasName()) {
        continue;
      }
      auto ptr_type = llvm::dyn_cast<llvm::PointerType>(inst.getType());
      if (!ptr_type || ptr_type->getElementType()->isPointerTy()) {
        continue;
      }

      auto reg_type = ptr_type->getElementType();
      if (!GetRegisterOffset(module, state_ptr_type, &inst, &offset)) {
        continue;
      }

      // In `__remill_basic_block`, register assignments are the "last" things,
      // and aren't re-used for accessing sub-registers.
      if (!inst.hasNUses(0)) {
        continue;
      }

      auto name = inst.getName().str();
      impl->registers.emplace_back(name, offset, dl.getTypeAllocSize(reg_type),
                                   Complexity(&inst, state_ptr_type), reg_type);

      prev_reg_by_name[name] = &inst;
    }
  }

  CHECK_NOTNULL(insert_loc);

  // Sort them in such a way that we can recover the parentage of registers.
  std::sort(impl->registers.begin(), impl->registers.end(), RegisterComparator);

  impl->reg_by_offset.resize(dl.getTypeAllocSize(state_type));

  // Figure out parentage of registers, and fill in the various maps. Now that
  // `registers` is "finalized", it's safe to cross-link the various `Register`s
  // by pointer, as we won't be sorting/resizing the vector anymore.
  for (auto &reg : impl->registers) {
    impl->reg_by_name[reg.name] = &reg;

    for (uint64_t i = 0; i < reg.size; ++i) {
      auto &reg_at_offset = impl->reg_by_offset[reg.offset + i];
      if (!reg.parent) {
        reg.parent = reg_at_offset;
        if (reg_at_offset) {
          const_cast<Register *>(reg_at_offset)->children.push_back(&reg);
        }
      } else if (!reg_at_offset) {
        LOG(FATAL) << "Register " << reg.name
                   << " is not fully enclosed by parent " << reg.parent->name;
      } else if (reg.parent != reg_at_offset) {
        LOG(FATAL) << "Can't set parent of register " << reg.name << " to "
                   << reg_at_offset->name << " because it already has "
                   << reg.parent->name << " as its parent";
      }
      reg_at_offset = &reg;
    }

    reg.gep_index_list.push_back(llvm::ConstantInt::get(index_type, 0, false));

    std::tie(reg.gep_offset, reg.gep_type_at_offset) =
        BuildIndexes(dl, state_type, 0, reg.offset, reg.gep_index_list);

    CHECK(reg.gep_type_at_offset != nullptr)
        << "Unable to create index list for register '" << reg.name << "'";
  }

  auto state_ptr = NthArgument(basic_block, remill::kStatePointerArgNum);

  std::unordered_map<const Register *, llvm::SmallVector<llvm::Value *, 8>>
      reg_indexes;
  std::unordered_map<const Register *, llvm::GetElementPtrInst *> reg_gep;

  auto adjust_indexes = [=](const Register &reg,
                            llvm::SmallVector<llvm::Value *, 8> &index_vec) {
    if (!reg.children.empty()) {
      auto ptr_type = llvm::dyn_cast<llvm::PointerType>(
          llvm::GetElementPtrInst::getGEPReturnType(state_type, state_ptr,
                                                    index_vec));
      while (!ptr_type->getElementType()->isStructTy()) {
        index_vec.pop_back();
        CHECK(!index_vec.empty());
        ptr_type = llvm::dyn_cast<llvm::PointerType>(
            llvm::GetElementPtrInst::getGEPReturnType(state_type, state_ptr,
                                                      index_vec));
      }
    }
  };

  // Re-add register-specific instructions, but make sure that all GEPs for
  // sub-regs are derived from those of parent regs.
  for (auto &reg : impl->registers) {
    if (!reg.parent) {
      auto index_vec = reg.gep_index_list;
      adjust_indexes(reg, index_vec);
      reg_gep[&reg] = llvm::GetElementPtrInst::CreateInBounds(
          state_type, state_ptr, index_vec, llvm::Twine::createNull(),
          insert_loc);

      reg_indexes[&reg] = std::move(index_vec);

    } else {
      auto &parent_indexes = reg_indexes[reg.parent];
      auto parent_gep = reg_gep[reg.parent];
      CHECK_NOTNULL(parent_gep);
      const auto parent_elem_type =
          parent_gep->getType()->getPointerElementType();
      CHECK(parent_elem_type->isStructTy())
          << "Parent register " << reg.parent->name
          << " truncated index list isn't pointing to a structure type; got: "
          << LLVMThingToString(parent_elem_type) << " from "
          << LLVMThingToString(parent_gep);

      if (1 < parent_indexes.size() &&
          parent_indexes.size() < reg.gep_index_list.size()) {
        CHECK_EQ(parent_indexes.back(),
                 reg.gep_index_list[parent_indexes.size() - 1]);

        auto index_vec = reg.gep_index_list;
        adjust_indexes(reg, index_vec);

        auto sub_indexes = index_vec;

        std::reverse(sub_indexes.begin(), sub_indexes.end());
        for (auto i = 0U; i < parent_indexes.size(); ++i) {
          CHECK(!sub_indexes.empty());
          CHECK_EQ(sub_indexes.back(), parent_indexes[i]);
          sub_indexes.pop_back();
        }
        std::reverse(sub_indexes.begin(), sub_indexes.end());

        auto gep = llvm::GetElementPtrInst::CreateInBounds(
            parent_elem_type, parent_gep, sub_indexes,
            llvm::Twine::createNull(), insert_loc);

        CHECK_LE(TotalOffset(dl, gep, state_ptr_type), reg.offset);

        reg_gep[&reg] = gep;
        reg_indexes[&reg] = std::move(index_vec);

      } else if (parent_indexes.size() == reg.gep_index_list.size()) {
        llvm::Value *sub_indices[] = {llvm::ConstantInt::get(index_type, 0)};
        auto gep = llvm::GetElementPtrInst::CreateInBounds(
            parent_elem_type, parent_gep, sub_indices,
            llvm::Twine::createNull(), insert_loc);

        CHECK_LE(TotalOffset(dl, gep, state_ptr_type), reg.offset);

        reg_gep[&reg] = gep;
        reg_indexes[&reg] = reg.gep_index_list;

      } else {
        auto gep = llvm::GetElementPtrInst::CreateInBounds(
            parent_elem_type, parent_gep, reg.gep_index_list,
            llvm::Twine::createNull(), insert_loc);

        CHECK_LE(TotalOffset(dl, gep, state_ptr_type), reg.offset);
        reg_gep[&reg] = gep;
        reg_indexes[&reg] = reg.gep_index_list;
      }
    }
  }

  const auto reg_md_id = context->getMDKindID("remill_register");

  // Replace the old versions of the registers with new versions.
  const auto addr_space = state_ptr_type->getAddressSpace();
  llvm::IRBuilder<> ir(insert_loc);
  for (auto &reg : impl->registers) {
    auto final = FinishAddressOf(ir, dl, state_ptr_type, state_size, &reg,
                                 addr_space, reg_gep[&reg]);

    auto prev_reg = prev_reg_by_name[reg.name];
    prev_reg->replaceAllUsesWith(final);
    prev_reg->eraseFromParent();
    final->setName(reg.name);

    // Create the node for a `remill_register` annotation.
    if (auto final_inst = llvm::dyn_cast<llvm::Instruction>(final);
        final_inst) {
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
      auto reg_name_md = llvm::ValueAsMetadata::get(reg.constant_name);
      auto reg_name_node = llvm::MDNode::get(*context, reg_name_md);
#else
      auto reg_name_node = llvm::MDNode::get(*context, reg.constant_name);
#endif
      final_inst->setMetadata(reg_md_id, reg_name_node);
    }
  }

  // Run through and delete dead unnamed instructions.
  std::vector<llvm::Instruction *> to_remove;
  for (auto changed = true; changed;) {
    changed = false;
    for (auto &block : *basic_block) {
      for (auto &inst : block) {
        if (inst.getType()->isPointerTy() && !inst.hasName() &&
            !inst.hasNUsesOrMore(1)) {
          to_remove.push_back(&inst);
          changed = true;
        }
      }
      for (auto inst : to_remove) {
        inst->eraseFromParent();
      }
      to_remove.clear();
    }
  }
}

}  // namespace remill
