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
#include <llvm/IR/AttributeMask.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/ArchBase.h>  // For `Arch` and `ArchBase`.

#include <algorithm>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/OS.h"

namespace remill {
namespace {

static unsigned AddressSize(ArchName arch_name) {
  switch (arch_name) {
    case kArchInvalid:
      LOG(FATAL) << "Cannot get address size for invalid arch.";
      return 0;
    case kArchX86:
    case kArchX86_AVX:
    case kArchX86_AVX512:
    case kArchX86_SLEIGH:
    case kArchAArch32LittleEndian:
    case kArchThumb2LittleEndian:
    case kArchSparc32:
    case kArchSparc32_SLEIGH:
    case kArchMIPS: return 32; // Actually MIPS64 but on 32bit Address bus for vr4300
    case kArchPPC: return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchAMD64_SLEIGH:
    case kArchAArch64LittleEndian:
    case kArchAArch64LittleEndian_SLEIGH:
    case kArchSparc64: return 64;
  }
  return 0;
}

}  // namespace

Arch::Arch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(AddressSize(arch_name_)),
      context(context_) {}

ArchBase::ArchBase(llvm::LLVMContext *context_, OSName os_name_,
                   ArchName arch_name_)
    : Arch(context_, os_name_, arch_name_) {}

Arch::~Arch(void) {}

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

namespace {
static std::mutex gSleighArchLock;
}  // namespace

// Returns a lock on global state. In general, Remill doesn't use global
// variables for storing state; however, SLEIGH sometimes does, and so when
// using SLEIGH-backed architectures, it can be necessary to acquire this
// lock.
ArchLocker Arch::Lock(ArchName arch_name_) {
  switch (arch_name_) {
    case ArchName::kArchAArch32LittleEndian:
    case ArchName::kArchThumb2LittleEndian:
    case ArchName::kArchAArch64LittleEndian_SLEIGH:
    case ArchName::kArchAMD64_SLEIGH:
    case ArchName::kArchX86_SLEIGH:
    case ArchName::kArchSparc32_SLEIGH:
    case ArchName::kArchPPC: return &gSleighArchLock;
    case ArchName::kArchMIPS: return &gSleighArchLock;
    default: return ArchLocker();
  }
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


auto Arch::GetArchByName(llvm::LLVMContext *context_, OSName os_name_,
                         ArchName arch_name_) -> ArchPtr {
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchAArch64LittleEndian_SLEIGH: {
      DLOG(INFO)
          << "Using architecture: AArch64 Sleigh, feature set: Little Endian";
      return GetAArch64Sleigh(context_, os_name_, arch_name_);
    }

    case kArchAArch64LittleEndian: {
      DLOG(INFO) << "Using architecture: AArch64, feature set: Little Endian";
      return GetAArch64(context_, os_name_, arch_name_);
    }

    case kArchAArch32LittleEndian: {
      DLOG(INFO) << "Using architecture: AArch32, feature set: Little Endian";
      return GetAArch32(context_, os_name_, arch_name_);
      break;
    }

    case kArchThumb2LittleEndian: {
      DLOG(INFO) << "Using architecture: thumb2";
      return GetSleighThumb2(context_, os_name_, arch_name_);
    }

    case kArchX86: {
      DLOG(INFO) << "Using architecture: X86";
      return GetX86(context_, os_name_, arch_name_);
    }

    case kArchX86_SLEIGH: {
      DLOG(INFO) << "Using architecture: X86_Sleigh";
      return GetSleighX86(context_, os_name_, arch_name_);
    }

    case kArchAMD64_SLEIGH: {
      DLOG(INFO) << "Using architecture: X86_Sleigh";
      return GetSleighX86(context_, os_name_, arch_name_);
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

    case kArchSparc32: {
      DLOG(INFO) << "Using architecture: 32-bit SPARC";
      return GetSPARC32(context_, os_name_, arch_name_);
    }

    case kArchSparc64: {
      DLOG(INFO) << "Using architecture: 64-bit SPARC";
      return GetSPARC64(context_, os_name_, arch_name_);
    }

    case kArchSparc32_SLEIGH: {
      DLOG(INFO) << "Using architecture: 32-bit SPARC32_Sleigh";
      return GetSPARC32Sleigh(context_, os_name_, arch_name_);
    }

    case kArchPPC: {
      DLOG(INFO) << "Using architecture: PowerPC";
      return GetSleighPPC(context_, os_name_, arch_name_);
    }

    case kArchMIPS: {
      DLOG(INFO) << "Using architecture: MIPS";
      return GetSleighMIPS(context_, os_name_, arch_name_);
    }
    default: {
      return nullptr;
    }
  }
}

auto Arch::Build(llvm::LLVMContext *context_, OSName os_name_,
                 ArchName arch_name_) -> ArchPtr {
  ArchPtr ret = Arch::GetArchByName(context_, os_name_, arch_name_);
  if (ret) {
    ret->PopulateRegisterTable();
  }

  return ret;
}

auto Arch::Get(llvm::LLVMContext &context, std::string_view os,
               std::string_view arch_name) -> ArchPtr {
  return Arch::Build(&context, GetOSName(os), GetArchName(arch_name));
}

auto Arch::Get(llvm::LLVMContext &context, OSName os, ArchName arch_name)
    -> ArchPtr {
  return Arch::Build(&context, os, arch_name);
}

auto Arch::GetHostArch(llvm::LLVMContext &ctx) -> ArchPtr {
  return Arch::Build(&ctx, GetOSName(REMILL_OS), GetArchName(REMILL_ARCH));
}

// Return the type of the state structure.
llvm::StructType *ArchBase::StateStructType(void) const {
  CHECK_NOTNULL(state_type);
  return state_type;
}

// Pointer to a state structure type.
llvm::PointerType *ArchBase::StatePointerType(void) const {
  CHECK(this->state_type)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return llvm::PointerType::get(*context, 0);
}

// Return the type of an address, i.e. `addr_t` in the semantics.
llvm::IntegerType *Arch::AddressType(void) const {
  return llvm::IntegerType::get(*context, address_size);
}

// The type of memory.
llvm::PointerType *ArchBase::MemoryPointerType(void) const {
  CHECK_NOTNULL(memory_type);
  return memory_type;
}

// Return the type of a lifted function.
llvm::FunctionType *ArchBase::LiftedFunctionType(void) const {
  CHECK_NOTNULL(lifted_function_type);
  return lifted_function_type;
}

llvm::StructType *ArchBase::RegisterWindowType(void) const {
  CHECK(this->register_window_type)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return this->register_window_type;
}

unsigned ArchBase::RegMdID(void) const {
  return this->reg_md_id;
}

// Return information about the register at offset `offset` in the `State`
// structure.
const Register *ArchBase::RegisterAtStateOffset(uint64_t offset) const {
  if (offset >= reg_by_offset.size()) {
    return nullptr;
  } else {
    return reg_by_offset[offset];  // May be `nullptr`.
  }
}

// Apply `cb` to every register.
void ArchBase::ForEachRegister(std::function<void(const Register *)> cb) const {
  for (const auto &reg : registers) {
    cb(reg.get());
  }
}

// Return information about a register, given its name.
const Register *ArchBase::RegisterByName(std::string_view name_) const {
  std::string name(name_.data(), name_.size());

  auto [curr_val_it, added] = reg_by_name.emplace(std::move(name), nullptr);
  if (added) {
    return nullptr;
  }
  return curr_val_it->second;
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

}  // namespace

remill::Arch::ArchPtr Arch::GetModuleArch(const llvm::Module &module) {
  const llvm::Triple triple = llvm::Triple(module.getTargetTriple());
  return remill::Arch::Build(&module.getContext(), GetOSName(triple),
                             GetArchName(triple));
}

bool Arch::IsX86(void) const {
  switch (arch_name) {
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
    case remill::kArchX86_SLEIGH: return true;
    default: return false;
  }
}

bool Arch::IsAMD64(void) const {
  switch (arch_name) {
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
    case remill::kArchAMD64_SLEIGH: return true;
    default: return false;
  }
}

bool Arch::IsAArch32(void) const {
  return remill::kArchAArch32LittleEndian == arch_name;
}

bool Arch::IsAArch64(void) const {
  return remill::kArchAArch64LittleEndian == arch_name;
}

bool Arch::IsSPARC32(void) const {
  return remill::kArchSparc32 == arch_name;
}

bool Arch::IsSPARC64(void) const {
  return remill::kArchSparc64 == arch_name;
}

bool Arch::IsPPC(void) const {
  return remill::kArchPPC == arch_name;
}

bool Arch::IsMIPS(void) const {
  return remill::kArchMIPS == arch_name;
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

// These variables must always be defined within any lifted function.
static bool BlockHasSpecialVars(llvm::Function *basic_block) {
  return FindVarInFunction(basic_block, kStateVariableName, true).first &&
         FindVarInFunction(basic_block, kMemoryVariableName, true).first &&
         FindVarInFunction(basic_block, kPCVariableName, true).first &&
         FindVarInFunction(basic_block, kNextPCVariableName, true).first &&
         FindVarInFunction(basic_block, kBranchTakenVariableName, true).first;
}

// Add attributes to llvm::Argument in a way portable across LLVMs
static void AddNoAliasToArgument(llvm::Argument *arg) {
  arg->addAttr(llvm::Attribute::NoAlias);
}

}  // namespace

Register::Register(const std::string &name_, uint64_t offset_,
                   llvm::Type *type_, const Register *parent_,
                   const Arch *arch_)
    : name(name_),
      offset(offset_),
      size(arch_->DataLayout().getTypeAllocSize(type_)),
      type(type_),
      constant_name(
          llvm::ConstantDataArray::getString(type->getContext(), name_)),
      parent(parent_),
      arch(arch_) {

  if (parent) {
    parent->children.push_back(this);
  }
}

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

// Compute the total offset of a GEP chain.
static uint64_t TotalOffset(const llvm::DataLayout &dl, llvm::Value *base,
                            llvm::StructType *state_type) {
  uint64_t total_offset = 0;
  const auto state_size = dl.getTypeAllocSize(state_type);
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

    } else if (base->getType()->isPointerTy()) {
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
                llvm::StructType *state_type, size_t state_size,
                const Register *reg, unsigned addr_space, llvm::Value *gep) {


  auto gep_offset = TotalOffset(dl, gep, state_type);

  CHECK_LT(gep_offset, state_size);

  const auto index_type = reg->gep_index_list[0]->getType();
  const auto goal_ptr_type =
      llvm::PointerType::get(ir.getContext(), addr_space);

  // Best case: we've found a value field in the structure that
  // is located at the correct byte offset.
  if (gep_offset == reg->offset) {
    if (auto const_gep = llvm::dyn_cast<llvm::Constant>(gep); const_gep) {
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
        const_gep, llvm::PointerType::get(ir.getContext(), addr_space));
    const_gep = llvm::ConstantExpr::getGetElementPtr(byte_type, const_gep,
                                                     elem_indexes);
    return llvm::ConstantExpr::getBitCast(const_gep, goal_ptr_type);

  } else {
    gep = ir.CreateBitCast(gep,
                           llvm::PointerType::get(ir.getContext(), addr_space));
    gep = ir.CreateGEP(byte_type, gep, elem_indexes);
    return ir.CreateBitCast(gep, goal_ptr_type);
  }
}

}  // namespace

void Register::ComputeGEPAccessors(const llvm::DataLayout &dl,
                                   llvm::StructType *state_type) {
  if (!state_type) {
    state_type = arch->StateStructType();
  }

  if (gep_type_at_offset || !state_type) {
    return;
  }

  auto &context = state_type->getContext();

  gep_index_list.push_back(
      llvm::Constant::getNullValue(llvm::Type::getInt32Ty(context)));

  std::tie(gep_offset, gep_type_at_offset) =
      BuildIndexes(dl, state_type, 0, offset, gep_index_list);
}

// Generate a GEP that will let us load/store to this register, given
// a `State *`.
llvm::Value *Register::AddressOf(llvm::Value *state_ptr,
                                 llvm::BasicBlock *add_to_end) const {
  llvm::IRBuilder<> ir(add_to_end);
  return AddressOf(state_ptr, ir);
}

llvm::Value *Register::AddressOf(llvm::Value *state_ptr,
                                 llvm::IRBuilder<> &ir) const {
  auto &context = type->getContext();
  CHECK_EQ(&context, &(state_ptr->getContext()));
  const auto state_ptr_type =
      llvm::dyn_cast<llvm::PointerType>(state_ptr->getType());
  CHECK_NOTNULL(state_ptr_type);
  const auto addr_space = state_ptr_type->getAddressSpace();

  const auto state_type = arch->StateStructType();

  const auto module = ir.GetInsertBlock()->getParent()->getParent();
  const auto &dl = module->getDataLayout();

  if (!gep_type_at_offset) {
    const_cast<Register *>(this)->ComputeGEPAccessors(dl, state_type);
  }

  llvm::Value *gep = nullptr;
  if (auto const_state_ptr = llvm::dyn_cast<llvm::Constant>(state_ptr);
      const_state_ptr) {
    gep = llvm::ConstantExpr::getInBoundsGetElementPtr(
        state_type, const_state_ptr, gep_index_list);
  } else {
    gep = ir.CreateInBoundsGEP(state_type, state_ptr, gep_index_list);
  }

  auto state_size = dl.getTypeAllocSize(state_type);
  auto ret =
      FinishAddressOf(ir, dl, state_type, state_size, this, addr_space, gep);

  // Add the metadata to `inst`.
  if (auto inst = llvm::dyn_cast<llvm::Instruction>(ret); inst) {
    auto reg_name_md = llvm::ValueAsMetadata::get(constant_name);
    auto reg_name_node = llvm::MDNode::get(context, reg_name_md);
    inst->setMetadata(arch->RegMdID(), reg_name_node);
    inst->setName(name);
  }

  return ret;
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

  target_attribs = target_attribs.addAttribute(context, "target-features");
  target_attribs = target_attribs.addAttribute(context, "target-cpu");

  for (llvm::Function &func : *mod) {
    auto attribs = func.getAttributes();
    attribs = attribs.removeFnAttributes(context,
                                         llvm::AttributeMask(target_attribs));
    func.setAttributes(attribs);
  }
}

// Create a lifted function declaration with name `name` inside of `module`.
//
// NOTE(pag): This should be called after `PrepareModule` and after the
//            semantics have been loaded.
llvm::Function *Arch::DeclareLiftedFunction(std::string_view name_,
                                            llvm::Module *module) const {
  auto &context = module->getContext();
  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      RecontextualizeType(LiftedFunctionType(), context));
  llvm::StringRef name(name_.data(), name_.size());
  auto func = module->getFunction(name.str());
  
  if (!func || func->getFunctionType() != func_type) {
    func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, 0u, name, module);
  } else if (func->isDeclaration()) {
    func->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
  }

  auto memory = remill::NthArgument(func, kMemoryPointerArgNum);
  auto state = remill::NthArgument(func, kStatePointerArgNum);
  auto pc = remill::NthArgument(func, kPCArgNum);
  memory->setName("memory");
  state->setName("state");
  pc->setName("program_counter");

  AddNoAliasToArgument(state);
  AddNoAliasToArgument(memory);

  return func;
}

// Create a lifted function with name `name` inside of `module`.
//
// NOTE(pag): This should be called after `PrepareModule` and after the
//            semantics have been loaded.
llvm::Function *Arch::DefineLiftedFunction(std::string_view name_,
                                           llvm::Module *module) const {
  auto func = DeclareLiftedFunction(name_, module);
  InitializeEmptyLiftedFunction(func);
  InitFunctionAttributes(func);
  return func;
}

// Initialize an empty lifted function with the default variables that it
// should contain.
void Arch::InitializeEmptyLiftedFunction(llvm::Function *func) const {
  CHECK(func->isDeclaration());
  auto module = func->getParent();
  auto &context = module->getContext();
  auto block = llvm::BasicBlock::Create(context, "", func);
  auto u8 = llvm::Type::getInt8Ty(context);
  auto addr = llvm::Type::getIntNTy(context, address_size);
  auto memory = remill::NthArgument(func, kMemoryPointerArgNum);
  auto state = remill::NthArgument(func, kStatePointerArgNum);

  llvm::IRBuilder<> ir(block);
  ir.CreateAlloca(u8, nullptr, "BRANCH_TAKEN");
  ir.CreateAlloca(addr, nullptr, "RETURN_PC");
  ir.CreateAlloca(addr, nullptr, "MONITOR");

  // NOTE(pag): `PC` and `NEXT_PC` are handled by
  //            `FinishLiftedFunctionInitialization`.

  ir.CreateStore(state, ir.CreateAlloca(state->getType(), nullptr, "STATE"));
  ir.CreateStore(memory, ir.CreateAlloca(memory->getType(), nullptr, "MEMORY"));

  FinishLiftedFunctionInitialization(module, func);
  CHECK(BlockHasSpecialVars(func));
}

void Arch::PrepareModule(llvm::Module *mod) const {
  PrepareModuleDataLayout(mod);
}

const Register *ArchBase::AddRegister(const char *reg_name_,
                                      llvm::Type *val_type, size_t offset,
                                      const char *parent_reg_name) const {

  CHECK_NOTNULL(val_type);

  const std::string reg_name(reg_name_);
  if (auto reg = reg_by_name.find(reg_name); reg != reg_by_name.end()) {
    return reg->second;
  }

  const auto dl = this->DataLayout();

  // If this is a sub-register, then link it in.
  const Register *parent_reg = nullptr;
  if (parent_reg_name) {
    parent_reg = reg_by_name[parent_reg_name];
  }

  DLOG(INFO) << "Adding register " << reg_name << " with type " << val_type;

  auto reg_impl = new Register(reg_name, offset, val_type, parent_reg, this);

  //reg_impl->ComputeGEPAccessors(dl, this->state_type);


  reg_by_name.emplace(reg_name, reg_impl);
  registers.emplace_back(reg_impl);

  auto maybe_get_reg_name = [](auto reg_ptr) -> std::string {
    if (!reg_ptr) {
      return "(nullptr)";
    }
    return reg_ptr->name;
  };

  auto needed_size = reg_impl->offset + reg_impl->size;
  if (needed_size >= reg_by_offset.size()) {
    reg_by_offset.resize(needed_size);
  }

  // Provide easy access to registers at specific offsets in the `State`
  // structure.
  for (auto i = reg_impl->offset; i < needed_size; ++i) {
    auto &reg_at_offset = reg_by_offset[i];
    if (!reg_at_offset) {
      reg_at_offset = reg_impl;
    } else if (reg_at_offset) {
      CHECK_EQ(reg_at_offset->EnclosingRegister(),
               reg_impl->EnclosingRegister())
          << maybe_get_reg_name(reg_at_offset->EnclosingRegister())
          << " != " << maybe_get_reg_name(reg_impl->EnclosingRegister());
      ;
      reg_at_offset = reg_impl;
    }
  }

  return reg_impl;
}

// Get all of the register information from the prepared module.
void ArchBase::InitFromSemanticsModule(llvm::Module *module) const {
  if (state_type) {
    return;
  }

  const auto &dl = module->getDataLayout();
  const auto basic_block = module->getFunction("__remill_jump");
  CHECK_NOTNULL(basic_block);

  const auto *state_global = module->getGlobalVariable("__remill_state");
  CHECK_NOTNULL(state_global);
  auto *state_type =
      llvm::dyn_cast<llvm::StructType>(state_global->getValueType());
  CHECK_NOTNULL(state_type);

  const auto *register_window_global =
      module->getGlobalVariable("__remill_register_window");
  if (register_window_global) {
    auto *register_window_type = llvm::dyn_cast<llvm::StructType>(
        register_window_global->getValueType());
    CHECK_NOTNULL(register_window_type);
    this->register_window_type = register_window_type;
  }

  // TODO(pag): Eventually we need a reliable way to get this that will work
  //            in the presence of opaque pointers.
  this->state_type = state_type;

  reg_by_offset.resize(dl.getTypeAllocSize(state_type));
  memory_type = llvm::dyn_cast<llvm::PointerType>(
      NthArgument(basic_block, kMemoryPointerArgNum)->getType());
  lifted_function_type = basic_block->getFunctionType();
  reg_md_id = context->getMDKindID("remill_register");

  CHECK(!reg_by_name.empty());

  this->instrinsics.reset(new IntrinsicTable(module));
}

const IntrinsicTable *ArchBase::GetInstrinsicTable(void) const {
  return this->instrinsics.get();
}


DecodingContext DefaultContextAndLifter::CreateInitialContext(void) const {
  return DecodingContext();
}


Instruction::FallthroughFlow DefaultContextAndLifter::GetFallthrough() const {
  return Instruction::FallthroughFlow(this->CreateInitialContext());
}

Instruction::DirectFlow
DefaultContextAndLifter::GetDirectFlow(uint64_t target) const {
  return Instruction::DirectFlow(target, this->CreateInitialContext());
}

Instruction::IndirectFlow DefaultContextAndLifter::GetIndirectFlow() const {
  return Instruction::IndirectFlow(this->CreateInitialContext());
}

Instruction::InstructionFlowCategory
DefaultContextAndLifter::FillInFlowFromCategoryAndDefaultContext(
    const remill::Instruction &inst) const {
  switch (inst.category) {
    case Instruction::Category::kCategoryNormal:
      return Instruction::NormalInsn(this->GetFallthrough());
    case Instruction::Category::kCategoryAsyncHyperCall:
      return Instruction::AsyncHyperCall();
    case Instruction::Category::kCategoryConditionalAsyncHyperCall:
      return Instruction::ConditionalInstruction(Instruction::AsyncHyperCall(),
                                                 this->GetFallthrough());
    case Instruction::Category::kCategoryConditionalBranch:
      return Instruction::ConditionalInstruction(
          Instruction::DirectJump(this->GetDirectFlow(inst.branch_taken_pc)),
          this->GetFallthrough());
    case Instruction::Category::kCategoryDirectJump:
      return Instruction::DirectJump(this->GetDirectFlow(inst.branch_taken_pc));
    case Instruction::Category::kCategoryIndirectJump:
      return Instruction::IndirectJump(this->GetIndirectFlow());
    case Instruction::Category::kCategoryConditionalIndirectJump:
      return Instruction::ConditionalInstruction(
          Instruction::IndirectJump(this->GetIndirectFlow()),
          this->GetFallthrough());
    case Instruction::Category::kCategoryError: return Instruction::ErrorInsn();
    case Instruction::Category::kCategoryFunctionReturn:
      return Instruction::FunctionReturn(this->GetIndirectFlow());
    case Instruction::Category::kCategoryConditionalFunctionReturn:
      return Instruction::ConditionalInstruction(
          Instruction::FunctionReturn(this->GetIndirectFlow()),
          this->GetFallthrough());
    case Instruction::Category::kCategoryConditionalDirectFunctionCall:
      return Instruction::ConditionalInstruction(
          Instruction::DirectFunctionCall(
              this->GetDirectFlow(inst.branch_taken_pc)),
          this->GetFallthrough());
    case Instruction::Category::kCategoryDirectFunctionCall:
      return Instruction::DirectFunctionCall(
          this->GetDirectFlow(inst.branch_taken_pc));
    case Instruction::Category::kCategoryIndirectFunctionCall:
      return Instruction::IndirectFunctionCall(this->GetIndirectFlow());
    case Instruction::Category::kCategoryConditionalIndirectFunctionCall:
      return Instruction::ConditionalInstruction(
          Instruction::IndirectFunctionCall(this->GetIndirectFlow()),
          this->GetFallthrough());
    case Instruction::Category::kCategoryInvalid:
      return Instruction::InvalidInsn();
    case Instruction::Category::kCategoryNoOp:
      return Instruction::NoOp(this->GetFallthrough());
  }
}

bool DefaultContextAndLifter::DecodeInstruction(uint64_t address,
                                                std::string_view instr_bytes,
                                                Instruction &inst,
                                                DecodingContext context) const {
  inst.SetLifter(std::make_unique<remill::InstructionLifter>(
      this, this->GetInstrinsicTable()));

  auto res = this->ArchDecodeInstruction(address, instr_bytes, inst);
  if (res) {
    inst.flows = this->FillInFlowFromCategoryAndDefaultContext(inst);
  }

  return res;
}


OperandLifter::OpLifterPtr DefaultContextAndLifter::DefaultLifter(
    const remill::IntrinsicTable &intrinsics) const {
  return std::make_shared<InstructionLifter>(this, intrinsics);
}


DefaultContextAndLifter::DefaultContextAndLifter(llvm::LLVMContext *context_,
                                                 OSName os_name_,
                                                 ArchName arch_name_)
    : ArchBase(context_, os_name_, arch_name_) {}


}  // namespace remill
