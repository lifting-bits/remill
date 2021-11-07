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

#include "Arch.h"  // For `Arch` and `ArchImpl`.

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
              "`_avx` or `_avx512` appended), aarch64, aarch32");

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
    case kArchAArch32LittleEndian:
    case kArchSparc32: return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchAArch64LittleEndian:
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
  ArchPtr ret;
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchAArch64LittleEndian: {
      DLOG(INFO) << "Using architecture: AArch64, feature set: Little Endian";
      ret = GetAArch64(context_, os_name_, arch_name_);
      break;
    }

    case kArchAArch32LittleEndian: {
      DLOG(INFO) << "Using architecture: AArch32, feature set: Little Endian";
      ret = GetAArch32(context_, os_name_, arch_name_);
      break;
    }

    case kArchX86: {
      DLOG(INFO) << "Using architecture: X86";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchX86_AVX: {
      DLOG(INFO) << "Using architecture: X86, feature set: AVX";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchX86_AVX512: {
      DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchAMD64: {
      DLOG(INFO) << "Using architecture: AMD64";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchAMD64_AVX: {
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchAMD64_AVX512: {
      DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
      ret = GetSleighX86(context_, os_name_, arch_name_);
      break;
    }

    case kArchSparc32: {
      DLOG(INFO) << "Using architecture: 32-bit SPARC";
      ret = GetSPARC(context_, os_name_, arch_name_);
      break;
    }

    case kArchSparc64: {
      DLOG(INFO) << "Using architecture: 64-bit SPARC";
      ret = GetSPARC64(context_, os_name_, arch_name_);
      break;
    }
  }

  if (ret) {
    ret->impl.reset(new ArchImpl);
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
llvm::StructType *Arch::StateStructType(void) const {
  CHECK(impl)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return impl->state_type;
}

// Pointer to a state structure type.
llvm::PointerType *Arch::StatePointerType(void) const {
  CHECK(impl)
      << "Have you not run `PrepareModule` on a loaded semantics module?";
  return llvm::PointerType::get(impl->state_type, 0);
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
    cb(reg.get());
  }
}

// Return information about a register, given its name.
const Register *Arch::RegisterByName(std::string_view name_) const {
  std::string name(name_.data(), name_.size());
  auto [curr_val_it, added] =
      impl->reg_by_name.emplace(std::move(name), nullptr);
  if (added) {
    return nullptr;
  } else {
    return curr_val_it->second;
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
  return FindVarInFunction(basic_block, kStateVariableName, true) &&
         FindVarInFunction(basic_block, kMemoryVariableName, true) &&
         FindVarInFunction(basic_block, kPCVariableName, true) &&
         FindVarInFunction(basic_block, kNextPCVariableName, true) &&
         FindVarInFunction(basic_block, kBranchTakenVariableName, true);
}

// Add attributes to llvm::Argument in a way portable across LLVMs
static void AddNoAliasToArgument(llvm::Argument *arg) {
  IF_LLVM_LT_390(arg->addAttr(llvm::AttributeSet::get(
      arg->getContext(), arg->getArgNo() + 1, llvm::Attribute::NoAlias)););

  IF_LLVM_GTE_390(arg->addAttr(llvm::Attribute::NoAlias););
}

}  // namespace

Register::Register(const std::string &name_, uint64_t offset_, uint64_t size_,
                   llvm::Type *type_, const Register *parent_,
                   const ArchImpl *arch_)
    : name(name_),
      offset(offset_),
      size(size_),
      type(type_),
      constant_name(
          llvm::ConstantDataArray::getString(type->getContext(), name_)),
      parent(parent_),
      arch(arch_) {}

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
                const Register *reg, unsigned addr_space,
                llvm::Value *gep) {


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

void Register::CompteGEPAccessors(const llvm::DataLayout &dl,
                                  llvm::Type *state_type) {
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

  const auto state_type =
      llvm::dyn_cast<llvm::StructType>(state_ptr_type->getPointerElementType());
  CHECK_NOTNULL(state_type);

  const auto module = ir.GetInsertBlock()->getParent()->getParent();
  const auto &dl = module->getDataLayout();

  if (!gep_type_at_offset) {
    const_cast<Register *>(this)->CompteGEPAccessors(dl, state_type);
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
  auto ret = FinishAddressOf(
      ir, dl, state_ptr_type, state_size, this, addr_space, gep);

  // Add the metadata to `inst`.
  if (auto inst = llvm::dyn_cast<llvm::Instruction>(ret); inst) {
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
    auto reg_name_md = llvm::ValueAsMetadata::get(constant_name);
    auto reg_name_node = llvm::MDNode::get(context, reg_name_md);
#else
    auto reg_name_node = llvm::MDNode::get(context, reg->constant_name);
#endif
    inst->setMetadata(arch->reg_md_id, reg_name_node);
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
  auto func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, 0u, name, module);

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

  ir.CreateStore(state,
                 ir.CreateAlloca(llvm::PointerType::get(impl->state_type, 0),
                                 nullptr, "STATE"));
  ir.CreateStore(memory,
                 ir.CreateAlloca(impl->memory_type, nullptr, "MEMORY"));

  FinishLiftedFunctionInitialization(module, func);
  CHECK(BlockHasSpecialVars(func));
}

void Arch::PrepareModule(llvm::Module *mod) const {
  PrepareModuleDataLayout(mod);
}

const Register *Arch::AddRegister(const char *reg_name_, llvm::Type *val_type,
                                  size_t offset,
                                  const char *parent_reg_name) const {
  CHECK_NOTNULL(val_type);

  const std::string reg_name(reg_name_);
  auto &reg = impl->reg_by_name[reg_name];
  if (reg) {
    return reg;
  }

  const auto dl = this->DataLayout();

  // If this is a sub-register, then link it in.
  const Register *parent_reg = nullptr;
  if (parent_reg_name) {
    parent_reg = impl->reg_by_name[parent_reg_name];
  }

  auto reg_impl = new Register(reg_name, offset, dl.getTypeAllocSize(val_type),
                               val_type, parent_reg, impl.get());

  reg_impl->CompteGEPAccessors(dl, impl->state_type);

  reg = reg_impl;
  impl->registers.emplace_back(reg_impl);

  if (parent_reg) {
    const_cast<Register *>(reg->parent)->children.push_back(reg);
  }

  auto maybe_get_reg_name = [](auto reg_ptr) -> std::string {
    if (!reg_ptr) {
      return "(nullptr)";
    }
    return reg_ptr->name;
  };

  // Provide easy access to registers at specific offsets in the `State`
  // structure.
  for (auto i = reg->offset; i < (reg->offset + reg->size); ++i) {
    auto &reg_at_offset = impl->reg_by_offset[i];
    if (!reg_at_offset) {
      reg_at_offset = reg;
    } else if (reg_at_offset) {
      CHECK_EQ(reg_at_offset->EnclosingRegister(), reg->EnclosingRegister())
        << maybe_get_reg_name(reg_at_offset->EnclosingRegister()) << " != "
        << maybe_get_reg_name(reg->EnclosingRegister());;
      reg_at_offset = reg;
    }
  }

  return reg;
}

// Get all of the register information from the prepared module.
void Arch::InitFromSemanticsModule(llvm::Module *module) const {
  if (!impl) {
    impl.reset(new ArchImpl);
  }

  if (impl->state_type) {
    return;
  }

  const auto &dl = module->getDataLayout();
  const auto basic_block = module->getFunction("__remill_jump");
  CHECK_NOTNULL(basic_block);
  const auto state_ptr_type =
      NthArgument(basic_block, kStatePointerArgNum)->getType();
  const auto state_type =
      llvm::dyn_cast<llvm::StructType>(state_ptr_type->getPointerElementType());

  impl->state_type = state_type;
  impl->reg_by_offset.resize(dl.getTypeAllocSize(state_type));
  impl->memory_type = llvm::dyn_cast<llvm::PointerType>(
      NthArgument(basic_block, kMemoryPointerArgNum)->getType());
  impl->lifted_function_type = basic_block->getFunctionType();
  impl->reg_md_id = context->getMDKindID("remill_register");

  CHECK(!impl->reg_by_name.empty());
}

}  // namespace remill
