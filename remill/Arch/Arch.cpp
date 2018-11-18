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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <memory>
#include <unordered_map>

#include <llvm/ADT/APInt.h>
#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include "remill/Arch/Arch.h"
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
              "`_avx` or `_avx512` appended), aarch64, "
              "mips32, mips64");

DECLARE_string(os);

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
    case kArchMips32:
      return 32;
    case kArchAMD64:
    case kArchAMD64_AVX:
    case kArchAMD64_AVX512:
    case kArchMips64:
    case kArchAArch64LittleEndian:
      return 64;
  }
  return 0;
}

// Used for static storage duration caches of `Arch` specializations. The
// `std::unique_ptr` makes sure that the `Arch` objects are freed on `exit`
// from the program.
using ArchPtr = std::unique_ptr<const Arch>;
using ArchCache = std::unordered_map<uint32_t, ArchPtr>;

}  // namespace

Arch::Arch(OSName os_name_, ArchName arch_name_)
    : os_name(os_name_),
      arch_name(arch_name_),
      address_size(AddressSize(arch_name_)) {}

Arch::~Arch(void) {}

bool Arch::LazyDecodeInstruction(
    uint64_t address, const std::string &instr_bytes,
    Instruction &inst) const {
  return DecodeInstruction(address, instr_bytes, inst);
}

llvm::Triple Arch::BasicTriple(void) const {
  llvm::Triple triple;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot get triple OS.";
      break;

    case kOSLinux:
    case kOSVxWorks:
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
  }
  return triple;
}

const Arch *Arch::Get(OSName os_name_, ArchName arch_name_) {
  switch (arch_name_) {
    case kArchInvalid:
      LOG(FATAL) << "Unrecognized architecture.";
      return nullptr;

    case kArchAArch64LittleEndian: {
      static ArchCache gArchAArch64LE;
      auto &arch = gArchAArch64LE[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AArch64, feature set: Little Endian";
        arch = ArchPtr(GetAArch64(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86: {
      static ArchCache gArchX86;
      auto &arch = gArchX86[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchMips32: {
      static ArchCache gArchMips;
      auto &arch = gArchMips[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: 32-bit MIPS";
        arch = ArchPtr(GetMips(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchMips64: {
      static ArchCache gArchMips64;
      auto &arch = gArchMips64[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: 64-bit MIPS";
        arch = ArchPtr(GetMips(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86_AVX: {
      static ArchCache gArchX86_AVX;
      auto &arch = gArchX86_AVX[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86, feature set: AVX";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchX86_AVX512: {
      static ArchCache gArchX86_AVX512;
      auto &arch = gArchX86_AVX512[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: X86, feature set: AVX512";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64: {
      static ArchCache gArchAMD64;
      auto &arch = gArchAMD64[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64_AVX: {
      static ArchCache gArchAMD64_AVX;
      auto &arch = gArchAMD64_AVX[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64, feature set: AVX";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }

    case kArchAMD64_AVX512: {
      static ArchCache gArchAMD64_AVX512;
      auto &arch = gArchAMD64_AVX512[os_name_];
      if (!arch) {
        DLOG(INFO) << "Using architecture: AMD64, feature set: AVX512";
        arch = ArchPtr(GetX86(os_name_, arch_name_));
      }
      return arch.get();
    }
  }
  return nullptr;
}

// Return information about the register at offset `offset` in the `State`
// structure.
const Register *Arch::RegisterAtStateOffset(uint64_t offset) const {
  if (offset >= reg_by_offset.size()) {
    return nullptr;
  } else {
    return reg_by_offset[offset];  // May be `nullptr`.
  }
}

// Return information about a register, given its name.
const Register *Arch::RegisterByName(const std::string &name) const {
  auto reg_it = reg_by_name.find(name);
  if (reg_it == reg_by_name.end()) {
    return nullptr;
  } else {
    return reg_it->second;
  }
}

const Arch *Arch::GetMips(OSName, ArchName) {
  return nullptr;
}

const Arch *GetHostArch(void) {
  static const Arch *gHostArch = nullptr;
  if (!gHostArch) {
    gHostArch = Arch::Get(GetOSName(REMILL_OS), GetArchName(REMILL_ARCH));
  }
  return gHostArch;
}

const Arch *GetTargetArch(void) {
  static const Arch *gTargetArch = nullptr;
  if (!gTargetArch) {
    gTargetArch = Arch::Get(GetOSName(FLAGS_os), GetArchName(FLAGS_arch));
  }
  return gTargetArch;
}

bool Arch::IsX86(void) const {
  switch (arch_name) {
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      return true;
    default:
      return false;
  }
}

bool Arch::IsAMD64(void) const {
  switch (arch_name) {
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      return true;
    default:
      return false;
  }
}

bool Arch::IsAArch64(void) const {
  return remill::kArchAArch64LittleEndian == arch_name;
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
  llvm::DataLayout dl(module);
  *offset = 0;
  do {
    if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(reg)) {
      llvm::APInt gep_offset(dl.getPointerSizeInBits(0), 0);
      if (!gep->accumulateConstantOffset(dl, gep_offset)) {
        DLOG(INFO)
            << "Named variable " << val_name << " is not a register in the "
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
      DLOG(INFO)
          << "Named variable " << val_name << " is not a register in the "
          << "state structure";
      return false;
    }
  } while (reg);

  DLOG(INFO)
      << "Offset of register " << val_name << " in state structure is "
      << *offset;

  return true;
}

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` intrinsic with the same names as we find in the
// C++ definition of that function. However, we compile that function with
// debug information, and so we will try to recover the variables names for
// later lookup.
static void FixupBasicBlockVariables(llvm::Function *basic_block) {
  std::vector<llvm::StoreInst *> stores;
  std::vector<llvm::Instruction *> remove_insts;

  std::unordered_map<llvm::AllocaInst *, llvm::Value *> stored_val;

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
        if (auto decl_inst = llvm::dyn_cast<llvm::DbgDeclareInst>(debug_inst)) {
          auto addr = decl_inst->getAddress();
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 7)
          addr->setName(decl_inst->getVariable()->getName());
#else
          llvm::DIVariable var(decl_inst->getVariable());
          addr->setName(var.getName());
#endif
        }
        remove_insts.push_back(debug_inst);

      // Get stores.
      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
        auto dst_alloca = llvm::dyn_cast<llvm::AllocaInst>(
            store_inst->getPointerOperand());
        if (dst_alloca) {
          stored_val[dst_alloca] = store_inst->getValueOperand();
        }
        stores.push_back(store_inst);

      // Forward stores to loads.
      } else if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
        auto src_alloca = llvm::dyn_cast<llvm::AllocaInst>(
            load_inst->getPointerOperand());
        if (src_alloca) {
          if (auto val = stored_val[src_alloca]) {
            load_inst->replaceAllUsesWith(val);
            remove_insts.push_back(load_inst);
          }
        }
      } else if (llvm::isa<llvm::BranchInst>(&inst) ||
                 llvm::isa<llvm::CallInst>(&inst) ||
                 llvm::isa<llvm::InvokeInst>(&inst)) {
        LOG(FATAL)
            << "Unsupported instruction in __remill_basic_block: "
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

    if (val && ptr && val->getType()->isPointerTy() && ptr->hasName()) {
      auto name = ptr->getName().str();
      ptr->setName("");
      val->setName(name);
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

  CHECK(BlockHasSpecialVars(basic_block))
      << "Unable to locate required variables in `__remill_basic_block`.";
}

// Add attributes to llvm::Argument in a way portable across LLVMs
static void AddNoAliasToArgument(llvm::Argument *arg) {
  IF_LLVM_LT_39(
    arg->addAttr(
      llvm::AttributeSet::get(
        arg->getContext(),
        arg->getArgNo() + 1,
        llvm::Attribute::NoAlias)
    ); 
  );

  IF_LLVM_GTE_39(
    arg->addAttr(llvm::Attribute::NoAlias);
  );
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
    return lhs.order < rhs.order;
  }
}

}  // namespace

Register::Register(const std::string &name_, uint64_t offset_, uint64_t size_,
                   uint64_t order_, llvm::Type *type_)
    : name(name_),
      offset(offset_),
      size(size_),
      order(order_),
      type(type_),
      parent(nullptr) {}

// Returns the enclosing register of size AT LEAST `size`, or `nullptr`.
const Register *Register::EnclosingRegisterOfSize(uint64_t size_) const {
  auto enclosing = this;
  for (; enclosing && enclosing->size < size_; enclosing = enclosing->parent) {
    /* Empty. */;
  }
  return enclosing;
}

const Register *Register::EnclosingRegister(void) const {
  auto enclosing = this;
  while (enclosing->parent) {
    enclosing = enclosing->parent;
  }
  return enclosing;
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
      IF_LLVM_LT_50_(llvm::AttributeSet::FunctionIndex)
      "target-features");
  target_attribs = target_attribs.addAttribute(
      context,
      IF_LLVM_LT_50_(llvm::AttributeSet::FunctionIndex)
      "target-cpu");

  for (llvm::Function &func : *mod) {
    auto attribs = func.getAttributes();
    attribs = attribs.removeAttributes(
        context,
        llvm::AttributeLoc::FunctionIndex,
        target_attribs);
    func.setAttributes(attribs);
  }
}

void Arch::PrepareModule(llvm::Module *mod) const {
  PrepareModuleRemillFunctions(mod);
  PrepareModuleDataLayout(mod);
  if (registers.empty()) {
    CollectRegisters(mod);
  }
}

// Get all of the register information from the prepared module.
void Arch::CollectRegisters(llvm::Module *module) const {
  llvm::DataLayout dl(module);
  auto basic_block = BasicBlockFunction(module);
  auto state_ptr_type = StatePointerType(module);
  std::vector<llvm::Instruction *> named_insts;
  uint64_t order = 0;

  // Collect all registers.
  for (auto &block : *basic_block) {
    for (auto &inst : block) {
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
      auto name = inst.getName().str();
      registers.emplace_back(
          name, offset, dl.getTypeAllocSize(reg_type), order++, reg_type);
    }
  }

  // Sort them in such a way that we can recover the parentage of registers.
  std::sort(registers.begin(), registers.end(), RegisterComparator);

  auto num_bytes = dl.getTypeAllocSize(state_ptr_type->getElementType());
  reg_by_offset.resize(num_bytes);

  // Figure out parentage of registers, and fill in the various maps.
  for (auto &reg : registers) {
    reg_by_name[reg.name] = &reg;

    for (uint64_t i = 0; i < reg.size; ++i) {
      auto &reg_at_offset = reg_by_offset[reg.offset + i];
      if (!reg.parent) {
        reg.parent = reg_at_offset;
      } else if (!reg_at_offset) {
        LOG(FATAL)
            << "Register " << reg.name << " is not fully enclosed by parent "
            << reg.parent->name;
      } else if (reg.parent != reg_at_offset) {
        LOG(FATAL)
            << "Can't set parent of register " << reg.name
            << " to " << reg_at_offset->name << " because it already has "
            << reg.parent->name << " as its parent";
      }
      reg_at_offset = &reg;
    }
  }
}

}  // namespace remill
