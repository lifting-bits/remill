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

#include <memory>
#include <unordered_map>

#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "remill/BC/ABI.h"
#include "remill/BC/Compat/Attributes.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

#include "remill/OS/OS.h"

DEFINE_string(arch, "",
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

llvm::Triple Arch::BasicTriple(void) const {
  llvm::Triple triple;
  switch (os_name) {
    case kOSInvalid:
      LOG(FATAL) << "Cannot get triple OS.";
      break;

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

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` intrinsic with the same names as we find in the
// C++ definition of that function. However, we compile that function with
// debug information, and so we will try to recover the variables names for
// later lookup.
static void FixupBasicBlockVariables(llvm::Function *basic_block) {
  if (BlockHasSpecialVars(basic_block)) {
    return;
  }

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (auto decl_inst = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
        auto addr = decl_inst->getAddress();
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 7)
        addr->setName(decl_inst->getVariable()->getName());
#else
        llvm::DIVariable var(decl_inst->getVariable());
        addr->setName(var.getName());
#endif
      }
    }
  }

  CHECK(BlockHasSpecialVars(basic_block))
      << "Unable to locate required variables in `__remill_basic_block`.";
}

// Initialize some attributes that are common to all newly created block
// functions. Also, give pretty names to the arguments of block functions.
static void InitBlockFunctionAttributes(llvm::Function *block_func) {
  block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  block_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

  remill::NthArgument(block_func, kMemoryPointerArgNum)->setName("memory");
  remill::NthArgument(block_func, kStatePointerArgNum)->setName("state");
  remill::NthArgument(block_func, kPCArgNum)->setName("pc");
}

}  // namespace

// Converts an LLVM module object to have the right triple / data layout
// information for the target architecture.
void Arch::PrepareModule(llvm::Module *mod) const {
  auto basic_block = BasicBlockFunction(mod);

  InitFunctionAttributes(basic_block);
  FixupBasicBlockVariables(basic_block);
  InitBlockFunctionAttributes(basic_block);

  basic_block->addFnAttr(llvm::Attribute::OptimizeNone);
  basic_block->removeFnAttr(llvm::Attribute::AlwaysInline);
  basic_block->removeFnAttr(llvm::Attribute::InlineHint);
  basic_block->addFnAttr(llvm::Attribute::NoInline);
  basic_block->setVisibility(llvm::GlobalValue::DefaultVisibility);

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

}  // namespace remill
