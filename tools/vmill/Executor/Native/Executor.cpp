/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/Triple.h>

#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/CodeGen/AsmPrinter.h>
#include <llvm/CodeGen/MachineFunctionPass.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/CodeGen/Passes.h>

#include <llvm/ExecutionEngine/ObjectMemoryBuffer.h>
#include <llvm/ExecutionEngine/RTDyldMemoryManager.h>
#include <llvm/ExecutionEngine/RuntimeDyld.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Module.h>

#include <llvm/Object/ObjectFile.h>

#include <llvm/Support/CodeGen.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetSubtargetInfo.h>

#include "remill/Arch/Runtime/HyperCall.h"
#include "remill/Arch/Runtime/Types.h"
#include "remill/BC/Util.h"

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Executor/Native/Executor.h"
#include "tools/vmill/Executor/Runtime.h"
#include "tools/vmill/OS/System.h"

namespace remill {
namespace vmill {
namespace {

enum {
  kMaxNumLibs = 64
};

#define MAKE_READ_WRITE_MEM(suffix, type, intern_type) \
    static type \
    ReadMem ## suffix (void *, uint32_t addr) { \
      return static_cast<type>(*reinterpret_cast<intern_type *>( \
          static_cast<uintptr_t>(addr))); \
    } \
    static void * \
    WriteMem ## suffix (void *mem, uint32_t addr, type val) { \
      *reinterpret_cast<intern_type *>( \
          static_cast<uintptr_t>(addr)) = static_cast<intern_type>(val); \
      return mem; \
    }

MAKE_READ_WRITE_MEM(8, uint8_t, uint8_t)
MAKE_READ_WRITE_MEM(16, uint16_t, uint16_t)
MAKE_READ_WRITE_MEM(32, uint32_t, uint32_t)
MAKE_READ_WRITE_MEM(64, uint64_t, uint64_t)
MAKE_READ_WRITE_MEM(FP32, float32_t, float32_t)
MAKE_READ_WRITE_MEM(FP64, float64_t, float64_t)
MAKE_READ_WRITE_MEM(FP80, float64_t, long double)

static void *MemNoOp(void *mem) {
  return mem;
}

template <typename T>
static T Undef(void) {
  return 0;
}

static void DeferInlining(void) {}
static void MarkAsUsed(void *) {}

static Executor::Flow Error(void *, void *, uint32_t) {
  return Executor::kFlowError;
}
static Executor::Flow IndirectFunctionCall(void *, void *, uint32_t) {
  return Executor::kFlowFunctionCall;
}

static Executor::Flow FunctionReturn(void *, void *, uint32_t) {
  return Executor::kFlowFunctionReturn;
}

static Executor::Flow IndirectJump(void *, void *, uint32_t) {
  return Executor::kFlowJump;
}

static Executor::Flow AsyncHyperCall(void *, void *, uint32_t) {
  return Executor::kFlowAsyncHyperCall;
}

static void *SyncHyperCall(void *, void *, SyncHyperCall::Name) {
  __builtin_unreachable();
}

static const struct Runtime kRuntime = {
    reinterpret_cast<void *>(ReadMem8),
    reinterpret_cast<void *>(ReadMem16),
    reinterpret_cast<void *>(ReadMem32),
    reinterpret_cast<void *>(ReadMem64),
    reinterpret_cast<void *>(WriteMem8),
    reinterpret_cast<void *>(WriteMem16),
    reinterpret_cast<void *>(WriteMem32),
    reinterpret_cast<void *>(WriteMem64),
    reinterpret_cast<void *>(ReadMemFP32),
    reinterpret_cast<void *>(ReadMemFP64),
    reinterpret_cast<void *>(ReadMemFP80),
    reinterpret_cast<void *>(WriteMemFP32),
    reinterpret_cast<void *>(WriteMemFP64),
    reinterpret_cast<void *>(WriteMemFP80),
    reinterpret_cast<void *>(Error),
    reinterpret_cast<void *>(IndirectJump),
    reinterpret_cast<void *>(IndirectFunctionCall),
    reinterpret_cast<void *>(FunctionReturn),
    reinterpret_cast<void *>(AsyncHyperCall),
    reinterpret_cast<void *>(SyncHyperCall),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(MemNoOp),
    reinterpret_cast<void *>(Undef<uint8_t>),
    reinterpret_cast<void *>(Undef<uint16_t>),
    reinterpret_cast<void *>(Undef<uint32_t>),
    reinterpret_cast<void *>(Undef<uint64_t>),
    reinterpret_cast<void *>(Undef<float32_t>),
    reinterpret_cast<void *>(Undef<float64_t>),
    reinterpret_cast<void *>(DeferInlining),
    reinterpret_cast<void *>(MarkAsUsed)
};

// Return the target triple.
static llvm::Triple GetTriple(void) {
  llvm::Triple triple(llvm::Triple::getArchTypeName(llvm::Triple::x86_64),
                      llvm::Triple::getVendorTypeName(llvm::Triple::PC),
                      llvm::Triple::getOSTypeName(llvm::Triple::Linux),
                      llvm::Triple::getEnvironmentTypeName(llvm::Triple::GNU));
  return triple;
}

// Emulates `-mtune=native`. We want the compiled code to run as well as it
// can on the current machine.
static std::string GetNativeFeatureString(void) {
  llvm::SubtargetFeatures target_features;
  llvm::StringMap<bool> host_features;
  if (llvm::sys::getHostCPUFeatures(host_features)) {
    for (auto &feature : host_features) {
      target_features.AddFeature(feature.first(), feature.second);
    }
  }
  return target_features.getString();
}

static const llvm::Target *GetTarget(llvm::Triple target_triple) {
  std::string error;
  auto target = llvm::TargetRegistry::lookupTarget("", target_triple, error);
  CHECK(nullptr != target)
      << "Unable to find target for triple " << target_triple.getTriple()
      << ": " << error;
  return target;
}

// Remill depends on tail-calls to transfer control between lifted blocks and
// control-flow intrinsics. We want to put functions into their own sections
// so that `ld` will do some dead-code elimination for use.
static llvm::TargetOptions GetTargetOptions(void) {
  llvm::TargetOptions target_options;
  target_options.GuaranteedTailCallOpt = true;
  target_options.EnableFastISel = true;
  return target_options;
}

// Packages up all things related to dynamically generated shared libraries.
class DynamicLib {
 public:
  explicit DynamicLib(llvm::RuntimeDyld::SymbolResolver &resolver)
      : loader(mman, resolver) {
    // Don't allocate memory for sections that aren't needed for execution.
    loader.setProcessAllSections(false);
  }

  llvm::SectionMemoryManager mman;
  llvm::RuntimeDyld loader;
  std::unique_ptr<llvm::ObjectMemoryBuffer> buff;
  std::unique_ptr<llvm::object::ObjectFile> file;

 private:
  DynamicLib(void) = delete;
};

// Type of a compiled lifted function.
using LiftedFunc = Executor::Flow(void *, void *, uint32_t);

// Implements a function-at-a-time JIT compiler using LLVM's ORC JIT compiler
// infrastructure.
class JITExecutor : public NativeExecutor,
                    public llvm::RuntimeDyld::SymbolResolver {
 public:
  virtual ~JITExecutor(void);

  JITExecutor(const Runtime *runtime_,
              const Arch * const arch_,
              CodeVersion code_version_);

  llvm::RuntimeDyld::SymbolInfo findSymbolInLogicalDylib(
      const std::string &name) override;

  llvm::RuntimeDyld::SymbolInfo findSymbol(const std::string &Name) override;

 protected:
  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  Flow Execute(Process *process, llvm::Function *func) override;

 private:
  JITExecutor(void) = delete;

  void CollapseCache(llvm::Module *module);

  LiftedFunc *GetLiftedFunc(llvm::Function *func, uint64_t pc);
  void Compile(llvm::Module *);
  void InitializeModuleForCodeGen(llvm::Module *);
  void FinalizeModuleForCodeGen(llvm::Module *);

  llvm::Triple target_triple;
  const llvm::Target *target;
  llvm::TargetMachine *target_machine;

  std::unordered_map<uint64_t, LiftedFunc *> funcs;

  // Loaded dynamic libraries.
  std::vector<std::unique_ptr<DynamicLib>> libs;

  // Cache of symbols used during dynamic symbol resolution.
  std::unordered_map<std::string, uintptr_t> syms;

  // Set of functions that we're planning to JIT compile.
  std::set<llvm::Function *> jited_funcs;
};

JITExecutor::~JITExecutor(void) {
  delete target_machine;
}

JITExecutor::JITExecutor(const Runtime *runtime_,
                         const Arch * const arch_,
                         CodeVersion code_version_)
    : NativeExecutor(runtime_, arch_, code_version_),
      target_triple(GetTriple()),
      target(GetTarget(target_triple)),
      target_machine(target->createTargetMachine(
          target_triple.getTriple(),
          llvm::sys::getHostCPUName(),
          GetNativeFeatureString(),
          GetTargetOptions(),
          llvm::Reloc::PIC_,
          llvm::CodeModel::JITDefault,
          llvm::CodeGenOpt::None)) {
  llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
}

void JITExecutor::CollapseCache(llvm::Module *module) {
  DLOG(INFO)
      << "Collapsing " << libs.size() << " cached shared libraries.";

  funcs.clear();
  libs.clear();
  syms.clear();

  for (auto &func : *module) {
    if (func.hasAvailableExternallyLinkage()) {
      func.setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }

  for (auto &global : module->getGlobalList()) {
    if (global.hasAvailableExternallyLinkage()) {
      global.setLinkage(llvm::GlobalValue::ExternalLinkage);
    }
  }
}


// Mark externally available globals with initializers as having available
// externally linkage to prevent them (semantics ISELs, indirect/exported/
// imported block tables) from being recompiled.
//
// TODO(pag): This isn't ideal but oh well. We reverse this in `TE::~TE`.
void JITExecutor::InitializeModuleForCodeGen(llvm::Module *module) {
  // We're going to compile lifted functions (ideally), and probably semantics
  // functions on the first pass. We want those functions to be available for
  // lookup by the `Execute` method, but not to be recompiled. So initially
  // we mark them all external, so that they will be available for lookup, but
  // after JITing them, we mark them as available externally (which is true!)
  // so that they don't get recompiled.
  auto num_funcs_to_compile = 0;
  for (auto &func : *module) {
    if (!func.isDeclaration() && !func.hasAvailableExternallyLinkage()) {
      func.setLinkage(llvm::GlobalValue::ExternalLinkage);
      ++num_funcs_to_compile;
      jited_funcs.insert(&func);
    }
  }

  DLOG(INFO)
      << "Going to JIT compile " << num_funcs_to_compile << " functions";

  if (!libs.empty()) {
    return;
  }

  auto num_marked_globals = 0;
  for (auto &global : module->getGlobalList()) {
    if (global.hasInitializer() && global.hasExternalLinkage() &&
        llvm::isa<llvm::Constant>(global)) {
      global.setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
      ++num_marked_globals;
    }
  }

  DLOG(INFO)
      << "Marked " << num_marked_globals << " globals to not be recompiled";
}

// Mark now-compiled lifted functions as externally available. The next
// time we try to compile the module, marked functions will be ignored
// during code generation (see llvm::MachineFunctionPass::runOnFunction).
//
// This isn't ideal, and is reversed in `TE::~TE` to make sure the cached
// module, if/when revived, can be JIT-compiled "properly".
void JITExecutor::FinalizeModuleForCodeGen(llvm::Module *module) {
  if (auto intrinsics = module->getFunction("__remill_intrinsics")) {
    intrinsics->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  if (auto basic_block = module->getFunction("__remill_basic_block")) {
    basic_block->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  auto num_compiled_functions = 0;
  for (auto jited_func : jited_funcs) {
    jited_func->setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
    ++num_compiled_functions;
  }
  jited_funcs.clear();

  DLOG(INFO)
      << "JIT-compiled " << num_compiled_functions << " functions";
}

// Compile everything in `module` into a dynamic library. This will library
// representing this module onto the `libs` stack.
void JITExecutor::Compile(llvm::Module *module) {

  if (libs.size() >= kMaxNumLibs) {
    CollapseCache(module);
  }

  if (auto intrinsics = module->getFunction("__remill_intrinsics")) {
    intrinsics->setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
  }

  if (auto basic_block = module->getFunction("__remill_basic_block")) {
    basic_block->setLinkage(llvm::GlobalValue::AvailableExternallyLinkage);
  }

  InitializeModuleForCodeGen(module);

  llvm::SmallVector<char, 0> byte_buff;
  llvm::raw_svector_ostream byte_buff_stream(byte_buff);

  llvm::legacy::PassManager pm;
  llvm::MCContext *machine_context = nullptr;
  target_machine->addPassesToEmitMC(
      pm, machine_context, byte_buff_stream, false /* DisableVerify */);

  module->setTargetTriple(target_triple.getTriple());
  module->setDataLayout(target_machine->createDataLayout());
  pm.run(*module);

  std::unique_ptr<llvm::ObjectMemoryBuffer> obj_buff(
      new llvm::ObjectMemoryBuffer(std::move(byte_buff)));

  auto obj_file_exp = llvm::object::ObjectFile::createObjectFile(
      *obj_buff, llvm::sys::fs::file_magic::elf_shared_object);

  std::string error;
  if (!obj_file_exp) {
    llvm::raw_string_ostream error_stream(error);
    llvm::logAllUnhandledErrors(obj_file_exp.takeError(), error_stream, "");
    error_stream.flush();

    LOG(FATAL)
        << "Failed to load JIT-compiled object file from memory: " << error;
  }

  std::unique_ptr<DynamicLib> lib(new DynamicLib(*this));
  lib->file = std::move(*obj_file_exp);
  lib->buff = std::move(obj_buff);

  auto info = lib->loader.loadObject(*lib->file.get());
  CHECK(!lib->loader.hasError())
      << "Unable to load JIT-compiled object into a dyld: "
      << lib->loader.getErrorString().str();

  // Push the lib onto the lib stack, and ask it to resolve symbols (it will
  // use the JIT executor's symbol cache for this).
  libs.push_back(std::move(lib));
  libs.back()->loader.resolveRelocations();
  CHECK(!libs.back()->mman.finalizeMemory(&error))
      << "Unable to finalize JITed code memory: " << error;

  FinalizeModuleForCodeGen(module);
}

// Defer to the SectionMemoryManager on the top of the library stack to find
// local symbols.
llvm::RuntimeDyld::SymbolInfo JITExecutor::findSymbolInLogicalDylib(
    const std::string &name) {
  return libs.back()->mman.findSymbolInLogicalDylib(name);
}

// Use the runtime
llvm::RuntimeDyld::SymbolInfo JITExecutor::findSymbol(const std::string &name) {
  auto &sym = syms[name];
  if (sym) {
    return {reinterpret_cast<uintptr_t>(sym), llvm::JITSymbolFlags::None};
  }

  if (auto runtime_func = runtime->GetImplementation(name)) {
    sym = reinterpret_cast<uintptr_t>(runtime_func);

  // Go down the stack of loaded libs and find the symbol.
  } else {
    for (auto rlib_it = libs.rbegin(); rlib_it != libs.rend(); ++rlib_it) {
      if (auto sym_ptr = (*rlib_it)->loader.getSymbolLocalAddress(name)) {
        sym = reinterpret_cast<uintptr_t>(sym_ptr);
        break;
      }
      auto dsym = (*rlib_it)->mman.findSymbolInLogicalDylib(name);
      if (dsym) {
        sym = dsym.getAddress();
        break;
      }

      dsym = (*rlib_it)->mman.findSymbol(name);
      if (dsym) {
        sym = dsym.getAddress();
        break;
      }
    }
  }

  LOG_IF(WARNING, !sym)
      << "Unable to find symbol " << name << "; it may not be compiled yet";

  return {reinterpret_cast<uintptr_t>(sym), llvm::JITSymbolFlags::None};
}

LiftedFunc *JITExecutor::GetLiftedFunc(llvm::Function *func, uint64_t pc) {
  auto func_name = func->getName().str();
  auto func_sym = findSymbol(func_name);
  if (!func_sym) {
    DLOG(INFO)
        << "Beginning new incremental JIT compile to be able to execute "
        << "lifted code for PC " << std::hex << pc;

    Compile(func->getParent());
    func_sym = findSymbol(func_name);
    CHECK(func_sym.getAddress())
        << "Unable to find JIT compiled code for " << func_name
        << " implementing code at PC " << std::hex << pc;
  }

  return reinterpret_cast<LiftedFunc *>(func_sym.getAddress());
}

// Execute the LLVM function `func` representing code in `process` at
// the current program counter.
Executor::Flow JITExecutor::Execute(Process *process, llvm::Function *func) {
  auto memory = process->Memory();
  auto state = process->MachineState();
  auto pc = process->ProgramCounter();
  auto &jited_func = funcs[pc];

  if (!jited_func) {
    jited_func = GetLiftedFunc(func, pc);
  }

  return jited_func(memory, state, static_cast<uint32_t>(pc));
}

}  // namespace

NativeExecutor::~NativeExecutor(void) {}

// Create a native code executor. This is a kind-of JIT compiler.
Executor *Executor::CreateNativeExecutor(const Arch * const arch_,
                                         CodeVersion code_version_) {
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmPrinter();
  return new JITExecutor(&kRuntime, arch_, code_version_);
}


}  // namespace vmill
}  // namespace remill
