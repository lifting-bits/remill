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

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Executor/Native/Executor.h"
#include "tools/vmill/Executor/Runtime.h"
#include "tools/vmill/OS/System.h"

namespace remill {
namespace vmill {
namespace {

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
  target_options.FunctionSections = true;
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

// Implements a function-at-a-time JIT compiler using LLVM's ORC JIT compiler
// infrastructure.
class JITExecutor : public NativeExecutor,
                    public llvm::RuntimeDyld::SymbolResolver {
 public:
  virtual ~JITExecutor(void);

  JITExecutor(const Arch * const arch_, CodeVersion code_version_);

  llvm::RuntimeDyld::SymbolInfo findSymbolInLogicalDylib(
      const std::string &name) override;

  llvm::RuntimeDyld::SymbolInfo findSymbol(const std::string &Name) override;

 protected:
  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  Flow Execute(Process *process, llvm::Function *func) override;

 private:
  JITExecutor(void) = delete;

  // Recompile a module, partially or fully.
  void Compile(llvm::Function *);

  llvm::Triple target_triple;
  llvm::TargetLibraryInfoImpl tli;
  const llvm::Target *target;
  llvm::TargetMachine *target_machine;
  llvm::MCAsmBackend *asm_backend;

  // Loaded dynamic libraries.
  std::vector<std::unique_ptr<DynamicLib>> libs;

  // Cache of symbols used during dynamic symbol resolution.
  std::unordered_map<std::string, uintptr_t> syms;
};

JITExecutor::~JITExecutor(void) {
  delete target_machine;
}

JITExecutor::JITExecutor(const Arch * const arch_, CodeVersion code_version_)
    : NativeExecutor(&kRuntime, arch_, code_version_),
      target_triple(GetTriple()),
      tli(target_triple),
      target(GetTarget(target_triple)),
      target_machine(target->createTargetMachine(
          target_triple.getTriple(),
          llvm::sys::getHostCPUName(),
          GetNativeFeatureString(),
          GetTargetOptions(),
          llvm::Reloc::PIC_,
          llvm::CodeModel::Default,
          llvm::CodeGenOpt::Aggressive)),
      asm_backend(target_machine->getTarget().createMCAsmBackend(
          *target_machine->getMCRegisterInfo(),
          target_triple.getTriple(),
          llvm::sys::getHostCPUName())) {
  llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
}

// Request that `func`'s bitcode be compiled.s
void JITExecutor::Compile(llvm::Function *func) {
  llvm::SmallVector<char, 0> byte_buff;
  llvm::raw_svector_ostream byte_buff_stream(byte_buff);

  llvm::legacy::PassManager pm;
  llvm::MCContext *machine_context = nullptr;
  target_machine->addPassesToEmitMC(
      pm, machine_context, byte_buff_stream, false /* DisableVerify */);

  auto module = func->getParent();
  module->setTargetTriple(target_triple.getTriple());
  module->setDataLayout(target_machine->createDataLayout());
  pm.add(new llvm::TargetLibraryInfoWrapperPass(tli));
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
      << "Unable to find symbol " << name;

  return {reinterpret_cast<uintptr_t>(sym), llvm::JITSymbolFlags::None};
}

// Execute the LLVM function `func` representing code in `process` at
// the current program counter.
Executor::Flow JITExecutor::Execute(Process *process, llvm::Function *func) {
  auto memory = process->Memory();
  auto state = process->MachineState();
  auto pc = process->ProgramCounter();

  auto func_name = func->getName().str();
  auto func_sym = findSymbol(func_name);
  if (!func_sym) {
    Compile(func);
    func_sym = findSymbol(func_name);
    CHECK(func_sym.getAddress())
        << "Unable to find JIT compiled code for " << func_name
        << " implementing code at PC " << std::hex << pc;
  }

  using LiftedFunc = Executor::Flow(void *, void *, uint32_t);
  return reinterpret_cast<LiftedFunc *>(func_sym.getAddress())(
      memory, state, static_cast<uint32_t>(pc));
}

//
//// The ORC JIT compiler operates at the granularity of a "partition". For
//// purely dynamic compilation, a partition can be made up of only a single
//// LLVM function. In our case, Remill-lifted bitcode is "trace-based", that
//// is, one lifted block calls another lifted block calls another, etc. So,
//// when ORC needs to compile something new on-demand, we recursively build
//// up the trace induced by the bitcode.
//std::set<llvm::Function *> TracingJIT::PartitionTrace(llvm::Function &entry) {
//  std::set<llvm::Function *> trace;
//  std::vector<llvm::Function *> work_list;
//  work_list.push_back(&entry);
//
//  while (!work_list.empty()) {
//    llvm::Function *func = work_list.pop_back();
//    trace.insert(func);
//
//    for (auto &block : *func) {
//      if (auto term = block.getTerminatingMustTailCall()) {
//        auto called_func = term->getCalledFunction();
//        if (!trace.count(called_func)) {
//          work_list.push_back(called_func);
//        }
//      }
//    }
//  }
//  return trace;
//}

}  // namespace

NativeExecutor::~NativeExecutor(void) {}

// Create a native code executor. This is a kind-of JIT compiler.
Executor *Executor::CreateNativeExecutor(const Arch * const arch_,
                                         CodeVersion code_version_) {
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmPrinter();
  return new JITExecutor(arch_, code_version_);
}


}  // namespace vmill
}  // namespace remill
