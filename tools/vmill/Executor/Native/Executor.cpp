/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 1
#define ADDRESS_SIZE_BITS 32

#include "remill/Arch/X86/Runtime/State.h"

#include <glog/logging.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <ctime>
#include <functional>
#include <memory>
#include <queue>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>

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

#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/HyperCall.h"
#include "remill/Arch/Runtime/Types.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Executor/Runtime.h"
#include "tools/vmill/OS/System.h"

struct Memory;
struct State;

namespace remill {
namespace vmill {
namespace {

static thread_local Executor::Flow gFlow = Executor::kFlowError;

#define MAKE_READ_WRITE_MEM(suffix, type, intern_type) \
    static type \
    ReadMem ## suffix(Memory *, uint32_t addr) { \
      return static_cast<type>(*reinterpret_cast<intern_type *>( \
          static_cast<uintptr_t>(addr))); \
    } \
    static Memory * \
    WriteMem ## suffix(Memory *mem, uint32_t addr, type val) { \
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

static Memory *MemNoOp(Memory *mem) {
  return mem;
}

template <typename T>
static T Undef(void) {
  return 0;
}

static void DeferInlining(void) {}
static void MarkAsUsed(void *) {}

static void Error(Memory *, ArchState *, uint32_t) {
  gFlow = Executor::kFlowError;
}
static void IndirectFunctionCall(Memory *, ArchState *, uint32_t) {
  gFlow = Executor::kFlowFunctionCall;
}

static void FunctionReturn(Memory *, ArchState *, uint32_t) {
  gFlow = Executor::kFlowFunctionReturn;
}

static void IndirectJump(Memory *, ArchState *, uint32_t) {
  gFlow = Executor::kFlowJump;
}

static void AsyncHyperCall(Memory *, ArchState *, uint32_t) {
  gFlow = Executor::kFlowAsyncHyperCall;
}

static Memory *SyncHyperCall(Memory *memory, ArchState *state_,
                             SyncHyperCall::Name name) {
  auto state = reinterpret_cast<State *>(state_);
  auto pc = state->gpr.rip.dword;

  switch (name) {
    case SyncHyperCall::kX86EmulateInstruction:
      LOG(FATAL)
          << "Unable to execute 32-bit instruction at " << std::hex << pc;
      break;

    case SyncHyperCall::kAMD64EmulateInstruction:
      LOG(FATAL)
          << "Unable to execute 64-bit instruction at " << std::hex << pc;
      break;

    case SyncHyperCall::kDebugBreakpoint:
      if (false) {
        printf(
            "eip=%x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x ebp=%x esp=%x\n",
             state->gpr.rip.dword,
             state->gpr.rax.dword,
             state->gpr.rbx.dword,
             state->gpr.rcx.dword,
             state->gpr.rdx.dword,
             state->gpr.rsi.dword,
             state->gpr.rdi.dword,
             state->gpr.rbp.dword,
             state->gpr.rsp.dword);
        printf("cf=%d pf=%d af=%d zf=%d sf=%d df=%d of=%d\n\n",
               state->aflag.cf,
               state->aflag.pf,
               state->aflag.af,
               state->aflag.zf,
               state->aflag.sf,
               state->aflag.df,
               state->aflag.of);

//        fflush(stdout);
      }
      break;

    default:
      __builtin_unreachable();
      break;
  }

  return memory;
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
// control-flow intrinsics.
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
using LiftedFunc = void(Memory *, ArchState *, uint32_t);

// Implements a function-at-a-time JIT compiler using LLVM's ORC JIT compiler
// infrastructure.
class JITExecutor : public Executor,
                    public llvm::RuntimeDyld::SymbolResolver {
 public:
  virtual ~JITExecutor(void);

  JITExecutor(const Runtime *runtime_,
              const Arch * const arch_);

  // Create a process structure that is compatible with this executor.
  std::unique_ptr<Process> CreateProcess(const Snapshot *snapshot) override;

  llvm::RuntimeDyld::SymbolInfo findSymbolInLogicalDylib(
      const std::string &name) override;

  llvm::RuntimeDyld::SymbolInfo findSymbol(const std::string &Name) override;

 protected:
  // Execute the LLVM function `func` representing code in `process` at
  // the current program counter.
  Flow Execute(Process *process, Thread *thread, llvm::Function *func) override;

 private:
  JITExecutor(void) = delete;

  LiftedFunc *GetLiftedFunc(llvm::Function *func, uint64_t pc);

  void Compile(llvm::Module *module);
  void Compile(llvm::Function *func);

  llvm::Module *CloneCodeIntoNewModule(llvm::Function *func);

  llvm::Triple target_triple;
  const llvm::Target *target;
  llvm::TargetMachine *target_machine;

  std::unordered_map<uint64_t, LiftedFunc *> pc_to_jit_code;

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
                         const Arch * const arch_)
    : Executor(runtime_, arch_),
      target_triple(GetTriple()),
      target(GetTarget(target_triple)),
      target_machine(target->createTargetMachine(
          target_triple.getTriple(),
          llvm::sys::getHostCPUName(),
          GetNativeFeatureString(),
          GetTargetOptions(),
          llvm::Reloc::PIC_,
          llvm::CodeModel::Default,
          llvm::CodeGenOpt::None)) {
  llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
}

// Take clone `entry_func` and all reachable code into a new module, and
// return the new module.
llvm::Module *JITExecutor::CloneCodeIntoNewModule(llvm::Function *entry_func) {
  std::unordered_set<llvm::Function *> partition;
  std::queue<llvm::Function *> work_list;

  work_list.push(entry_func);
  for (auto lifted_func_entry : pc_to_func) {
    auto pc = lifted_func_entry.first;
    auto func = lifted_func_entry.second;
    if (!pc_to_jit_code.count(pc)) {
      work_list.push(func);
    }
  }

  // Go find every function that is directly reachable from `entry_func`. These
  // will all be cloned or declared in our new module.
  while (!work_list.empty()) {
    auto func = work_list.front();
    work_list.pop();
    auto old_size = partition.size();
    partition.insert(func);
    if (partition.size() == old_size) {
      continue;
    }

    for (auto &block : *func) {
      for (auto &inst : block) {
        auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst);
        if (!call_inst || llvm::isa<llvm::DbgInfoIntrinsic>(call_inst)) {
          continue;
        }

        if (auto called_func = call_inst->getCalledFunction()) {
          work_list.push(called_func);
        }
      }
    }
  }

  auto new_module = new llvm::Module(
      entry_func->getName(), entry_func->getContext());

  // Map old functions to new functions.
  std::unordered_map<llvm::Function *, llvm::Function *> func_map;
  for (auto func : partition) {
    auto new_func = llvm::dyn_cast<llvm::Function>(
        new_module->getOrInsertFunction(
            func->getName(), func->getFunctionType()));
    func_map[func] = new_func;
  }

  // Clone not previously compiled functions into the new module.
  auto num_cloned = 0;
  for (auto mapped_func : func_map) {
    auto old_func = mapped_func.first;
    auto new_func = mapped_func.second;

    if (old_func->isIntrinsic()) {
      new_func->recalculateIntrinsicID();

    } else if (!findSymbol(old_func->getName().str())) {
      CHECK(!old_func->isDeclaration())
          << "Cannot clone function declaration " << new_func->getName().str()
          << " into module for JITing.";

      CloneFunctionInto(old_func, new_func);
      ++num_cloned;
    }

    new_func->setAttributes(old_func->getAttributes());
    new_func->setCallingConv(old_func->getCallingConv());
    new_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    new_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }

  DLOG(INFO)
      << "Cloned " << num_cloned << " function into new module for JITing.";

  return new_module;
}

// Compile everything in `module` into a dynamic library.
void JITExecutor::Compile(llvm::Module *module) {

  llvm::SmallVector<char, 4096> byte_buff;
  llvm::raw_svector_ostream byte_buff_stream(byte_buff);

  llvm::legacy::PassManager pm;
  llvm::MCContext *machine_context = nullptr;
  target_machine->addPassesToEmitMC(
      pm, machine_context, byte_buff_stream, true /* DisableVerify */);

  auto codegen_start = time(nullptr);
  pm.run(*module);
  auto dyld_start = time(nullptr);
  DLOG(INFO)
      << "Spent " << (dyld_start - codegen_start) << "s compiling bitcode.";

//  static int i = 0;
//  std::stringstream ss;
//  ss << "/tmp/obj." << i++ << ".o";
//  auto o = ss.str();
//  write(open(o.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666), byte_buff.data(),
//  byte_buff.size_in_bytes());

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

  auto dyld_end = time(nullptr);
  DLOG(INFO)
      << "Spent " << (dyld_end - dyld_start) << "s loading compiled code.";
}

// Compile every function reachable from `func` into a dynamic library.
void JITExecutor::Compile(llvm::Function *func) {
  if (libs.empty()) {

    // TODO(pag): This is ugly. Need this to handle switch tables and such.
    auto module = func->getParent();
    for (auto &var : module->globals()) {
      if (var.hasPrivateLinkage()) {
        var.setLinkage(llvm::GlobalValue::ExternalLinkage);
        var.setVisibility(llvm::GlobalValue::DefaultVisibility);
      }
    }

    for (auto &sub : *module) {
      if (func_to_pc.count(&sub)) {
        sub.setLinkage(llvm::GlobalValue::ExternalLinkage);
        sub.setVisibility(llvm::GlobalValue::DefaultVisibility);
      }
    }

    module->setTargetTriple(target_triple.getTriple());
    module->setDataLayout(target_machine->createDataLayout());
    Compile(module);

  } else {
    auto new_module = CloneCodeIntoNewModule(func);
    new_module->setTargetTriple(target_triple.getTriple());
    new_module->setDataLayout(target_machine->createDataLayout());
    Compile(new_module);
    delete new_module;
  }
}

// Defer to the SectionMemoryManager on the top of the library stack to find
// local symbols.
llvm::RuntimeDyld::SymbolInfo JITExecutor::findSymbolInLogicalDylib(
    const std::string &name) {
  return libs.back()->mman.findSymbolInLogicalDylib(name);
}

// Find compiled symbols.
llvm::RuntimeDyld::SymbolInfo JITExecutor::findSymbol(const std::string &name) {
  auto &sym = syms[name];
  if (sym) {
    return {sym, llvm::JITSymbolFlags::None};

  // See if this symbol is a Remill-specific runtime function.
  } else if (auto runtime_func = runtime->GetImplementation(name)) {
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

    // The symbol isn't exposed in one of the compiled modules; try to find
    // it as a global symbol within the program itself.
    if (!sym) {
      sym = reinterpret_cast<uintptr_t>(dlsym(nullptr, name.c_str()));
    }
  }


  LOG_IF(WARNING, !sym)
      << "Unable to find symbol " << name << "; it may not be compiled yet";

  return {sym, llvm::JITSymbolFlags::None};
}

LiftedFunc *JITExecutor::GetLiftedFunc(llvm::Function *func, uint64_t pc) {
  auto func_name = func->getName().str();
  auto func_sym = findSymbol(func_name);
  if (!func_sym) {
    DLOG(INFO)
        << "Beginning new incremental JIT compile to be able to execute "
        << "lifted code for PC " << std::hex << pc;

    Compile(func);
    func_sym = findSymbol(func_name);
    CHECK(func_sym.getAddress())
        << "Unable to find JIT compiled code for " << func_name
        << " implementing code at PC " << std::hex << pc;
  }

  return reinterpret_cast<LiftedFunc *>(func_sym.getAddress());
}

// Execute the LLVM function `func` representing code in `process` at
// the current program counter.
Executor::Flow JITExecutor::Execute(Process *process, Thread *thread,
                                    llvm::Function *func) {
  auto memory = process->MachineMemory();
  auto state = thread->MachineState();
  auto pc = thread->NextProgramCounter();
  auto &jited_func = pc_to_jit_code[pc];

  if (!jited_func) {
    jited_func = GetLiftedFunc(func, pc);
  }

  jited_func(memory, state, static_cast<uint32_t>(pc));

  return gFlow;
}

// Create a process structure that is compatible with this executor.
std::unique_ptr<Process> JITExecutor::CreateProcess(const Snapshot *snapshot) {
  switch (snapshot->GetOS()) {
    case kOSInvalid:
      LOG(FATAL)
          << "Cannot emulate process for an invalid OS.";
      return nullptr;

    case kOSLinux:
      return Process::CreateNativeLinux(snapshot);

    case kOSmacOS:
      LOG(FATAL)
          << "Cannot emulate a macOS process.";
      return nullptr;
  }
}

}  // namespace

// Create a native code executor. This is a kind-of JIT compiler.
Executor *Executor::CreateNativeExecutor(const Arch * const arch_) {
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmPrinter();
  return new JITExecutor(&kRuntime, arch_);
}

}  // namespace vmill
}  // namespace remill
