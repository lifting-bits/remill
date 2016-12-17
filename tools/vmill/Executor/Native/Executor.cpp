/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <dlfcn.h>
#include <iostream>
#include <sstream>

#include "remill/OS/FileSystem.h"

#include "tools/vmill/BC/Callback.h"
#include "tools/vmill/BC/Translator.h"

#include "tools/vmill/CFG/Decoder.h"

#include "tools/vmill/Executor/Native/Executor.h"
#include "tools/vmill/Executor/Native/Compiler.h"

#include "tools/vmill/OS/System32.h"

DECLARE_string(workspace);

namespace remill {
namespace vmill {
namespace {

// This mirrors the actual `IndirectBlock` structure within Remill's
// `Intrinsics.h`, though we've co-opted it to take different arguments.
struct IndirectBlock final {
  const uint64_t lifted_address;
  LiftedFunction *lifted_func;
};

static std::string SharedObjectFileName(CodeVersion code_version) {
  std::stringstream ss;
  ss << FLAGS_workspace << "/native.cache";
  CHECK(TryCreateDirectory(ss.str()))
      << "Unable to create the " << ss.str() << " directory.";

  ss << "/" << code_version << ".so";
  return ss.str();
}

static void *OpenSharedLibrary(const std::string &file_name) {
  auto handle = dlopen(
      file_name.c_str(), RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);

  CHECK(nullptr != handle)
      << "Unable to load shared library " << file_name << ": "
      << dlerror();

  return handle;
}

}  // namespace

NativeExecutor::~NativeExecutor(void) {
  delete compiler;
  if (shared_object) {
    dlclose(shared_object);
  }
}

NativeExecutor::NativeExecutor(CodeVersion code_version_)
    : Executor(code_version_),
      compiler(Compiler::Create()),
      shared_object_path(SharedObjectFileName(code_version)),
      shared_object(FileExists(shared_object_path) ?
                    OpenSharedLibrary(shared_object_path) : nullptr) {}

Executor::Status NativeExecutor::Execute(Process32 *process, Thread32 *thread) {
  auto state = thread->MachineState();
  while (true) {
    auto pc = thread->ProgramCounter();
//    std::cout << std::hex << pc << std::endl;
    auto func_it = index.find(pc);

    // If we don't have the lifted code, then go lift it!
    if (func_it == index.end()) {
      Recompile(process, thread);
      func_it = index.find(pc);
    }

    CHECK(func_it != index.end())
        << "Unable to find code associated with PC " << std::hex << pc;

    switch ((func_it->second)(nullptr, state, pc)) {
      case ExecutionStatus::kAsyncHyperCall:
//        std::cout << "hyper call at " << std::hex << thread->ProgramCounter() << std::endl;
        return Executor::kStoppedAtAsyncHyperCall;

      case ExecutionStatus::kError:
        return Executor::kStoppedAtError;

      case ExecutionStatus::kFunctionCall:
      case ExecutionStatus::kFunctionReturn:
      case ExecutionStatus::kJump:
        break;
    }
  }

  CHECK(false)
      << "Fell off end of executor!";

  return Executor::kCannotContinue;
}

// Compiles or recompiles the bitcode in order to satisfy a new execution
// request for code that we don't yet have lifted.
void NativeExecutor::Recompile(Process32 *process, Thread32 *thread) {
  LiftedModuleCallback compile_module = [=] (llvm::Module *module) {
    compiler->CompileToSharedObject(module, shared_object_path);
  };

  CFGCallback lift_cfg = [=] (const cfg::Module *cfg) {
    translator->LiftCFG(cfg, compile_module);
  };

  ByteReaderCallback byte_reader = [=] (Addr64 addr, uint8_t *bytes) {
    return process->TryReadExecutableByte(static_cast<Addr32>(addr), bytes);
  };

  const auto pc = thread->ProgramCounter();

  DLOG(INFO)
      << "Lifting and compiling code for " << std::hex << pc;

  decoder->DecodeToCFG(pc, byte_reader, lift_cfg);

  index.clear();
  if (shared_object) {
    dlclose(shared_object);
  }

  // Open up the shared library and find the table of lifted blocks.
  shared_object = OpenSharedLibrary(shared_object_path);
  auto table_addr = dlsym(shared_object, "__remill_indirect_blocks");
  CHECK(nullptr != table_addr)
      << "Unable to find address of __remill_indirect_blocks in "
      << shared_object_path << ": " << dlerror();

  // Fill in the index with the new function pointers.
  auto entry = reinterpret_cast<IndirectBlock *>(table_addr);
  for (; entry->lifted_address && entry->lifted_func; ++entry) {
    index[entry->lifted_address] = entry->lifted_func;
  }

  DLOG(INFO)
      << "Indexed " << index.size() << " lifted functions from "
      << shared_object_path;
}

}  // namespace vmill
}  // namespace remill
