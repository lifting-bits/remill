/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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

#pragma once

#include <glog/logging.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Function.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <random>
#include <sstream>
#include <string>
#include <unordered_map>

namespace test_runner {


using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, uint8_t>;


class MemoryHandler {
 private:
  std::unordered_map<uint64_t, uint8_t> uninitialized_reads;
  std::unordered_map<uint64_t, uint8_t> state;

  random_bytes_engine rbe;
  llvm::support::endianness endian;

 public:
  MemoryHandler(llvm::support::endianness endian_);

  MemoryHandler(llvm::support::endianness endian_,
                std::unordered_map<uint64_t, uint8_t> initial_state);

  uint8_t read_byte(uint64_t addr);


  std::vector<uint8_t> readSize(uint64_t addr, size_t num);

  const std::unordered_map<uint64_t, uint8_t> &GetMemory() const;

  std::string DumpState() const;

  template <class T>
  T ReadMemory(uint64_t addr);


  template <class T>
  void WriteMemory(uint64_t addr, T value);

  std::unordered_map<uint64_t, uint8_t> GetUninitializedReads();
};

template <class T>
T MemoryHandler::ReadMemory(uint64_t addr) {
  auto buff = this->readSize(addr, sizeof(T));
  return llvm::support::endian::read<T>(buff.data(), this->endian);
}


template <class T>
void MemoryHandler::WriteMemory(uint64_t addr, T value) {
  std::vector<uint8_t> buff(sizeof(T));
  llvm::support::endian::write<T>(buff.data(), value, this->endian);
  for (size_t i = 0; i < sizeof(T); i++) {
    this->state[addr + i] = buff[i];
  }
}


void StubOutFlagComputationInstrinsics(llvm::Module *mod,
                                       llvm::ExecutionEngine &exec_engine);
llvm::Function *
CopyFunctionIntoNewModule(llvm::Module *target, const llvm::Function *old_func,
                          const std::unique_ptr<llvm::Module> &old_module);

void *MissingFunctionStub(const std::string &name);

template <typename T, typename P>
void ExecuteLiftedFunction(
    llvm::Function *func, size_t insn_length, T *state,
    test_runner::MemoryHandler *handler,
    const std::function<uint64_t(T *)> &program_counter_fetch) {
  std::string load_error = "";
  llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr, &load_error);
  if (!load_error.empty()) {
    LOG(FATAL) << "Failed to load: " << load_error;
  }

  auto tgt_mod = llvm::CloneModule(*func->getParent());
  tgt_mod->setTargetTriple("");
  tgt_mod->setDataLayout(llvm::DataLayout(""));
  llvm::InitializeNativeTarget();
  llvm::InitializeNativeTargetAsmParser();
  llvm::InitializeNativeTargetAsmPrinter();


  auto res = remill::VerifyModuleMsg(tgt_mod.get());
  if (res.has_value()) {

    LOG(FATAL) << *res;
  }

  llvm::EngineBuilder builder(std::move(tgt_mod));


  std::string estr;
  auto eptr =
      builder.setEngineKind(llvm::EngineKind::JIT).setErrorStr(&estr).create();

  if (eptr == nullptr) {
    LOG(FATAL) << estr;
  }

  std::unique_ptr<llvm::ExecutionEngine> engine(eptr);


  auto target = engine->FindFunctionNamed(func->getName());
  StubOutFlagComputationInstrinsics(target->getParent(), *engine);

  engine->InstallLazyFunctionCreator(&MissingFunctionStub);
  engine->DisableSymbolSearching(false);
  // expect traditional remill lifted insn
  assert(func->arg_size() == 3);

  auto returned =
      (void *(*) (T *, uint32_t, void *) ) engine->getFunctionAddress(
          target->getName().str());

  assert(returned != nullptr);
  auto orig_pc = program_counter_fetch(state);
  // run until we terminate and exit pc
  while (program_counter_fetch(state) == orig_pc) {
    returned(state, program_counter_fetch(state), handler);
  }
}

template <typename T>
void RandomizeState(T &state, random_bytes_engine &rbe) {
  std::vector<uint8_t> data(sizeof(T));
  std::generate(begin(data), end(data), std::ref(rbe));

  std::memcpy(&state, data.data(), sizeof(T));
}

uint8_t random_boolean_flag(random_bytes_engine &rbe);


enum TypeId { MEMORY = 0, STATE = 1 };

class LiftingTester {
 private:
  std::shared_ptr<llvm::Module> semantics_module;
  remill::Arch::ArchPtr arch;
  std::unique_ptr<remill::IntrinsicTable> table;
  remill::OperandLifter::OpLifterPtr lifter;


 public:
  // Produces a tester lifter that lifts into a target prepared semantics module
  LiftingTester(std::shared_ptr<llvm::Module> semantics_module_,
                remill::OSName os_name, remill::ArchName arch_name);

  // Builds a new semantics module to lift into
  LiftingTester(llvm::LLVMContext &context, remill::OSName os_name,
                remill::ArchName arch_name);
  std::unordered_map<TypeId, llvm::Type *> GetTypeMapping();

  std::optional<std::pair<llvm::Function *, remill::Instruction>>
  LiftInstructionFunction(std::string_view fname, std::string_view bytes,
                          uint64_t address);

  std::optional<std::pair<llvm::Function *, remill::Instruction>>
  LiftInstructionFunction(std::string_view fname, std::string_view bytes,
                          uint64_t address, const remill::DecodingContext &ctx);

  const remill::Arch::ArchPtr &GetArch() const;
};
}  // namespace test_runner
