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

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Runtime/HyperCall.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/SleighLifter.h>
#include <remill/BC/Util.h>
#include <test_runner/TestRunner.h>

#include <random>


namespace test_runner {

namespace {
static bool FuncIsIntrinsicPrefixedBy(const llvm::Function *func,
                                      const char *prefix) {
  return func->isDeclaration() && func->getName().find(prefix) == 0;
}
}  // namespace


uint8_t random_boolean_flag(random_bytes_engine &rbe) {
  std::uniform_int_distribution<> gen(0, 1);
  return gen(rbe);
}

void *MissingFunctionStub(const std::string &name) {
  if (auto res = llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(name)) {
    return res;
  }

#ifdef __APPLE__
  if (name.at(0) == '_') {
    if (auto res = llvm::sys::DynamicLibrary::SearchForAddressOfSymbol(
            name.substr(1, name.length()))) {
      return res;
    }
  }
#endif
  LOG(FATAL) << "Missing function: " << name;
  return nullptr;
}

MemoryHandler::MemoryHandler(llvm::endianness endian_) : endian(endian_) {}

MemoryHandler::MemoryHandler(
    llvm::endianness endian_,
    std::unordered_map<uint64_t, uint8_t> initial_state)
    : state(std::move(initial_state)),
      endian(endian_) {}

uint8_t MemoryHandler::read_byte(uint64_t addr) {
  if (state.find(addr) != state.end()) {
    return state.find(addr)->second;
  }

  auto genned = rbe();
  uninitialized_reads.insert({addr, genned});
  state.insert({addr, genned});
  return genned;
}

std::vector<uint8_t> MemoryHandler::readSize(uint64_t addr, size_t num) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < num; i++) {
    bytes.push_back(this->read_byte(addr + i));
  }
  return bytes;
}

const std::unordered_map<uint64_t, uint8_t> &MemoryHandler::GetMemory() const {
  return this->state;
}

std::string MemoryHandler::DumpState() const {

  llvm::json::Object mapping;
  for (const auto &kv : this->state) {
    std::stringstream ss;
    ss << kv.first;
    mapping[ss.str()] = kv.second;
  }

  std::string res;
  llvm::json::Value v(std::move(mapping));
  llvm::raw_string_ostream ss(res);
  ss << v;

  return ss.str();
}

std::unordered_map<uint64_t, uint8_t> MemoryHandler::GetUninitializedReads() {
  return this->uninitialized_reads;
}


extern "C" {
uint8_t __remill_undefined_8(void) {
  return 0;
}

uint8_t __remill_read_memory_8(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  auto res = memory->ReadMemory<uint8_t>(addr);
  LOG(INFO) << "Read memory " << res;
  return res;
}

MemoryHandler *__remill_write_memory_8(MemoryHandler *memory, uint64_t addr,
                                       uint8_t value) {
  LOG(INFO) << "Writing " << std::hex << addr
            << " value: " << (unsigned int) value;
  memory->WriteMemory<uint8_t>(addr, value);
  return memory;
}

uint16_t __remill_read_memory_16(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  auto res = memory->ReadMemory<uint16_t>(addr);
  LOG(INFO) << "Read memory " << res;
  return res;
}

MemoryHandler *__remill_write_memory_16(MemoryHandler *memory, uint64_t addr,
                                        uint16_t value) {
  LOG(INFO) << "Writing " << std::hex << addr << " value: " << value;
  memory->WriteMemory<uint16_t>(addr, value);
  return memory;
}

uint32_t __remill_read_memory_32(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  auto res = memory->ReadMemory<uint32_t>(addr);
  LOG(INFO) << "Read memory " << std::hex << res;
  return res;
}

MemoryHandler *__remill_write_memory_32(MemoryHandler *memory, uint64_t addr,
                                        uint32_t value) {
  LOG(INFO) << "Writing " << std::hex << addr << " value: " << value;
  memory->WriteMemory<uint32_t>(addr, value);
  return memory;
}

uint64_t __remill_read_memory_64(MemoryHandler *memory, uint64_t addr) {
  LOG(INFO) << "Reading " << std::hex << addr;
  return memory->ReadMemory<uint64_t>(addr);
}

MemoryHandler *__remill_write_memory_64(MemoryHandler *memory, uint64_t addr,
                                        uint64_t value) {
  LOG(INFO) << "Writing " << std::hex << addr << " value: " << value;
  memory->WriteMemory<uint64_t>(addr, value);
  return memory;
}

struct State;

// PowerPC syscalls leave a `__remill_sync_hyper_call` invocation.
// Create an empty stub implementation so we can still execute our LLVM code.
MemoryHandler *__remill_sync_hyper_call(State &state, MemoryHandler *mem,
                                        SyncHyperCall::Name call) {
  return mem;
}
}


LiftingTester::LiftingTester(std::shared_ptr<llvm::Module> semantics_module_,
                             remill::OSName os_name, remill::ArchName arch_name)
    : semantics_module(std::move(semantics_module_)),
      arch(remill::Arch::Build(&this->semantics_module->getContext(), os_name,
                               arch_name)),
      table(std::make_unique<remill::IntrinsicTable>(
          this->semantics_module.get())) {
  this->arch->InitFromSemanticsModule(this->semantics_module.get());
  this->lifter = this->arch->DefaultLifter(*this->table.get());
}

LiftingTester::LiftingTester(llvm::LLVMContext &context, remill::OSName os_name,
                             remill::ArchName arch_name)
    : arch(remill::Arch::Build(&context, os_name, arch_name)) {
  this->semantics_module =
      std::shared_ptr(remill::LoadArchSemantics(this->arch.get()));
  this->table =
      std::make_unique<remill::IntrinsicTable>(this->semantics_module.get());
  this->lifter = this->arch->DefaultLifter(*this->table.get());
}

std::unordered_map<TypeId, llvm::Type *> LiftingTester::GetTypeMapping() {
  std::unordered_map<TypeId, llvm::Type *> res;

  res.emplace(TypeId::MEMORY, this->arch->MemoryPointerType());
  res.emplace(TypeId::STATE, this->arch->StateStructType());

  return res;
}


std::optional<std::pair<llvm::Function *, remill::Instruction>>
LiftingTester::LiftInstructionFunction(std::string_view fname,
                                       std::string_view bytes, uint64_t address,
                                       const remill::DecodingContext &ctx) {
  remill::Instruction insn;
  // This works for now since each arch has an initial context that represents the arch correctly.
  if (!this->arch->DecodeInstruction(address, bytes, insn, ctx)) {
    LOG(ERROR) << "Failed decode";
    return std::nullopt;
  }

  LOG(INFO) << "Decoded insn " << insn.Serialize();

  auto target_func =
      this->arch->DefineLiftedFunction(fname, this->semantics_module.get());
  LOG(INFO) << "Func sig: "
            << remill::LLVMThingToString(target_func->getType());

  if (remill::LiftStatus::kLiftedInstruction !=
      insn.GetLifter()->LiftIntoBlock(insn, &target_func->getEntryBlock())) {
    target_func->eraseFromParent();
    return std::nullopt;
  }

  auto mem_ptr_ref =
      remill::LoadMemoryPointerRef(&target_func->getEntryBlock());

  llvm::IRBuilder bldr(&target_func->getEntryBlock());

  auto pc_ref = remill::LoadProgramCounterRef(&target_func->getEntryBlock());
  auto next_pc_ref =
      remill::LoadNextProgramCounterRef(&target_func->getEntryBlock());
  bldr.CreateStore(
      bldr.CreateLoad(llvm::IntegerType::get(target_func->getContext(), 32),
                      next_pc_ref),
      pc_ref);

  bldr.CreateRet(bldr.CreateLoad(this->lifter->GetMemoryType(), mem_ptr_ref));

  return std::make_pair(target_func, insn);
}

std::optional<std::pair<llvm::Function *, remill::Instruction>>
LiftingTester::LiftInstructionFunction(std::string_view fname,
                                       std::string_view bytes,
                                       uint64_t address) {
  return LiftInstructionFunction(fname, bytes, address,
                                 this->arch->CreateInitialContext());
}

const remill::Arch::ArchPtr &LiftingTester::GetArch() const {
  return this->arch;
}


static constexpr const char *kFlagIntrinsicPrefix = "__remill_flag_computation";
static constexpr const char *kCompareFlagIntrinsicPrefix = "__remill_compare";

/// NOTE(Ian): This stub is variadic to handle flag computations which accept arbitrary operand width types. since this function
/// stubs out to an identity function at runtime this is fine.
bool flag_computation_stub(bool res, ...) {
  return res;
}

bool compare_instrinsic_stub(bool res) {
  return res;
}


llvm::Function *
CopyFunctionIntoNewModule(llvm::Module *target, const llvm::Function *old_func,
                          const std::unique_ptr<llvm::Module> &old_module) {
  auto new_f = llvm::Function::Create(old_func->getFunctionType(),
                                      old_func->getLinkage(),
                                      old_func->getName(), target);
  remill::CloneFunctionInto(old_module->getFunction(old_func->getName()),
                            new_f);
  return new_f;
}

void StubOutFlagComputationInstrinsics(llvm::Module *mod,
                                       llvm::ExecutionEngine &exec_engine) {
  for (auto &func : mod->getFunctionList()) {
    if (FuncIsIntrinsicPrefixedBy(&func, kFlagIntrinsicPrefix)) {
      exec_engine.addGlobalMapping(&func, (void *) &flag_computation_stub);
    }

    if (FuncIsIntrinsicPrefixedBy(&func, kCompareFlagIntrinsicPrefix)) {
      exec_engine.addGlobalMapping(&func, (void *) &compare_instrinsic_stub);
    }
  }
}
}  // namespace test_runner
