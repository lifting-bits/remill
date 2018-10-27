/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

DEFINE_uint64(address, 0, "Address at which we should assume the bytes are"
                          "located in virtual memory.");

DEFINE_uint64(entry_address, 0, "Address of instruction that should be "
                                "considered the entrypoint of this code. "
                                "Defaults to the value of --address.");

DEFINE_string(bytes, "", "Hex-encoded byte string to lift.");

DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "", "Path to file where the LLVM bitcode should be "
                          "saved.");

using Memory = std::map<uint64_t, uint8_t>;

// Unhexlify the data passed to `--bytes`, and fill in `memory` with each
// such byte.
static Memory UnhexlifyInputBytes(uint64_t addr_mask) {
  Memory memory;

  for (size_t i = 0; i < FLAGS_bytes.size(); i += 2) {
    char nibbles[] = {FLAGS_bytes[i], FLAGS_bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      std::cerr
          << "Invalid hex byte value '" << nibbles << "' specified in --bytes."
          << std::endl;
      exit(EXIT_FAILURE);
    }

    auto byte_addr = FLAGS_address + (i / 2);
    auto masked_addr = byte_addr & addr_mask;

    // Make sure that if a really big number is specified for `--address`,
    // that we don't accidentally wrap around and start filling out low
    // byte addresses.
    if (masked_addr < byte_addr) {
      std::cerr
          << "Too many bytes specified to --bytes, would result "
          << "in a 32-bit overflow.";
      exit(EXIT_FAILURE);

    } else if (masked_addr < FLAGS_address) {
      std::cerr
          << "Too many bytes specified to --bytes, would result "
          << "in a 64-bit overflow.";
      exit(EXIT_FAILURE);
    }

    memory[byte_addr] = static_cast<uint8_t>(byte_val);
  }

  return memory;
}

class SimpleTraceManager : public remill::TraceManager {
 public:
  virtual ~SimpleTraceManager(void) = default;

  explicit SimpleTraceManager(Memory &memory_)
      : memory(memory_) {}

 protected:
  // Called when we have lifted, i.e. defined the contents, of a new trace.
  // The derived class is expected to do something useful with this.
  void SetLiftedTraceDefinition(
      uint64_t addr, llvm::Function *lifted_func) override {
    traces[addr] = lifted_func;
  }

  // Get a declaration for a lifted trace. The idea here is that a derived
  // class might have additional global info available to them that lets
  // them declare traces ahead of time. In order to distinguish between
  // stuff we've lifted, and stuff we haven't lifted, we allow the lifter
  // to access "defined" vs. "declared" traces.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override {
    auto trace_it = traces.find(addr);
    if (trace_it != traces.end()) {
      return trace_it->second;
    } else {
      return nullptr;
    }
  }

  // Get a definition for a lifted trace.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override {
    return GetLiftedTraceDeclaration(addr);
  }

  // Try to read an executable byte of memory. Returns `true` of the byte
  // at address `addr` is executable and readable, and updates the byte
  // pointed to by `byte` with the read value.
  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override {
    auto byte_it = memory.find(addr);
    if (byte_it != memory.end()) {
      *byte = byte_it->second;
      return true;
    } else {
      return false;
    }
  }

 public:
  Memory &memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
};

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_bytes.empty()) {
    std::cerr
        << "Please specify a sequence of hex bytes to --bytes." << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_bytes.size() % 2) {
    std::cerr
        << "Please specify an even number of nibbles to --bytes." << std::endl;
    return EXIT_FAILURE;
  }

  if (!FLAGS_entry_address) {
    FLAGS_entry_address = FLAGS_address;
  }

  // Make sure `--address` and `--entry_address` are in-bounds for the target
  // architecture's address size.
  auto arch = remill::GetTargetArch();
  const uint64_t addr_mask = ~0ULL >> (64UL - arch->address_size);
  if (FLAGS_address != (FLAGS_address & addr_mask)) {
    std::cerr
        << "Value " << std::hex << FLAGS_address
        << " passed to --address does not fit into 32-bits. Did mean"
        << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_entry_address != (FLAGS_entry_address & addr_mask)) {
    std::cerr
        << "Value " << std::hex << FLAGS_entry_address
        << " passed to --entry_address does not fit into 32-bits. Did mean"
        << " to specify a 64-bit architecture to --arch?" << std::endl;
    return EXIT_FAILURE;
  }

  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module(remill::LoadTargetSemantics(&context));

  Memory memory = UnhexlifyInputBytes(addr_mask);
  SimpleTraceManager manager(memory);
  remill::IntrinsicTable intrinsics(module);
  remill::InstructionLifter inst_lifter(arch, intrinsics);
  remill::TraceLifter trace_lifter(inst_lifter, manager);

  // Lift all discoverable traces starting from `--entry_address` into
  // `module`.
  trace_lifter.Lift(FLAGS_entry_address);

  // Optimize the module, but with a particular focus on only the functions
  // that we actually lifted.
  remill::OptimizationGuide guide = {};
  guide.eliminate_dead_stores = true;
  remill::OptimizeModule(module, manager.traces, guide);

  // Create a new module in which we will move all the lifted functions. Prepare
  // the module for code of this architecture, i.e. set the data layout, triple,
  // etc.
  llvm::Module dest_module("lifted_code", context);
  arch->PrepareModuleDataLayout(&dest_module);

  // Move the lifted code into a new module. This module will be much smaller
  // because it won't be bogged down with all of the semantics definitions.
  // This is a good JITing strategy: optimize the lifted code in the semantics
  // module, move it to a new module, instrument it there, then JIT compile it.
  for (auto &lifted_entry : manager.traces) {
    remill::MoveFunctionIntoModule(lifted_entry.second, &dest_module);
  }

  int ret = EXIT_SUCCESS;

  if (!FLAGS_ir_out.empty()) {
    if (!remill::StoreModuleIRToFile(&dest_module, FLAGS_ir_out, true)) {
      LOG(ERROR)
          << "Could not save LLVM IR to " << FLAGS_ir_out;
      ret = EXIT_FAILURE;
    }
  }
  if (!FLAGS_bc_out.empty()) {
    if (!remill::StoreModuleToFile(&dest_module, FLAGS_bc_out, true)) {
      LOG(ERROR)
          << "Could not save LLVM bitcode to " << FLAGS_bc_out;
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
