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

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/Arch/Name.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/OS/OS.h"

#include "tests/AArch64/Test.h"

#ifdef __APPLE__
# define SYMBOL_PREFIX "_"
#else
# define SYMBOL_PREFIX ""
#endif

DEFINE_string(bc_out, "",
              "Name of the file in which to place the generated bitcode.");

DECLARE_string(arch);
DECLARE_string(os);

extern "C" {
int gNativeState [[gnu::used]] = 0;
int gLiftedState [[gnu::used]] = 0;
}  // extern

namespace {

// Decode a test and add it as a basic block to the module.
//
// TODO(pag): Eventually handle control-flow.
static void AddFunctionToModule(llvm::Module *module,
                                const remill::Arch *arch,
                                const test::TestInfo &test) {
  DLOG(INFO)
      << "Adding block for: " << test.test_name;

  std::stringstream ss;
  ss << SYMBOL_PREFIX << test.test_name << "_lifted";

  auto word_type = llvm::Type::getIntNTy(module->getContext(),
                                         arch->address_size);
  auto func = remill::DeclareLiftedFunction(module, ss.str());
  remill::CloneBlockFunctionInto(func);

  func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  func->addFnAttr(llvm::Attribute::OptimizeNone);

  remill::IntrinsicTable intrinsics(module);
  remill::InstructionLifter lifter(word_type, &intrinsics);

  auto block = &(func->front());
  auto addr = test.test_begin;
  while (addr < test.test_end) {
    std::string inst_bytes;
    auto bytes = reinterpret_cast<const char *>(addr);
    inst_bytes.insert(inst_bytes.end(), bytes, bytes + 4);

    remill::Instruction inst;
    CHECK(arch->DecodeInstruction(addr, inst_bytes, inst))
        << "Can't decode test instruction in " << test.test_name;

    LOG(INFO)
        << "Lifting " << inst.Serialize();

    CHECK(lifter.LiftIntoBlock(inst, block))
        << "Can't lift test instruction in " << test.test_name;

    addr += inst.NumBytes();
  }

  remill::AddTerminatingTailCall(block, intrinsics.missing_block);
}

}  // namespace

extern "C" int main(int argc, char *argv[]) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  auto os = remill::GetOSName(REMILL_OS);
  auto arch = remill::Arch::Get(os, remill::kArchAArch64LittleEndian);

  DLOG(INFO) << "Generating tests.";

  auto context = new llvm::LLVMContext;
  auto bc_file = remill::FindSemanticsBitcodeFile(FLAGS_arch);
  auto module = remill::LoadModuleFromFile(context, bc_file);
  remill::GetHostArch()->PrepareModule(module);

  for (auto i = 0U; ; ++i) {
    const auto &test = test::__aarch64_test_table_begin[i];
    if (&test >= &(test::__aarch64_test_table_end[0])) break;
    AddFunctionToModule(module, arch, test);
  }

  DLOG(INFO) << "Serializing bitcode to " << FLAGS_bc_out;
  remill::StoreModuleToFile(module, FLAGS_bc_out);

  DLOG(INFO) << "Done.";
  return 0;
}
