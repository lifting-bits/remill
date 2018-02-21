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
#include <map>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
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

#include "tests/X86/Test.h"

#ifdef __APPLE__
# define SYMBOL_PREFIX "_"
#else
# define SYMBOL_PREFIX ""
#endif

DEFINE_string(bc_out, "",
              "Name of the file in which to place the generated bitcode.");

DECLARE_string(arch);
DECLARE_string(os);

namespace {

// Decode a test and add it as a basic block to the module.
//
// TODO(pag): Eventually handle control-flow.
__attribute__((noinline))
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

  remill::IntrinsicTable intrinsics(module);
  remill::InstructionLifter lifter(word_type, &intrinsics);

  std::map<uint64_t, remill::Instruction> inst;
  std::map<uint64_t, llvm::BasicBlock *> blocks;

  // Function that will create basic blocks as needed.
  auto GetOrCreateBlock = [func, &blocks] (uint64_t block_pc) {
    auto &block = blocks[block_pc];
    if (!block) {
      block = llvm::BasicBlock::Create(func->getContext(), "", func);
    }
    return block;
  };

  std::stringstream seen_insts;
  const char *sep = "";

  auto entry_block = GetOrCreateBlock(test.test_begin);
  llvm::BranchInst::Create(entry_block, &(func->front()));

  // auto saw_isel = false;
  auto addr = test.test_begin;
  while (addr < test.test_end) {
    std::string inst_bytes;
    auto bytes = reinterpret_cast<const char *>(addr);
    inst_bytes.insert(inst_bytes.end(), bytes, bytes + 15);

    remill::Instruction inst;
    CHECK(arch->DecodeInstruction(addr, inst_bytes, inst))
        << "Can't decode test instruction " << inst.Serialize()
        << " in " << test.test_name;

    seen_insts << sep << inst.function;
    sep = ", ";

    LOG(INFO)
        << "Lifting " << inst.Serialize();

    auto block = GetOrCreateBlock(inst.pc);
    CHECK(remill::kLiftedInstruction == lifter.LiftIntoBlock(inst, block))
        << "Can't lift test instruction " << inst.Serialize()
        << " in " << test.test_name;

    // Taken from AArch64, where each test has an isel_name:
    // saw_isel = saw_isel || inst.function == test.isel_name;
    addr += inst.NumBytes();

    // Connect together the basic blocks.
    switch (inst.category) {
      case remill::Instruction::kCategoryNormal:
      case remill::Instruction::kCategoryNoOp:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
        break;

      case remill::Instruction::kCategoryDirectJump:
      case remill::Instruction::kCategoryDirectFunctionCall:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc),
                                 block);
        break;

      case remill::Instruction::kCategoryConditionalBranch:
        llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc),
                                 GetOrCreateBlock(inst.branch_not_taken_pc),
                                 remill::LoadBranchTaken(block), block);
        break;

      default:
        remill::AddTerminatingTailCall(block, intrinsics.missing_block);
        break;
    }
  }

 // CHECK(saw_isel)
 //     << "Test " << test.test_name << " does not have an instruction that "
 //     << "uses the semantics function " << test.isel_name << ", saw "
 //     << seen_insts.str();

  // Terminate any stragglers.
  for (auto pc_to_block : blocks) {
    auto block = pc_to_block.second;
    if (!block->getTerminator()) {
      remill::AddTerminatingTailCall(block, intrinsics.missing_block);
    }
  }
}

}  // namespace

extern "C" int main(int argc, char *argv[]) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  auto os = remill::GetOSName(REMILL_OS);
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Get(os, arch_name);
  auto target_arch = remill::Arch::Get(os, remill::kArchAMD64_AVX512);

  DLOG(INFO) << "Generating tests.";

  auto context = new llvm::LLVMContext;
  auto module = remill::LoadTargetSemantics(context);
  remill::GetHostArch()->PrepareModule(module);

  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    AddFunctionToModule(module, arch, test);
  }

  DLOG(INFO) << "Serializing bitcode to " << FLAGS_bc_out;
  remill::StoreModuleToFile(module, FLAGS_bc_out);

  DLOG(INFO) << "Done.";
  return 0;
}
