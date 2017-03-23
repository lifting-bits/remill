/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/OS.h"

#include "tests/X86/Test.h"

#ifdef __APPLE__
# define SYMBOL_PREFIX "_"
#else
# define SYMBOL_PREFIX ""
#endif

#ifndef REMILL_OS
# if defined(__APPLE__)
#   define REMILL_OS "mac"
# elif defined(__linux__)
#   define REMILL_OS "linux"
# endif
#endif

DEFINE_string(bc_out, "",
              "Name of the file in which to place the generated bitcode.");

DEFINE_string(arch, "", "Architecture of the code to be lifted.");

DEFINE_string(os, "", "");

namespace {

// Decode a test and add it as a basic block to the module.
//
// TODO(pag): Eventually handle control-flow.
static void AddFunctionToModule(remill::cfg::Module *module,
                                const remill::Arch *arch,
                                const test::TestInfo &test) {
  std::stringstream ss;
  ss << SYMBOL_PREFIX << test.test_name << "_lifted";

  DLOG(INFO) << "Adding block for: " << test.test_name;

  auto block = module->add_blocks();
  block->set_address(test.test_begin);
  block->set_name(ss.str());

  auto addr = test.test_begin;
  while (addr < test.test_end) {
    std::string instr_bytes;
    auto bytes = reinterpret_cast<const char *>(addr);
    instr_bytes.insert(instr_bytes.end(), bytes, bytes + 15);

    auto inst = arch->DecodeInstruction(addr, instr_bytes);
    CHECK(inst->IsValid())
        << "Can't decode test instruction in " << test.test_name;

    instr_bytes.clear();
    instr_bytes.insert(instr_bytes.end(), bytes, bytes + inst->NumBytes());

    auto instr = block->add_instructions();
    instr->set_bytes(instr_bytes);
    instr->set_address(addr);
    addr += inst->NumBytes();

    delete inst;
  }
}

}  // namespace

extern "C" int main(int argc, char *argv[]) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  auto os = remill::kOSLinux;
  auto arch_name = remill::GetArchName(FLAGS_arch);
  auto arch = remill::Arch::Get(os, arch_name);
  auto target_arch = remill::Arch::Get(os, remill::kArchAMD64_AVX512);

  DLOG(INFO) << "Generating tests.";

  auto cfg = new remill::cfg::Module;
  for (auto i = 0U; ; ++i) {
    const auto &test = test::__x86_test_table_begin[i];
    if (&test >= &(test::__x86_test_table_end[0])) break;
    AddFunctionToModule(cfg, arch, test);
  }

  auto context = new llvm::LLVMContext;
  auto bc_file = remill::FindSemanticsBitcodeFile("", FLAGS_arch);
  auto module = remill::LoadModuleFromFile(context, bc_file);
  target_arch->PrepareModule(module);
  auto translator = new remill::Lifter(arch, module);
  translator->LiftCFG(cfg);

  // Rename all the lifted blocks to have the same name as their test cases.
  remill::ForEachBlock(module,
                       [=] (uint64_t pc, uint64_t, llvm::Function *func) {
    std::string name;
    CHECK(remill::TryGetBlockName(func, name))
        << "Unable to get the name of the block at PC " << std::hex << pc;
    func->setName(name);
    func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  });

  DLOG(INFO) << "Serializing bitcode to " << FLAGS_bc_out;
  remill::StoreModuleToFile(module, FLAGS_bc_out);

  DLOG(INFO) << "Done.";
  return 0;
}
