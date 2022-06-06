#include <glog/logging.h>
#include <gtest/gtest.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/X86/Runtime/State.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <functional>
#include <random>

#include "gtest/gtest.h"


int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}


TEST(LiftingRegressions, AsrsFailsInContext) {

  llvm::LLVMContext curr_context;
  auto arch = remill::Arch::Build(&curr_context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchThumb2LittleEndian);
  EXPECT_NE(arch.get(), nullptr);

  remill::Instruction insn;

  std::string_view insn_data("\x00\x11", 2);
  LOG(INFO) << "string len: " << insn_data.size();
  EXPECT_TRUE(!arch->DecodeInstruction(0x12049, insn_data, insn));
}
