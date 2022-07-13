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
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <functional>
#include <random>

#include "gtest/gtest.h"


namespace {
const static std::unordered_map<std::string,
                                std::function<uint32_t &(AArch32State &)>>
    reg_to_accessor = {};
}

class TestOutputSpec {
 private:
  std::string target_bytes;
  remill::Instruction::Category expected_category;
  std::vector<std::pair<std::string, uint32_t>> register_preconditions;
  std::vector<std::pair<std::string, uint32_t>> register_postconditions;


  void ApplyCondition(AArch32State &state, std::string reg, uint32_t value) {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      accessor->second(state) = value;
    }
  }

  void CheckCondition(AArch32State &state, std::string reg, uint32_t value) {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      CHECK_EQ(accessor->second(state), value);
    }
  }

 public:
  TestOutputSpec(
      std::string target_bytes, remill::Instruction::Category expected_category,
      std::vector<std::pair<std::string, uint32_t>> register_preconditions,
      std::vector<std::pair<std::string, uint32_t>> register_postconditions)
      : target_bytes(target_bytes),
        expected_category(expected_category),
        register_preconditions(std::move(register_preconditions)),
        register_postconditions(std::move(register_postconditions)) {}


  void SetupTestPreconditions(AArch32State &state) {
    for (auto prec : this->register_preconditions) {
      this->ApplyCondition(state, prec.first, prec.second);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(AArch32State &state) {
    for (auto post : this->register_postconditions) {
      this->CheckCondition(state, post.first, post.second);
    }
  }
};

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
