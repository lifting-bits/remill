#include <glog/logging.h>
#include <gtest/gtest.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include "gtest/gtest.h"

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}


class LiftingTester {
 private:
  remill::InstructionLifter::LifterPtr lifter;
  std::unique_ptr<llvm::Module> target_module;
  std::unique_ptr<remill::IntrinsicTable> table;
  remill::Arch::ArchPtr arch;

 public:
  LiftingTester(llvm::LLVMContext *context, remill::OSName os_name,
                remill::ArchName arch_name) {
    this->arch = remill::Arch::Build(context, os_name, arch_name);
    this->target_module = remill::LoadArchSemantics(this->arch.get());
    this->table =
        std::make_unique<remill::IntrinsicTable>(this->target_module.get());
    this->lifter = this->arch->DefaultLifter(*this->table.get());
    this->arch->PrepareModule(this->target_module);
  }

  std::optional<llvm::Function *>
  LiftInstructionFunction(std::string_view fname, std::string_view bytes,
                          uint64_t address) {
    remill::Instruction insn;
    if (!this->arch->DecodeInstruction(address, bytes, insn)) {
      return std::nullopt;
    }

    auto target_func =
        this->arch->DefineLiftedFunction(fname, this->target_module.get());

    if (remill::LiftStatus::kLiftedInstruction ==
        this->lifter->LiftIntoBlock(insn, &target_func->getEntryBlock())) {
      return target_func;
    } else {
      target_func->eraseFromParent();
      return std::nullopt;
    }
  }
};


TEST(DifferentialTests, SimpleAddDifferenceX86) {
  llvm::LLVMContext context;
  LiftingTester sleighx86tester(&context, remill::OSName::kOSLinux,
                                remill::ArchName::kArchX86_SLEIGH);

  LiftingTester x86_base_tester(&context, remill::OSName::kOSLinux,
                                remill::ArchName::kArchX86);
  std::string_view insn_data("\x01\xca", 2);
  auto func1 =
      sleighx86tester.LiftInstructionFunction("add_diff_sleigh", insn_data, 0);

  EXPECT_TRUE(func1.has_value());

  LOG(INFO) << remill::LLVMThingToString(*func1);

  auto func2 =
      x86_base_tester.LiftInstructionFunction("add_diff_x86", insn_data, 0);

  EXPECT_TRUE(func2.has_value());

  LOG(INFO) << remill::LLVMThingToString(*func2);
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
