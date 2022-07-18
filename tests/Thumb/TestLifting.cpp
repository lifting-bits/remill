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
#include <test_runner/TestRunner.h>

#include <functional>
#include <random>
#include <sstream>

#include "gtest/gtest.h"


namespace {
const static std::unordered_map<std::string,
                                std::function<uint32_t &(AArch32State &)>>
    reg_to_accessor = {
        {"r15",
         [](AArch32State &st) -> uint32_t & { return st.gpr.r15.dword; }},
        {"sp", [](AArch32State &st) -> uint32_t & { return st.gpr.r13.dword; }},
        {"r1", [](AArch32State &st) -> uint32_t & { return st.gpr.r1.dword; }}};
}

class TestOutputSpec {
 public:
  uint64_t addr;
  std::string target_bytes;

 private:
  remill::Instruction::Category expected_category;
  std::vector<std::pair<std::string, uint32_t>> register_preconditions;
  std::vector<std::pair<std::string, uint32_t>> register_postconditions;
  std::vector<std::function<void(test_runner::MemoryHandler &)>>
      initial_memory_conditions;

  void ApplyCondition(AArch32State &state, std::string reg,
                      uint32_t value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      accessor->second(state) = value;
    }
  }

  void CheckCondition(AArch32State &state, std::string reg,
                      uint32_t value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      CHECK_EQ(accessor->second(state), value);
    }
  }

 public:
  template <typename T>
  void AddPrecWrite(uint64_t addr, T value) {
    this->initial_memory_conditions.push_back(
        [addr, value](test_runner::MemoryHandler &mem_hand) {
          mem_hand.WriteMemory(addr, value);
        });
  }

  const std::vector<std::function<void(test_runner::MemoryHandler &)>> &
  GetMemoryPrecs() const {
    return this->initial_memory_conditions;
  }

  TestOutputSpec(
      std::string target_bytes, remill::Instruction::Category expected_category,
      std::vector<std::pair<std::string, uint32_t>> register_preconditions,
      std::vector<std::pair<std::string, uint32_t>> register_postconditions)
      : target_bytes(target_bytes),
        expected_category(expected_category),
        register_preconditions(std::move(register_preconditions)),
        register_postconditions(std::move(register_postconditions)) {}


  void SetupTestPreconditions(AArch32State &state) const {
    for (auto prec : this->register_preconditions) {
      this->ApplyCondition(state, prec.first, prec.second);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) const {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(AArch32State &state) const {
    for (auto post : this->register_postconditions) {
      this->CheckCondition(state, post.first, post.second);
    }
  }
};

class TestSpecRunner {
 private:
  test_runner::LiftingTester lifter;
  uint64_t tst_ctr;
  test_runner::random_bytes_engine rbe;
  llvm::support::endianness endian;

 public:
  TestSpecRunner(llvm::LLVMContext &context)
      : lifter(test_runner::LiftingTester(
            context, remill::OSName::kOSLinux,
            remill::ArchName::kArchThumb2LittleEndian)),
        tst_ctr(0),
        endian(lifter.GetArch()->MemoryAccessIsLittleEndian()
                   ? llvm::support::endianness::little
                   : llvm::support::endianness::big) {}

  void RunTestSpec(const TestOutputSpec &test) {
    std::stringstream ss;
    ss << "test_disas_func_" << this->tst_ctr++;

    auto maybe_func =
        lifter.LiftInstructionFunction(ss.str(), test.target_bytes, test.addr);


    CHECK(maybe_func.has_value());
    auto lifted_func = maybe_func->first;

    auto new_mod = llvm::CloneModule(*lifted_func->getParent());
    remill::OptimizeBareModule(new_mod.get());

    auto justFuncMod =
        std::make_unique<llvm::Module>("", new_mod->getContext());

    auto new_func = test_runner::CopyFunctionIntoNewModule(
        justFuncMod.get(), lifted_func, new_mod);
    AArch32State *st = (AArch32State *) alloca(sizeof(AArch32State));


    test.CheckLiftedInstruction(maybe_func->second);
    test_runner::RandomizeState(st, this->rbe);

    st->sr.z = test_runner::random_boolean_flag(this->rbe);
    st->sr.c = test_runner::random_boolean_flag(this->rbe);
    st->sr.v = test_runner::random_boolean_flag(this->rbe);
    st->sr.z = test_runner::random_boolean_flag(this->rbe);
    st->sr.n = test_runner::random_boolean_flag(this->rbe);

    test.SetupTestPreconditions(*st);
    auto mem_hand = std::make_unique<test_runner::MemoryHandler>(this->endian);

    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(*mem_hand);
    }

    test_runner::ExecuteLiftedFunction<AArch32State, uint32_t>(
        new_func, test.target_bytes.length(), st, mem_hand.get(),
        [](AArch32State *st) { return st->gpr.r15.dword; });

    LOG(INFO) << "Pc after execute " << st->gpr.r15.dword;
    test.CheckResultingState(*st);
  }
};

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}


TEST(ThumbRandomizedLifts, PopPC) {

  llvm::LLVMContext curr_context;
  std::string insn_data("\x00\xbd", 2);
  //std::string insn_data("\x01\x10\x81\xe0");
  TestOutputSpec spec(insn_data,
                      remill::Instruction::Category::kCategoryFunctionReturn,
                      {{"r15", 12}, {"sp", 10}}, {{"r15", 16}});
  spec.AddPrecWrite<uint32_t>(10, 16);
  llvm::LLVMContext context;

  context.enableOpaquePointers();
  TestSpecRunner runner(context);
  runner.RunTestSpec(spec);
}
