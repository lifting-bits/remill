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
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/AArch32/ArchContext.h>
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>
#include <test_runner/TestRunner.h>

#include <functional>
#include <random>
#include <sstream>
#include <variant>

#include "gtest/gtest.h"
#include "test_runner/TestOutputSpec.h"


namespace {

const static std::unordered_map<
    std::string, std::function<test_runner::RegisterValueRef(AArch32State &)>>
    reg_to_accessor = {
        {"r15",
         [](AArch32State &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r15.dword;
         }},
        {"sp",
         [](AArch32State &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r13.dword;
         }},
        {"r1",
         [](AArch32State &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r1.dword;
         }},
        {"z", [](AArch32State &st) -> test_runner::RegisterValueRef {
           return &st.sr.z;
         }}};


std::optional<remill::Instruction> GetFlows(std::string_view bytes,
                                            uint64_t address, uint64_t tm_val) {

  llvm::LLVMContext context;
  auto arch = remill::Arch::Build(&context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchAArch32LittleEndian);
  auto sems = remill::LoadArchSemantics(arch.get());


  remill::DecodingContext dec_context;
  dec_context.UpdateContextReg(std::string(remill::kThumbModeRegName), tm_val);
  CHECK(dec_context.HasValueForReg("TMReg"));
  remill::Instruction insn;

  if (!arch->DecodeInstruction(address, bytes, insn, dec_context)) {
    return std::nullopt;
  } else {
    return insn;
  }
}
}  // namespace


using MemoryModifier = std::function<void(test_runner::MemoryHandler &)>;

struct RegisterPrecondition {
  std::string register_name;
  test_runner::RegisterValue enforced_value;
};

class TestOutputSpec {
 public:
  uint64_t addr;
  std::string target_bytes;

 private:
  remill::Instruction::Category expected_category;
  std::vector<RegisterPrecondition> register_preconditions;
  std::vector<RegisterPrecondition> register_postconditions;
  std::vector<MemoryModifier> initial_memory_conditions;

  template <typename T>
  void ApplyCondWithAcc(
      T value,
      std::function<test_runner::RegisterValueRef(AArch32State &)> accessor,
      AArch32State &state) const {
    *(std::get<T *>(accessor(state))) = value;
  }

  void ApplyCondition(AArch32State &state, std::string reg,
                      test_runner::RegisterValue value) const {
    auto accessor = reg_to_accessor.find(reg);

    if (accessor == reg_to_accessor.end()) {
      return;
    }
    LOG(INFO) << "applying for " << reg;

    std::visit(
        [&](auto arg) { ApplyCondWithAcc(arg, accessor->second, state); },
        value);
  }


  template <typename T>
  void CheckRegEq(
      T value,
      std::function<test_runner::RegisterValueRef(AArch32State &)> accessor,
      AArch32State &state) const {
    T sval = *(std::get<T *>(accessor(state)));
    LOG(INFO) << "state value: " << sval;
    CHECK_EQ(sval, value);
  }

  void CheckCondition(AArch32State &state, std::string reg,
                      test_runner::RegisterValue value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor == reg_to_accessor.end()) {
      return;
    }
    std::visit([&](auto arg) { CheckRegEq(arg, accessor->second, state); },
               value);
  }

 public:
  template <typename T>
  void AddPrecWrite(uint64_t addr, T value) {
    this->initial_memory_conditions.push_back(
        [addr, value](test_runner::MemoryHandler &mem_hand) {
          mem_hand.WriteMemory(addr, value);
        });
  }

  const std::vector<MemoryModifier> &GetMemoryPrecs() const {
    return this->initial_memory_conditions;
  }

  TestOutputSpec(uint64_t disas_addr, std::string target_bytes,
                 remill::Instruction::Category expected_category,
                 std::vector<RegisterPrecondition> register_preconditions,
                 std::vector<RegisterPrecondition> register_postconditions)
      : addr(disas_addr),
        target_bytes(target_bytes),
        expected_category(expected_category),
        register_preconditions(std::move(register_preconditions)),
        register_postconditions(std::move(register_postconditions)) {}


  void SetupTestPreconditions(AArch32State &state) const {
    for (auto prec : this->register_preconditions) {
      this->ApplyCondition(state, prec.register_name, prec.enforced_value);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) const {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(AArch32State &state) const {
    for (auto post : this->register_postconditions) {
      this->CheckCondition(state, post.register_name, post.enforced_value);
    }
  }
};

class TestSpecRunner {
 private:
  test_runner::LiftingTester lifter;
  uint64_t tst_ctr;
  test_runner::random_bytes_engine rbe;
  llvm::endianness endian;

 public:
  TestSpecRunner(llvm::LLVMContext &context, remill::ArchName name)
      : lifter(test_runner::LiftingTester(context, remill::OSName::kOSLinux,
                                          name)),
        tst_ctr(0),
        endian(lifter.GetArch()->MemoryAccessIsLittleEndian()
                   ? llvm::endianness::little
                   : llvm::endianness::big) {}

  void RunTestSpec(const TestOutputSpec &test) {
    std::stringstream ss;
    ss << "test_disas_func_" << this->tst_ctr++;

    auto maybe_func =
        lifter.LiftInstructionFunction(ss.str(), test.target_bytes, test.addr);


    CHECK(maybe_func.has_value());
    auto lifted_func = maybe_func->first;

    auto new_mod = llvm::CloneModule(*lifted_func->getParent());
    remill::OptimizeBareModule(new_mod.get());

    auto just_func_mod =
        std::make_unique<llvm::Module>("", new_mod->getContext());

    auto new_func = test_runner::CopyFunctionIntoNewModule(
        just_func_mod.get(), lifted_func, new_mod);
    AArch32State st = {};


    test.CheckLiftedInstruction(maybe_func->second);
    test_runner::RandomizeState(st, this->rbe);

    st.sr.z = test_runner::random_boolean_flag(this->rbe);
    st.sr.c = test_runner::random_boolean_flag(this->rbe);
    st.sr.v = test_runner::random_boolean_flag(this->rbe);
    st.sr.z = test_runner::random_boolean_flag(this->rbe);
    st.sr.n = test_runner::random_boolean_flag(this->rbe);

    test.SetupTestPreconditions(st);
    auto mem_hand = std::make_unique<test_runner::MemoryHandler>(this->endian);

    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(*mem_hand);
    }

    test_runner::ExecuteLiftedFunction<AArch32State>(
        new_func, test.target_bytes.length(), &st, mem_hand.get(),
        [](AArch32State *st) { return st->gpr.r15.dword; });

    LOG(INFO) << "Pc after execute " << st.gpr.r15.dword;
    test.CheckResultingState(st);
  }
};

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  return RUN_ALL_TESTS();
}


TEST(ThumbRandomizedLifts, PopPC) {

  llvm::LLVMContext curr_context;
  std::string insn_data("\x00\xbd", 2);
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryFunctionReturn,
      {{"r15", uint32_t(12)}, {"sp", uint32_t(10)}}, {{"r15", uint32_t(16)}});
  spec.AddPrecWrite<uint32_t>(10, 16);
  llvm::LLVMContext context;

  TestSpecRunner runner(context, remill::ArchName::kArchThumb2LittleEndian);
  runner.RunTestSpec(spec);
}


TEST(ArmRandomizedLifts, RelPcTest) {
  llvm::LLVMContext curr_context;
  std::string insn_data("\x0c\x10\x9f\xe5", 4);
  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryNormal,
                      {{"r15", uint32_t(0x12)}}, {{"r1", 0xdeadc0de}});
  // So ok instruction is at 18 which means pc is = 26
  spec.AddPrecWrite<uint32_t>(38, 0xdeadc0de);
  llvm::LLVMContext context;

  TestSpecRunner runner(context, remill::ArchName::kArchAArch32LittleEndian);
  runner.RunTestSpec(spec);
}

TEST(ThumbRandomizedLifts, RelPcTest) {

  llvm::LLVMContext curr_context;
  std::string insn_data("\x03\x49", 2);
  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryNormal,
                      {{"r15", uint32_t(0x12)}}, {{"r1", 0xdeadc0de}});
  // So ok instruction is at 18 which means pc is = 22
  spec.AddPrecWrite<uint32_t>(32, 0xdeadc0de);
  llvm::LLVMContext context;

  TestSpecRunner runner(context, remill::ArchName::kArchThumb2LittleEndian);
  runner.RunTestSpec(spec);
}

TEST(RegressionTests, RegressionPreffixSuffixInsn) {

  llvm::LLVMContext curr_context;
  std::string insn_data("\x3f\xf4\x53\xaf", 4);
  TestOutputSpec spec(
      0x00014182, insn_data,
      remill::Instruction::Category::kCategoryConditionalBranch,
      {{"z", uint8_t(1)}, {"r15", uint32_t(0x14186)}},
      // since we jump to 0001402c we are going to be 4 bytes ahead at 0x14030
      {{"r15", uint32_t(0x14030)}});

  llvm::LLVMContext context;

  TestSpecRunner runner(context, remill::ArchName::kArchThumb2LittleEndian);
  runner.RunTestSpec(spec);
}

TEST(RegressionTests, AARCH64RegSize) {
  llvm::LLVMContext context;
  auto arch = remill::Arch::Build(&context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchAArch64LittleEndian);
  auto sems = remill::LoadArchSemantics(arch.get());
  remill::IntrinsicTable instrinsics(sems.get());
  auto op_lifter = arch->DefaultLifter(instrinsics);
  auto target_lift = arch->DefineLiftedFunction("test_lift", sems.get());
  auto st_ptr = remill::LoadStatePointer(target_lift);
  CHECK_NOTNULL(st_ptr);
  auto lifted =
      op_lifter->LoadRegValue(&target_lift->getEntryBlock(), st_ptr, "W0");

  CHECK_EQ(lifted->getType()->getIntegerBitWidth(), 32);
  op_lifter->ClearCache();
  auto lifted2 =
      op_lifter->LoadRegValue(&target_lift->getEntryBlock(), st_ptr, "W0");

  CHECK_EQ(lifted2->getType()->getIntegerBitWidth(), 32);
}
TEST(RegressionTests, Armv8FPSCR) {
  llvm::LLVMContext context;
  auto arch = remill::Arch::Build(&context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchAArch32LittleEndian);
  CHECK_NOTNULL(arch->RegisterByName("FPSCR"));
}


/* These tests are transcribed from the behaviors described in: A2.3.1

  MOV(reg, thumb) ignores last bit, but does not mode-switch

  Thumb -> Thumb (1, mov pc, r1) -> {true: 1}

  B always remains in the same state:
  Arm -> Arm (0, b 4) -> {true: 0}
  Arm -> Arm (0, b 0) -> {true: 0}

  Thumb -> Thumb (1, b 4) -> {true: 1}
  Thumb -> Thumb (1, b 0) -> {true: 1}

  BLX immediate always changes, but is interprocedural so we keep the state the same
  Arm -> Arm (0, blx 1) -> {true: 0}
  Thumb -> Thumb (1, blx 1) -> {true: 1}

  Indirects (LDR, MOV(reg,ARM), BX):

  Arm -> (Thumb/Arm) (0, LDR PC, [r0]) -> {true: non_constant}
  Arm -> (Thumb/Arm) (0, BX r1) -> {true: non_constant}
  Thumb -> (Thumb/Arm) (1, LDR PC, [0]) -> {true: non_constant}
  Thumb -> (Thumb/Arm) (1, BX r1) -> {true: non_constant}

  Arm only
  Arm -> (Thumb/Arm) (0, mov pc, r1) -> {true: non_constant}



  Same but with conditionals:


  B always remains in the same state:
  Arm -> Arm (0, bne 4) -> {true: 0}
  Arm -> Arm (0, bne 0) -> {true: 0}
\

  BLX immediate always changes, but is interprocedural so we keep the state the same
  Arm -> Arm (0, blxne 1) -> {true: 0}

  Indirects (LDR, MOV(reg,ARM), BX):

  Arm -> (Thumb/Arm) (0, LDRNE PC, [r0]) -> {!=branch_not_taken_pc: non_constant, ==branch_not_taken_pc: 0}
  Arm -> (Thumb/Arm) (0, BXNE r1) -> {!=branch_not_taken_pc: non_constant, ==branch_not_taken_pc: 0}

  Arm only
  Arm -> (Thumb/Arm) (0, movne pc, r1) -> {!=branch_not_taken_pc: non_constant, ==branch_not_taken_pc: 0}

*/

/*
TEST(ArmContextTests, ThumbMovIgnoresAnyStateChange) {
  //mov pc, r1
  std::string insn_data("\x8f\x46", 2);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_TRUE(map(0xdeadbee2).GetContextValue(remill::kThumbModeRegName));
  EXPECT_TRUE(map(0x100).GetContextValue(remill::kThumbModeRegName));
}


TEST(ArmContextTests, ArmBStaysInArmAligned1) {
  // b 0
  std::string insn_data("\xfe\xff\xff\xea", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0x0).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmBStaysInArmAligned2) {
  // b 4
  std::string insn_data("\xff\xff\xff\xea", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0x4).GetContextValue(remill::kThumbModeRegName));
}


TEST(ArmContextTests, ThumbBStaysInThumbAligned1) {
  // b 0
  std::string insn_data("\xfe\xe7", 2);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_TRUE(map(0x0).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ThumbBStaysInThumbAligned2) {
  // b 4
  std::string insn_data("\x00\xe0", 2);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_TRUE(map(0x4).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmBLXInterProcStaysInSameMode) {
  // blx 4
  std::string insn_data("\xff\xff\xff\xfa", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ThumbBLXInterProcStaysInSameMode) {
  // blx 4
  std::string insn_data("\x00\xf0\x00\xe8", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_TRUE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmLDRIndirect) {
  // ldr pc, [r0]
  std::string insn_data("\x00\xf0\x90\xe5", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).HasValueForReg(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmBXIndirect) {
  // bx r1
  std::string insn_data("\x11\xff\x2f\xe1", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).HasValueForReg(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}


TEST(ArmContextTests, ThumbLDRIndirect) {
  // ldr pc, [r0]
  std::string insn_data("\xd0\xf8\x00\xf0", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).HasValueForReg(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ThumbBXIndirect) {
  // bx r1
  std::string insn_data("\x08\x47", 2);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee2).HasValueForReg(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmMovPCIndirectDoesAllowModeSwitch) {
  // mov pc, r1
  std::string insn_data("\x01\xf0\xa0\xe1", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).HasValueForReg(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}


// Conditionals


TEST(ArmContextTests, ArmBStaysInArmConditionalAligned1) {
  // bne 0
  std::string insn_data("\xfe\xff\xff\x1a", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0x0).GetContextValue(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmBStaysInArmConditionalAligned2) {
  // bne 4
  std::string insn_data("\xff\xff\xff\x1a", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0x0).GetContextValue(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmLDRIndirectConditional) {
  // ldrne pc, [r0]
  std::string insn_data("\x00\xf0\x90\x15", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmBXIndirectConditional) {
  // bxne r1
  std::string insn_data("\x11\xff\x2f\x11", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}

TEST(ArmContextTests, ArmMovPCIndirectDoesAllowModeSwitchConditional) {
  // movne pc, r1
  std::string insn_data("\x01\xf0\xa0\x11", 4);

  auto maybe_map = GetSuccessorContext(insn_data, 0xdeadbee0, 0);
  ASSERT_TRUE(maybe_map.has_value());
  auto map = *maybe_map;

  EXPECT_FALSE(map(0xdeadbee4).GetContextValue(remill::kThumbModeRegName));
  EXPECT_FALSE(map(0x1000).HasValueForReg(remill::kThumbModeRegName));
}
*/

// Two things we need to test: correct categories and when we lift, the branch taken var is set appropriately


TEST(ArmContextTests, ThumbBXIndirect) {
  // bx r1
  std::string insn_data("\x08\x47", 2);

  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto flow = *maybe_flow;

  remill::Instruction::InstructionFlowCategory jmp =
      remill::Instruction::IndirectJump(
          remill::Instruction::IndirectFlow(std::nullopt));


  remill::Instruction::IndirectJump str =
      std::get<remill::Instruction::IndirectJump>(flow.flows);

  EXPECT_FALSE(str.taken_flow.maybe_context.has_value());


  EXPECT_EQ(flow.flows, jmp);
}

TEST(ArmContextTests, ThumbMovIgnoresAnyStateChange) {
  //mov pc, r1
  std::string insn_data("\x8f\x46", 2);

  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto flow = *maybe_flow;


  remill::Instruction::InstructionFlowCategory jmp =
      remill::Instruction::IndirectJump(
          remill::Instruction::IndirectFlow(remill::kThumbContext));


  remill::Instruction::IndirectJump str =
      std::get<remill::Instruction::IndirectJump>(flow.flows);

  EXPECT_TRUE(str.taken_flow.maybe_context.has_value());


  remill::Instruction::IndirectJump str2 =
      std::get<remill::Instruction::IndirectJump>(jmp);

  EXPECT_TRUE(str2.taken_flow.maybe_context.has_value());

  EXPECT_EQ(flow.flows, jmp);
}

TEST(ArmContextTests, ThumbBLXInterProcStaysInSameMode) {
  // blx 4
  std::string insn_data("\x00\xf0\x00\xe8", 4);

  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto flow = *maybe_flow;

  remill::Instruction::InstructionFlowCategory jmp =
      remill::Instruction::DirectFunctionCall(
          remill::Instruction::DirectFlow(0xdeadbee0, remill::kARMContext));
}


TEST(ArmContextTests, ThumbBLStaysInSameContext) {
  // bl 1b528
  std::string insn_data("\x05\xf0\x74\xfc", 4);

  auto maybe_flow = GetFlows(insn_data, 0x1596c, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto act_insn = *maybe_flow;


  remill::Instruction::InstructionFlowCategory jmp =
      remill::Instruction::DirectFunctionCall(
          remill::Instruction::DirectFlow(0x1b258, remill::kThumbContext));

  auto dfcall =
      std::get<remill::Instruction::DirectFunctionCall>(act_insn.flows);


  EXPECT_EQ(0x0001b258, dfcall.taken_flow.known_target);

  EXPECT_EQ(remill::kThumbContext, dfcall.taken_flow.static_context);

  EXPECT_EQ(jmp, act_insn.flows);

  EXPECT_EQ(0x00015970, act_insn.next_pc);
}


TEST(ArmContextTests, ThumbBPLRegressionTest) {
  // bpl     #0x135e0
  std::string insn_data("\x7f\xf5\x70\xae", 4);

  auto maybe_flow = GetFlows(insn_data, 0x000138fc, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto act_insn = *maybe_flow;


  remill::Instruction::InstructionFlowCategory expect_cond_flow =
      remill::Instruction::ConditionalInstruction(
          remill::Instruction::DirectJump(
              remill::Instruction::DirectFlow(0x135e0, remill::kThumbContext)),
          remill::Instruction::FallthroughFlow(remill::kThumbContext));

  auto act_cond_insn_flow =
      std::get<remill::Instruction::ConditionalInstruction>(act_insn.flows);

  EXPECT_EQ(expect_cond_flow, act_insn.flows);
}
