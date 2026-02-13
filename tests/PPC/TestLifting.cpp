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

#include <gtest/gtest.h>
#include <llvm/IR/LLVMContext.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/Arch/PPC/Runtime/State.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>
#include <test_runner/TestOutputSpec.h>
#include <test_runner/TestRunner.h>

#include <unordered_map>

namespace {

const static std::unordered_map<
    std::string, std::function<test_runner::RegisterValueRef(PPCState &)>>
    reg_to_accessor = {
        {"pc",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.pc.qword;
         }},
        {"r0",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r0.qword;
         }},
        {"r1",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r1.qword;
         }},
        {"r2",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r2.qword;
         }},
        {"r3",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r3.qword;
         }},
        {"_r3", [](PPCState &st) -> uint32_t * { return &st.gpr.r3.lo_bits; }},
        {"_r4", [](PPCState &st) -> uint32_t * { return &st.gpr.r4.lo_bits; }},
        {"_r5", [](PPCState &st) -> uint32_t * { return &st.gpr.r5.lo_bits; }},
        {"r4",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r4.qword;
         }},
        {"r5",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r5.qword;
         }},
        {"r6",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r6.qword;
         }},
        {"r7",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r7.qword;
         }},
        {"r8",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r8.qword;
         }},
        {"r9",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r9.qword;
         }},
        {"r10",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r10.qword;
         }},
        {"r11",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r11.qword;
         }},
        {"r12",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.gpr.r12.qword;
         }},
        {"cr",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.iar.cr.qword;
         }},
        {"cr0",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr0;
         }},
        {"cr1",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr1;
         }},
        {"cr2",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr2;
         }},
        {"cr3",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr3;
         }},
        {"cr4",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr4;
         }},
        {"cr5",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr5;
         }},
        {"cr6",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr6;
         }},
        {"cr7",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.cr_flags.cr7;
         }},
        {"lr",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.iar.lr.qword;
         }},
        {"ctr",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.iar.ctr.qword;
         }},
        {"xer",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.iar.xer.qword;
         }},
        {"xer_so",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.xer_flags.so;
         }},
        {"xer_ov",
         [](PPCState &st) -> test_runner::RegisterValueRef {
           return &st.xer_flags.ov;
         }},
};

std::optional<remill::Instruction>
GetFlows(std::string_view bytes, uint64_t address, uint64_t vle_val) {

  llvm::LLVMContext context;
  auto arch = remill::Arch::Build(&context, remill::OSName::kOSLinux,
                                  remill::ArchName::kArchPPC);
  auto sems = remill::LoadArchSemantics(arch.get());


  remill::DecodingContext dec_context;
  dec_context.UpdateContextReg(std::string("VLEReg"), vle_val);
  CHECK(dec_context.HasValueForReg("VLEReg"));
  remill::Instruction insn;

  if (!arch->DecodeInstruction(address, bytes, insn, dec_context)) {
    return std::nullopt;
  } else {
    return insn;
  }
}
}  // namespace

using test_runner::TestOutputSpec;

template <typename S, typename = test_runner::EnableIfState<S>>
class TestSpecRunner {
 private:
  test_runner::LiftingTester lifter;
  uint64_t tst_ctr;
  test_runner::random_bytes_engine rbe;
  llvm::endianness endian;

 public:
  TestSpecRunner(llvm::LLVMContext &context)
      : lifter(test_runner::LiftingTester(context, remill::OSName::kOSLinux,
                                          remill::kArchPPC)),
        tst_ctr(0),
        endian(lifter.GetArch()->MemoryAccessIsLittleEndian()
                   ? llvm::endianness::little
                   : llvm::endianness::big) {}

  void RunTestSpec(const TestOutputSpec<S> &test,
                   const remill::DecodingContext &dec_ctx) {
    std::stringstream ss;
    ss << "test_disas_func_" << this->tst_ctr++;

    auto maybe_func = lifter.LiftInstructionFunction(
        ss.str(), test.target_bytes, test.addr, dec_ctx);

    CHECK(maybe_func.has_value());
    auto lifted_func = maybe_func->first;

    // Copy lifted function into new module to optimize out intrinsics that aren't used in the lifted function
    auto new_mod = llvm::CloneModule(*lifted_func->getParent());
    remill::OptimizeBareModule(new_mod.get());

    auto just_func_mod =
        std::make_unique<llvm::Module>("", new_mod->getContext());

    auto new_func = test_runner::CopyFunctionIntoNewModule(
        just_func_mod.get(), lifted_func, new_mod);
    S st = {};

    test.CheckLiftedInstruction(maybe_func->second);
    test_runner::RandomizeState(st, this->rbe);

    test.SetupTestPreconditions(st);
    auto mem_hand = std::make_unique<test_runner::MemoryHandler>(this->endian);

    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(*mem_hand);
    }

    test_runner::ExecuteLiftedFunction<S>(new_func, test.target_bytes.length(),
                                          &st, mem_hand.get(),
                                          [](S *st) { return st->pc.qword; });

    LOG(INFO) << "Pc after execute " << st.pc.qword;
    test.CheckResultingState(st);

    test.CheckResultingMemory(*mem_hand);
  }
};

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  return RUN_ALL_TESTS();
}


inline const remill::DecodingContext kVLEContext =
    remill::DecodingContext({{std::string("VLEReg"), 1}});

// Add two registers
TEST(PPCVLELifts, PPCVLEAdd) {
  llvm::LLVMContext curr_context;
  // add r5, r4, r3
  std::string insn_data("\x7C\xA4\x1A\x14", 4);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"r4", uint64_t(0xcc)}, {"r3", uint64_t(0xdd)}, {"pc", uint64_t(0x12)}},
      {{"r5", uint64_t(0x1a9)}, {"pc", uint64_t(0x16)}}, reg_to_accessor);
  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Divide two registers
TEST(PPCVLELifts, PPCVLEDiv) {
  llvm::LLVMContext curr_context;
  // div r5, r4, r3
  std::string insn_data("\x7c\xa4\x1b\x96", 4);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"_r4", uint32_t(0xcc)}, {"_r3", uint32_t(0x7)}, {"pc", uint64_t(0x12)}},
      {{"r5", uint64_t(0x1d)},
       {"_r4", uint32_t(0xcc)},
       {"_r3", uint32_t(0x7)},
       {"pc", uint64_t(0x16)}},
      reg_to_accessor);
  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Add two registers and record
TEST(PPCVLELifts, PPCVLEAddRecord) {
  llvm::LLVMContext curr_context;
  // add. r5, r4, r3
  // result is positive so cr0[1] is set which is the third bit in little endian
  std::string insn_data("\x7C\xA4\x1A\x15", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"r4", uint64_t(0xcc)},
                                 {"r3", uint64_t(0xdd)},
                                 {"cr0", uint8_t(0)},
                                 {"xer_so", uint8_t(0x0)},
                                 {"pc", uint64_t(0x12)}},
                                {{"r5", uint64_t(0x1a9)},
                                 {"cr0", uint8_t(0b100)},
                                 {"xer_so", uint8_t(0x0)},
                                 {"pc", uint64_t(0x16)}},
                                reg_to_accessor);
  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Add two registers and set overflow
TEST(PPCVLELifts, PPCVLEAddOverflow) {
  llvm::LLVMContext curr_context;
  // addo r5, r4, r3
  std::string insn_data("\x7C\xA4\x1E\x14", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"r4", uint64_t(5000000000000000000)},
                                 {"r3", uint64_t(5000000000000000000)},
                                 {"xer_ov", uint8_t(0x0)},
                                 {"xer_so", uint8_t(0x0)},
                                 {"pc", uint64_t(0x12)}},
                                {{"r5", uint64_t(0x8ac7230489e80000)},
                                 {"xer_ov", uint8_t(0x1)},
                                 {"xer_so", uint8_t(0x1)},
                                 {"pc", uint64_t(0x16)}},
                                reg_to_accessor);
  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE short Branch to Link Register
TEST(PPCVLELifts, PPCVLEBranchLinkRegister) {
  llvm::LLVMContext curr_context;
  // se_blr
  std::string insn_data("\x00\x04", 2);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryFunctionReturn,
      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x12)}},
      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x4)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE short Branch to Link Register and Link
TEST(PPCVLELifts, PPCVLEBranchLinkRegisterAndLink) {
  llvm::LLVMContext curr_context;
  // se_blrl
  std::string insn_data("\x00\x05", 2);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryFunctionReturn,
      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x12)}},
      {{"lr", uint64_t(0x14)}, {"pc", uint64_t(0x4)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE long relative branch that branches to negative relative offset
TEST(PPCVLELifts, PPCVLENegBranch) {
  llvm::LLVMContext curr_context;
  // e_b 0xfffffffa (-0x6)
  std::string insn_data("\x79\xff\xff\xfa", 4);
  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto act_insn = *maybe_flow;

  remill::Instruction::InstructionFlowCategory expected_condjmp =
      remill::Instruction::DirectJump(
          remill::Instruction::DirectFlow(0xdeadbee0 - 0x6, kVLEContext));

  auto actual_condjmp =
      std::get<remill::Instruction::DirectJump>(act_insn.flows);

  EXPECT_EQ(expected_condjmp, act_insn.flows);

  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint64_t(0x10)}}, {{"pc", uint64_t(0xa)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE long relative conditional branch
TEST(PPCVLELifts, PPCVLECondBranch) {
  llvm::LLVMContext curr_context;
  // e_beq 0xfffffffa (-0x6)
  std::string insn_data("\x7a\x12\xff\xfa", 4);
  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto act_insn = *maybe_flow;

  remill::Instruction::InstructionFlowCategory expected_condjmp =
      remill::Instruction::ConditionalInstruction(
          remill::Instruction::DirectJump(
              remill::Instruction::DirectFlow(0xdeadbee0 - 0x6, kVLEContext)),
          remill::Instruction::FallthroughFlow(kVLEContext));

  auto actual_condjmp =
      std::get<remill::Instruction::ConditionalInstruction>(act_insn.flows);

  EXPECT_EQ(expected_condjmp, act_insn.flows);

  TestOutputSpec<PPCState> spec(
      0x12, insn_data,
      remill::Instruction::Category::kCategoryConditionalBranch,
      {{"pc", uint64_t(0x10)}, {"cr0", uint8_t(0b10)}},
      {{"pc", uint64_t(0xa)}, {"cr0", uint8_t(0b10)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE long relative conditional branch
TEST(PPCVLELifts, PPCVLECondBranch2) {
  llvm::LLVMContext curr_context;
  // e_beq 0xfffffffa (-0x6)
  std::string insn_data("\x7a\x12\xff\xfa", 4);
  auto maybe_flow = GetFlows(insn_data, 0xdeadbee0, 1);
  ASSERT_TRUE(maybe_flow.has_value());
  auto act_insn = *maybe_flow;

  remill::Instruction::InstructionFlowCategory expected_condjmp =
      remill::Instruction::ConditionalInstruction(
          remill::Instruction::DirectJump(
              remill::Instruction::DirectFlow(0xdeadbee0 - 0x6, kVLEContext)),
          remill::Instruction::FallthroughFlow(kVLEContext));

  auto actual_condjmp =
      std::get<remill::Instruction::ConditionalInstruction>(act_insn.flows);

  EXPECT_EQ(expected_condjmp, act_insn.flows);

  TestOutputSpec<PPCState> spec(
      0x12, insn_data,
      remill::Instruction::Category::kCategoryConditionalBranch,
      {{"pc", uint64_t(0x10)}, {"cr0", uint8_t(0b0)}},
      {{"pc", uint64_t(0x14)}, {"cr0", uint8_t(0b0)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE long relative branch
TEST(PPCVLELifts, PPCVLEBranch) {
  llvm::LLVMContext curr_context;
  // e_b 0x5a
  std::string insn_data("\x78\x00\x00\x5a", 4);
  // offset PC by 0x1000012 to also test that relative PC lifting works correctly
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint64_t(0x1000012)}}, {{"pc", uint64_t(0x1000012 + 0x5a)}},
      reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE short compare immediate
TEST(PPCVLELifts, PPCVLECompareImmediate) {
  llvm::LLVMContext curr_context;
  // se_cmpi r7, 0x0
  std::string insn_data("\x2a\x07", 2);
  // cr1[2], set when result is zero
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r7", uint64_t(0x0)},
                                 {"xer_so", uint8_t(0)},
                                 {"cr0", uint8_t(0)}},
                                {{"pc", uint64_t(0x12 + 2)},
                                 {"xer_so", uint8_t(0)},
                                 {"cr0", uint8_t(0b10)}},
                                reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE Store word
TEST(PPCVLELifts, PPCVLEStoreWord) {
  llvm::LLVMContext curr_context;
  // e_stw r5, 0x10(r4)
  std::string insn_data("\x54\xa4\x00\x10", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"_r5", uint32_t(0x13371337)},
                                 {"r4", uint64_t(0xdeadbee0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"_r5", uint32_t(0x13371337)},
                                 {"r4", uint64_t(0xdeadbee0)}},
                                reg_to_accessor);
  spec.AddPrecWrite<uint32_t>(0xdeadbee0 + 0x10, 0x0);
  spec.AddPostRead<uint32_t>(0xdeadbee0 + 0x10, 0x13371337);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Load immediate
TEST(PPCVLELifts, PPCVLELoadImmediate) {
  llvm::LLVMContext curr_context;
  // se_li r7, 0x7
  std::string insn_data("\x48\x77", 2);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x12)}, {"r7", uint64_t(0x0)}},
      {{"pc", uint64_t(0x14)}, {"r7", uint64_t(0x7)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Load word and zero
TEST(PPCVLELifts, PPCVLELoadWordAndZero) {
  llvm::LLVMContext curr_context;
  // e_lwz r5, 0x10(r4)
  std::string insn_data("\x50\xa4\x00\x10", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r5", uint64_t(0x0)},
                                 {"r4", uint64_t(0xdeadbee0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"r5", uint64_t(0x13371337)},
                                 {"r4", uint64_t(0xdeadbee0)}},
                                reg_to_accessor);
  spec.AddPrecWrite<uint32_t>(0xdeadbee0 + 0x10, 0x13371337);
  spec.AddPostRead<uint32_t>(0xdeadbee0 + 0x10, 0x13371337);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE Load Multiple Volatile General Purpose Registers
// Instruction only operates on the 32bit register sizes
TEST(PPCVLELifts, PPCVLELoadMultipleGeneralPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_ldmvgprw 0x0(r1)
  std::string insn_data("\x18\x01\x10\x00", 4);

  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r1", uint64_t(0x13370)},
                                 {"r0", uint64_t(0x0)},
                                 {"r3", uint64_t(0x0)},
                                 {"r4", uint64_t(0x0)},
                                 {"r5", uint64_t(0x0)},
                                 {"r6", uint64_t(0x0)},
                                 {"r7", uint64_t(0x0)},
                                 {"r8", uint64_t(0x0)},
                                 {"r9", uint64_t(0x0)},
                                 {"r10", uint64_t(0x0)},
                                 {"r11", uint64_t(0x0)},
                                 {"r12", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"r1", uint64_t(0x13370)},
                                 {"r0", uint64_t(0x11223344)},
                                 {"r3", uint64_t(0x22114433)},
                                 {"r4", uint64_t(0x99aabbcc)},
                                 {"r5", uint64_t(0xaa99ccbb)},
                                 {"r6", uint64_t(0x88776655)},
                                 {"r7", uint64_t(0x77885566)},
                                 {"r8", uint64_t(0x00ffeedd)},
                                 {"r9", uint64_t(0xff00ddee)},
                                 {"r10", uint64_t(0x44332211)},
                                 {"r11", uint64_t(0xccbbaa99)},
                                 {"r12", uint64_t(0xbbcc99aa)}},
                                reg_to_accessor);
  spec.AddPrecWrite<uint32_t>(0x13370, 0x11223344);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x4, 0x22114433);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0xc, 0xaa99ccbb);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x10, 0x88776655);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x14, 0x77885566);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x18, 0x00ffeedd);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x1c, 0xff00ddee);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x20, 0x44332211);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x24, 0xccbbaa99);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x28, 0xbbcc99aa);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE Store Multiple Volatile General Purpose Registers
TEST(PPCVLELifts, PPCVLEStoreMultipleGeneralPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_stmvgprw 0x0(r1)
  std::string insn_data("\x18\x01\x11\x00", 4);

  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r1", uint64_t(0x13370)},
                                 {"r0", uint64_t(0x11223344)},
                                 {"r3", uint64_t(0x22114433)},
                                 {"r4", uint64_t(0x99aabbcc)},
                                 {"r5", uint64_t(0xaa99ccbb)},
                                 {"r6", uint64_t(0x88776655)},
                                 {"r7", uint64_t(0x77885566)},
                                 {"r8", uint64_t(0x00ffeedd)},
                                 {"r9", uint64_t(0xff00ddee)},
                                 {"r10", uint64_t(0x44332211)},
                                 {"r11", uint64_t(0xccbbaa99)},
                                 {"r12", uint64_t(0xbbcc99aa)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"r1", uint64_t(0x13370)},
                                 {"r0", uint64_t(0x11223344)},
                                 {"r3", uint64_t(0x22114433)},
                                 {"r4", uint64_t(0x99aabbcc)},
                                 {"r5", uint64_t(0xaa99ccbb)},
                                 {"r6", uint64_t(0x88776655)},
                                 {"r7", uint64_t(0x77885566)},
                                 {"r8", uint64_t(0x00ffeedd)},
                                 {"r9", uint64_t(0xff00ddee)},
                                 {"r10", uint64_t(0x44332211)},
                                 {"r11", uint64_t(0xccbbaa99)},
                                 {"r12", uint64_t(0xbbcc99aa)}},
                                reg_to_accessor);
  spec.AddPostRead<uint32_t>(0x13370, 0x11223344);
  spec.AddPostRead<uint32_t>(0x13370 + 0x4, 0x22114433);
  spec.AddPostRead<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPostRead<uint32_t>(0x13370 + 0xc, 0xaa99ccbb);
  spec.AddPostRead<uint32_t>(0x13370 + 0x10, 0x88776655);
  spec.AddPostRead<uint32_t>(0x13370 + 0x14, 0x77885566);
  spec.AddPostRead<uint32_t>(0x13370 + 0x18, 0x00ffeedd);
  spec.AddPostRead<uint32_t>(0x13370 + 0x1c, 0xff00ddee);
  spec.AddPostRead<uint32_t>(0x13370 + 0x20, 0x44332211);
  spec.AddPostRead<uint32_t>(0x13370 + 0x24, 0xccbbaa99);
  spec.AddPostRead<uint32_t>(0x13370 + 0x28, 0xbbcc99aa);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE Load Multiple Volatile Special Purpose Registers
TEST(PPCVLELifts, PPCVLELoadMultipleSpecialPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_ldmvsprw 0x0(r1)
  std::string insn_data("\x18\x21\x10\x00", 4);

  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r1", uint64_t(0x13370)},
                                 {"cr", uint64_t(0x0)},
                                 {"cr0", uint8_t(0x0)},
                                 {"cr1", uint8_t(0x0)},
                                 {"cr2", uint8_t(0x0)},
                                 {"cr3", uint8_t(0x0)},
                                 {"cr4", uint8_t(0x0)},
                                 {"cr5", uint8_t(0x0)},
                                 {"cr6", uint8_t(0x0)},
                                 {"cr7", uint8_t(0x0)},
                                 {"lr", uint64_t(0x0)},
                                 {"ctr", uint64_t(0x0)},
                                 {"xer", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"r1", uint64_t(0x13370)},
                                 // each crN register is 4-bits
                                 {"cr0", uint8_t(0x1)},
                                 {"cr1", uint8_t(0x2)},
                                 {"cr2", uint8_t(0x3)},
                                 {"cr3", uint8_t(0x4)},
                                 {"cr4", uint8_t(0x5)},
                                 {"cr5", uint8_t(0x6)},
                                 {"cr6", uint8_t(0x7)},
                                 {"cr7", uint8_t(0x8)},
                                 {"lr", uint64_t(0x55667788)},
                                 {"ctr", uint64_t(0x99aabbcc)},
                                 {"xer", uint64_t(0xddeeff00)}},
                                reg_to_accessor);
  spec.AddPrecWrite<uint32_t>(0x13370, 0x87654321);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x4, 0x55667788);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0xc, 0xddeeff00);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// VLE Store Multiple Volatile Special Purpose Registers
// TODO(wtan): Disabled for now due to bug in Ghidra pcode for this instruction
TEST(PPCVLELifts, DISABLED_PPCVLEStoreMultipleSpecialPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_stmvsprw 0x0(r1)
  std::string insn_data("\x18\x21\x11\x00", 4);

  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"r1", uint64_t(0x13370)},
                                 {"cr", uint64_t(0x11223344)},
                                 {"lr", uint64_t(0x55667788)},
                                 {"ctr", uint64_t(0x99aabbcc)},
                                 {"cr0", uint8_t(0x1)},
                                 {"cr1", uint8_t(0x2)},
                                 {"cr2", uint8_t(0x3)},
                                 {"cr3", uint8_t(0x4)},
                                 {"cr4", uint8_t(0x5)},
                                 {"cr5", uint8_t(0x6)},
                                 {"cr6", uint8_t(0x7)},
                                 {"cr7", uint8_t(0x8)},
                                 {"xer", uint64_t(0xddeeff00)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"r1", uint64_t(0x13370)},
                                 {"cr0", uint8_t(0x1)},
                                 {"cr1", uint8_t(0x2)},
                                 {"cr2", uint8_t(0x3)},
                                 {"cr3", uint8_t(0x4)},
                                 {"cr4", uint8_t(0x5)},
                                 {"cr5", uint8_t(0x6)},
                                 {"cr6", uint8_t(0x7)},
                                 {"cr7", uint8_t(0x8)},
                                 {"lr", uint64_t(0x55667788)},
                                 {"ctr", uint64_t(0x99aabbcc)},
                                 {"xer", uint64_t(0xddeeff00)}},
                                reg_to_accessor);
  spec.AddPostRead<uint32_t>(0x13370, 0x87654321);
  spec.AddPostRead<uint32_t>(0x13370 + 0x4, 0x55667788);
  spec.AddPostRead<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPostRead<uint32_t>(0x13370 + 0xc, 0xddeeff00);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Rotate Left Word Immediate then AND with Mask
// Tests internal conditional branches in pcode
TEST(PPCVLELifts, PPCVLERotateLeftWordImmediateAndMask) {
  llvm::LLVMContext curr_context;
  // e_rlwinm r6, r5, 0x1e, 0x1d, 0x1f
  // n >> 2 & 7
  // (n & 31) >> 2
  std::string insn_data("\x74\xa6\xf7\x7f", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"_r5", uint32_t(0x1337)},
                                 {"r6", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"_r5", uint32_t(0x1337)},
                                 {"r6", uint64_t(0x5)}},
                                reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Convert Floating-Point Double-Precision from Signed Integer
TEST(PPCVLELifts, PPCVLEConvertDoubleFromSignedInteger) {
  llvm::LLVMContext curr_context;
  // efdcfsi r5, r4
  std::string insn_data("\x10\xa0\x22\xf1", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"_r4", uint32_t(0x1337)},
                                 {"r5", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"_r4", uint32_t(0x1337)},
                                 {"r5", uint64_t(0x40b3370000000000)}},
                                reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Convert Floating-Point Single-Precision from Signed Integer
TEST(PPCVLELifts, PPCVLEConvertFloatFromSignedInteger) {
  llvm::LLVMContext curr_context;
  // efscfsi r5, r4
  std::string insn_data("\x10\xa0\x22\xd1", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"_r4", uint32_t(0x1337)},
                                 {"r5", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"_r4", uint32_t(0x1337)},
                                 {"r5", uint64_t(0x4599b800)}},
                                reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Convert Floating-Point Single-Precision to Signed Integer
TEST(PPCVLELifts, PPCVLEConvertFloatToSignedInteger) {
  llvm::LLVMContext curr_context;
  // efsctsi r5, r4
  std::string insn_data("\x10\xa0\x22\xd5", 4);
  TestOutputSpec<PPCState> spec(0x12, insn_data,
                                remill::Instruction::Category::kCategoryNormal,
                                {{"pc", uint64_t(0x12)},
                                 {"_r4", uint32_t(0x4599b800)},
                                 {"r5", uint64_t(0x0)}},
                                {{"pc", uint64_t(0x12 + 4)},
                                 {"_r4", uint32_t(0x4599b800)},
                                 {"r5", uint64_t(0x1337)}},
                                reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}

// Test syscall
TEST(PPCVLELifts, PPCVLESyscall) {
  llvm::LLVMContext curr_context;
  // e_sc
  std::string insn_data("\x7c\x00\x00\x48", 4);
  TestOutputSpec<PPCState> spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x12)}}, {{"pc", uint64_t(0x12 + 4)}}, reg_to_accessor);

  TestSpecRunner<PPCState> runner(curr_context);
  runner.RunTestSpec(spec, kVLEContext);
}
