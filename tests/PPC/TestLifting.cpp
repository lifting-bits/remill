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
#include <test_runner/TestRunner.h>

#include <unordered_map>

namespace {

const static std::unordered_map<std::string,
                                std::function<std::any(PPCState &)>>
    reg_to_accessor = {
        {"pc",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.pc.qword);
         }},
        {"r0",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r0.qword);
         }},
        {"r1",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r1.qword);
         }},
        {"r2",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r2.qword);
         }},
        {"r3",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r3.qword);
         }},
        {"r4",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r4.qword);
         }},
        {"r5",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r5.qword);
         }},
        {"r6",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r6.qword);
         }},
        {"r7",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r7.qword);
         }},
        {"r8",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r8.qword);
         }},
        {"r9",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return (st.gpr.r9.qword);
         }},
        {"r10",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.gpr.r10.qword;
         }},
        {"r11",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.gpr.r11.qword;
         }},
        {"r12",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.gpr.r12.qword;
         }},
        {"cr",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.iar.cr.qword;
         }},
        {"cr0",
         [](PPCState &st) -> std::reference_wrapper<uint8_t> {
           return st.cr_flags.cr0;
         }},
        {"lr",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.iar.lr.qword;
         }},
        {"ctr",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.iar.ctr.qword;
         }},
        {"xer",
         [](PPCState &st) -> std::reference_wrapper<uint64_t> {
           return st.iar.xer.qword;
         }},
        {"xer_so",
         [](PPCState &st) -> std::reference_wrapper<uint8_t> {
           return st.xer_flags.so;
         }},
        {"xer_ov",
         [](PPCState &st) -> std::reference_wrapper<uint8_t> {
           return st.xer_flags.ov;
         }},
};


std::optional<remill::Instruction>
GetFlows(std::string_view bytes, uint64_t address, uint64_t vle_val) {

  llvm::LLVMContext context;
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  context.enableOpaquePointers();
#endif
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


using MemoryModifier = std::function<void(test_runner::MemoryHandler &)>;

struct RegisterPrecondition {
  std::string register_name;
  std::variant<uint64_t, uint8_t> enforced_value;
};

struct MemoryPostcondition {
  uint64_t addr;
  std::vector<uint8_t> bytes;
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
  std::vector<MemoryModifier> expected_memory_conditions;

  template <typename T>
  void ApplyCondition(PPCState &state, std::string reg, T value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      std::any_cast<std::reference_wrapper<T>>(accessor->second(state)).get() =
          value;
    }
  }

  template <typename T>
  void CheckCondition(PPCState &state, std::string reg, T value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      auto actual =
          std::any_cast<std::reference_wrapper<T>>(accessor->second(state));
      LOG(INFO) << "Reg: " << reg << " Actual: " << std::hex << static_cast<uint64_t>(actual.get())
                << " Expected: " << std::hex << static_cast<uint64_t>(value);
      CHECK_EQ(actual, value);
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

  template <typename T>
  void AddPostRead(uint64_t addr, T value) {
    this->expected_memory_conditions.push_back(
        [addr, value](test_runner::MemoryHandler &mem_hand) {
          LOG(INFO) << "Mem: " << std::hex << addr << " Actual: " << std::hex
                    << mem_hand.ReadMemory<T>(addr) << " Expected: " << std::hex
                    << value;
          CHECK_EQ(mem_hand.ReadMemory<T>(addr), value);
        });
  }

  const std::vector<MemoryModifier> &GetMemoryPrecs() const {
    return this->initial_memory_conditions;
  }

  const std::vector<MemoryModifier> &GetMemoryPosts() const {
    return this->expected_memory_conditions;
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


  void SetupTestPreconditions(PPCState &state) const {
    for (auto prec : this->register_preconditions) {
      std::visit(
          [this, &state, prec](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            this->ApplyCondition<T>(state, prec.register_name, arg);
          },
          prec.enforced_value);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) const {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(PPCState &state) const {
    for (auto post : this->register_postconditions) {
      std::visit(
          [this, &state, post](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            this->CheckCondition<T>(state, post.register_name, arg);
          },
          post.enforced_value);
    }
  }

  void CheckResultingMemory(test_runner::MemoryHandler &mem_hand) const {
    for (const auto &post : this->GetMemoryPosts()) {
      post(mem_hand);
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
      : lifter(test_runner::LiftingTester(context, remill::OSName::kOSLinux,
                                          remill::ArchName::kArchPPC)),
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
    PPCState st = {};


    test.CheckLiftedInstruction(maybe_func->second);
    test_runner::RandomizeState(st, this->rbe);

    /*
    st.sr.z = test_runner::random_boolean_flag(this->rbe);
    st.sr.c = test_runner::random_boolean_flag(this->rbe);
    st.sr.v = test_runner::random_boolean_flag(this->rbe);
    st.sr.z = test_runner::random_boolean_flag(this->rbe);
    st.sr.n = test_runner::random_boolean_flag(this->rbe);
    */

    test.SetupTestPreconditions(st);
    auto mem_hand = std::make_unique<test_runner::MemoryHandler>(this->endian);

    for (const auto &prec : test.GetMemoryPrecs()) {
      prec(*mem_hand);
    }

    test_runner::ExecuteLiftedFunction<PPCState, uint64_t>(
        new_func, test.target_bytes.length(), &st, mem_hand.get(),
        [](PPCState *st) { return st->pc.qword; });

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

// Add two registers
TEST(PPCVLELifts, PPCVLEAdd) {
  llvm::LLVMContext curr_context;
  // add r5, r4, r3
  std::string insn_data("\x7C\xA4\x1A\x14", 4);
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"r4", uint64_t(0xcc)}, {"r3", uint64_t(0xdd)}, {"pc", uint64_t(0x12)}},
      {{"r5", uint64_t(0x1a9)}, {"pc", uint64_t(0x16)}});
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// Add two registers and record
TEST(PPCVLELifts, PPCVLEAddRecord) {
  llvm::LLVMContext curr_context;
  // add. r5, r4, r3
  // result is positive so cr0[1] is set which is the third bit in little endian
  std::string insn_data("\x7C\xA4\x1A\x15", 4);
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"r4", uint64_t(0xcc)}, {"r3", uint64_t(0xdd)}, {"cr0", uint8_t(0)}, {"pc", uint64_t(0x12)}},
      {{"r5", uint64_t(0x1a9)}, {"cr0", uint8_t(0b100)}, {"pc", uint64_t(0x16)}});
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// Add two registers and set overflow
TEST(PPCVLELifts, PPCVLEAddOverflow) {
  llvm::LLVMContext curr_context;
  // addo r5, r4, r3
  std::string insn_data("\x7C\xA4\x1E\x14", 4);
  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryNormal,
                      {{"r4", uint64_t(5000000000000000000)},
                       {"r3", uint64_t(5000000000000000000)},
                       {"xer_ov", uint8_t(0x0)},
                       {"xer_so", uint8_t(0x0)},
                       {"pc", uint64_t(0x12)}},
                      {{"r5", uint64_t(0x8ac7230489e80000)},
                       {"xer_ov", uint8_t(0x1)},
                       {"xer_so", uint8_t(0x1)},
                       {"pc", uint64_t(0x16)}});
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE short Branch to Link Register
TEST(PPCVLELifts, PPCVLEBranchLinkRegister) {
  llvm::LLVMContext curr_context;
  // se_blr
  std::string insn_data("\x00\x04", 2);
  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryFunctionReturn,
                      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x12)}},
                      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x4)}});

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE short Branch to Link Register and Link
TEST(PPCVLELifts, PPCVLEBranchLinkRegisterAndLink) {
  llvm::LLVMContext curr_context;
  // se_blrl
  std::string insn_data("\x00\x05", 2);
  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryFunctionReturn,
                      {{"lr", uint64_t(0x4)}, {"pc", uint64_t(0x12)}},
                      {{"lr", uint64_t(0x14)}, {"pc", uint64_t(0x4)}});

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

inline const remill::DecodingContext kVLEContext =
    remill::DecodingContext({{std::string("VLEReg"), 1}});

// VLE long relative conditional branch
TEST(PPCVLELifts, PPCVLECondBranch) {
  llvm::LLVMContext curr_context;
  // e_bne 0xfffffffa (-0x6)
  std::string insn_data("\x7a\x02\xff\xfa", 4);
  //TestOutputSpec spec(0x12, insn_data, remill::Instruction::Category::kCategoryConditionalBranch);
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
}

// VLE long relative branch
TEST(PPCVLELifts, PPCVLEBranch) {
  llvm::LLVMContext curr_context;
  // e_b 0x5a
  std::string insn_data("\x78\x00\x00\x5a", 4);
  // offset PC by 0x1000012 to also test that relative PC lifting works correctly
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryDirectJump,
      {{"pc", uint64_t(0x1000012)}}, {{"pc", uint64_t(0x1000012 + 0x5a)}});

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE Load Multiple Volatile General Purpose Registers
// Instruction only operates on the 32bit register sizes
TEST(PPCVLELifts, PPCVLELoadMultipleGeneralPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_ldmvgprw 0x0(r1)
  std::string insn_data("\x18\x01\x10\x00", 4);

  TestOutputSpec spec(0x12, insn_data,
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
                       {"r12", uint64_t(0xbbcc99aa)}});
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

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE Store Multiple Volatile General Purpose Registers
TEST(PPCVLELifts, PPCVLEStoreMultipleGeneralPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_stmvgprw 0x0(r1)
  std::string insn_data("\x18\x01\x11\x00", 4);

  TestOutputSpec spec(0x12, insn_data,
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
                       {"r12", uint64_t(0xbbcc99aa)}});
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

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE Load Multiple Volatile Special Purpose Registers
TEST(PPCVLELifts, PPCVLELoadMultipleSpecialPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_ldmvsprw 0x0(r1)
  std::string insn_data("\x18\x21\x10\x00", 4);

  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryNormal,
                      {{"pc", uint64_t(0x12)},
                       {"r1", uint64_t(0x13370)},
                       {"cr", uint64_t(0x0)},
                       {"lr", uint64_t(0x0)},
                       {"ctr", uint64_t(0x0)},
                       {"xer", uint64_t(0x0)}},
                      {{"pc", uint64_t(0x12 + 4)},
                       {"r1", uint64_t(0x13370)},
                       //{"cr", 0x11223344},
                       {"lr", uint64_t(0x55667788)},
                       {"ctr", uint64_t(0x99aabbcc)},
                       {"xer", uint64_t(0xddeeff00)}});
  spec.AddPrecWrite<uint32_t>(0x13370, 0x11223344);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x4, 0x55667788);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPrecWrite<uint32_t>(0x13370 + 0xc, 0xddeeff00);

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// VLE Store Multiple Volatile Special Purpose Registers
TEST(PPCVLELifts, PPCVLEStoreMultipleSpecialPurposeRegisters) {
  llvm::LLVMContext curr_context;
  // e_stmvsprw 0x0(r1)
  std::string insn_data("\x18\x21\x11\x00", 4);

  TestOutputSpec spec(0x12, insn_data,
                      remill::Instruction::Category::kCategoryNormal,
                      {{"pc", uint64_t(0x12)},
                       {"r1", uint64_t(0x13370)},
                       {"cr", uint64_t(0x11223344)},
                       {"lr", uint64_t(0x55667788)},
                       {"ctr", uint64_t(0x99aabbcc)},
                       {"xer", uint64_t(0xddeeff00)}},
                      {{"pc", uint64_t(0x12 + 4)},
                       {"r1", uint64_t(0x13370)},
                       {"cr", uint64_t(0x11223344)},
                       {"lr", uint64_t(0x55667788)},
                       {"ctr", uint64_t(0x99aabbcc)},
                       {"xer", uint64_t(0xddeeff00)}});
  //spec.AddPostRead<uint32_t>(0x13370, 0x11223344);
  spec.AddPostRead<uint32_t>(0x13370 + 0x4, 0x55667788);
  spec.AddPostRead<uint32_t>(0x13370 + 0x8, 0x99aabbcc);
  spec.AddPostRead<uint32_t>(0x13370 + 0xc, 0xddeeff00);

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// Rotate Left Word Immediate then AND with Mask
// Tests internal conditional branches in pcode
// Disabled since we don't support lifting instructions with internal control flow
TEST(PPCVLELifts, DISABLED_PPCVLERotateLeftWordImmediateAndMask) {
  llvm::LLVMContext curr_context;
  // e_rlwinm r6, r5, 0x1e, 0x1d, 0x1f
  // n >> 2 & 7
  // (n & 31) >> 2
  std::string insn_data("\x74\xa6\xf7\x7f");
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x12)}, {"r5", uint64_t(0x1337)}, {"r6", uint64_t(0x0)}},
      {{"pc", uint64_t(0x12 + 4)},
       {"r5", uint64_t(0x1337)},
       {"r6", uint64_t(0x5)}});

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}

// Convert Floating-Point Double-Precision from Signed Integer
TEST(PPCVLELifts, DISABLED_PPCVLEConvertDoubleFromSignedInteger) {
  llvm::LLVMContext curr_context;
  // e_efdcfsi r5, r4
  std::string insn_data("\x10\xa0\x22\xf1");
  TestOutputSpec spec(
      0x12, insn_data, remill::Instruction::Category::kCategoryNormal,
      {{"pc", uint64_t(0x12)}, {"r4", uint64_t(0x1337)}, {"r5", uint64_t(0x0)}},
      {{"pc", uint64_t(0x12 + 4)},
       {"r4", uint64_t(0x1337)},
       {"r5", uint64_t(0x4094e40000000000)}});

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
  curr_context.enableOpaquePointers();
#endif
  TestSpecRunner runner(curr_context);
  runner.RunTestSpec(spec);
}
