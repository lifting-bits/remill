/*
 * Copyright (c) 2026 Trail of Bits, Inc.
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

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <remill/Arch/SPARC64/Runtime/State.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <unordered_map>

#include "SPARCTestRunner.h"

namespace {

using test_runner::RegisterValueRef;
using Spec = test_runner::TestOutputSpec<SPARC64State>;
using Category = remill::Instruction::Category;

const auto &Accessors() {
  static const auto accessors = [] {
    std::unordered_map<std::string,
                       std::function<RegisterValueRef(SPARC64State &)>>
        res;
    static const char *const gprs[] = {
        "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7", "o0", "o1", "o2",
        "o3", "o4", "o5", "sp", "o7", "l0", "l1", "l2", "l3", "l4", "l5",
        "l6", "l7", "i0", "i1", "i2", "i3", "i4", "i5", "fp", "i7"};
    for (auto i = 0u; i < 32u; ++i) {
      res[gprs[i]] = [i](SPARC64State &st) -> RegisterValueRef {
        return &st.gpr[i].qword;
      };
    }
    res["pc"] = [](SPARC64State &st) -> RegisterValueRef {
      return &st.pc.qword;
    };
    res["fcc0"] = [](SPARC64State &st) -> RegisterValueRef {
      return &st.flags.fcc0;
    };

    // As in the register table: the state is laid out in the target's (big-
    // endian) byte order, where `fs0` and `fd0` are the first bytes of `fq0`.
    for (auto q = 0u; q < 8u; ++q) {
      for (auto f = 0u; f < 4u; ++f) {
        res["fs" + std::to_string(4u * q + f)] =
            [q, f](SPARC64State &st) -> RegisterValueRef {
          return reinterpret_cast<uint32_t *>(&st.fpreg[q].floats.elems[f]);
        };
      }
      for (auto d = 0u; d < 2u; ++d) {
        res["fd" + std::to_string(4u * q + 2u * d)] =
            [q, d](SPARC64State &st) -> RegisterValueRef {
          return reinterpret_cast<uint64_t *>(&st.fpreg[q].doubles.elems[d]);
        };
      }
    }
    return res;
  }();
  return accessors;
}

// Instruction bytes, including any NUL bytes.
template <size_t N>
std::string Bytes(const char (&bytes)[N]) {
  return std::string(bytes, N - 1u);
}

void RunSpec(const Spec &spec) {
  llvm::LLVMContext context;
  sparc_test::TestSpecRunner<SPARC64State> runner(
      context, remill::kArchSparc64,
      [](SPARC64State *st) { return st->pc.qword; });
  runner.RunTestSpec(spec);
}

}  // namespace

// add %o0, %o1, %o0
TEST(SPARC64Lifts, Add) {
  RunSpec(Spec(0x1000, Bytes("\x90\x02\x00\x09"), Category::kCategoryNormal,
               {{"o0", uint64_t(0x100000001)},
                {"o1", uint64_t(0xffffffff)},
                {"pc", uint64_t(0x1000)}},
               {{"o0", uint64_t(0x200000000)}, {"pc", uint64_t(0x1004)}},
               Accessors()));
}

// retl; add %o0, %o1, %o0 (delay slot)
TEST(SPARC64Lifts, ReturnWithDelaySlot) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x08\x90\x02\x00\x09"),
               Category::kCategoryFunctionReturn,
               {{"o0", uint64_t(5)},
                {"o1", uint64_t(7)},
                {"o7", uint64_t(0x2000)},
                {"pc", uint64_t(0x1000)}},
               {{"o0", uint64_t(12)}, {"pc", uint64_t(0x2008)}}, Accessors()));
}

// jmp %o7 + 12; nop (delay slot): a leaf function returning a structure
// returns past the `unimp` after the delay slot of its call.
TEST(SPARC64Lifts, LeafReturnPastUnimp) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x0c\x01\x00\x00\x00"),
               Category::kCategoryFunctionReturn,
               {{"o7", uint64_t(0x2000)}, {"pc", uint64_t(0x1000)}},
               {{"pc", uint64_t(0x200c)}}, Accessors()));
}

// jmp %i7 + 12; restore (delay slot): the same in a non-leaf function.
TEST(SPARC64Lifts, ReturnPastUnimp) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc7\xe0\x0c\x81\xe8\x00\x00"),
               Category::kCategoryFunctionReturn,
               {{"i7", uint64_t(0x3000)}, {"pc", uint64_t(0x1000)}},
               {{"o7", uint64_t(0x3000)}, {"pc", uint64_t(0x300c)}},
               Accessors()));
}

// jmp %o7 + 16; nop: any other displacement is an indirect jump.
TEST(SPARC64Lifts, JumpPastReturnAddress) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x10\x01\x00\x00\x00"),
               Category::kCategoryIndirectJump,
               {{"o7", uint64_t(0x2000)}, {"pc", uint64_t(0x1000)}},
               {{"pc", uint64_t(0x2010)}}, Accessors()));
}

// call 0x1010; add %o0, 1, %o0 (delay slot)
TEST(SPARC64Lifts, CallWithDelaySlot) {
  RunSpec(Spec(0x1000, Bytes("\x40\x00\x00\x04\x90\x02\x20\x01"),
               Category::kCategoryDirectFunctionCall,
               {{"o0", uint64_t(41)}, {"pc", uint64_t(0x1000)}},
               {{"o0", uint64_t(42)},
                {"o7", uint64_t(0x1000)},
                {"pc", uint64_t(0x1010)}},
               Accessors()));
}

// save %sp, -176, %sp
TEST(SPARC64Lifts, Save) {
  RunSpec(Spec(0x1000, Bytes("\x9d\xe3\xbf\x50"), Category::kCategoryNormal,
               {{"o0", uint64_t(1)},
                {"o7", uint64_t(0x3000)},
                {"sp", uint64_t(0x8000)},
                {"pc", uint64_t(0x1000)}},
               {{"i0", uint64_t(1)},
                {"i7", uint64_t(0x3000)},
                {"fp", uint64_t(0x8000)},
                {"sp", uint64_t(0x8000 - 176)},
                {"pc", uint64_t(0x1004)}},
               Accessors()));
}

// ret; restore %o0, %i0, %o0 (delay slot)
TEST(SPARC64Lifts, ReturnWithRestore) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc7\xe0\x08\x91\xea\x00\x18"),
               Category::kCategoryFunctionReturn,
               {{"i0", uint64_t(10)},
                {"o0", uint64_t(32)},
                {"i7", uint64_t(0x4000)},
                {"fp", uint64_t(0x9000)},
                {"pc", uint64_t(0x1000)}},
               {{"o0", uint64_t(42)},
                {"sp", uint64_t(0x9000)},
                {"pc", uint64_t(0x4008)}},
               Accessors()));
}

// brz,pn %o0, 0x100c; mov 20, %o1 (delay slot, executed on both paths)
TEST(SPARC64Lifts, BranchOnZeroTaken) {
  RunSpec(Spec(0x1000, Bytes("\x02\xc2\x00\x03\x92\x10\x20\x14"),
               Category::kCategoryConditionalBranch,
               {{"o0", uint64_t(0)}, {"pc", uint64_t(0x1000)}},
               {{"o1", uint64_t(20)}, {"pc", uint64_t(0x100c)}}, Accessors()));
}

TEST(SPARC64Lifts, BranchOnZeroNotTaken) {
  RunSpec(Spec(0x1000, Bytes("\x02\xc2\x00\x03\x92\x10\x20\x14"),
               Category::kCategoryConditionalBranch,
               {{"o0", uint64_t(5)}, {"pc", uint64_t(0x1000)}},
               {{"o1", uint64_t(20)}, {"pc", uint64_t(0x1008)}}, Accessors()));
}

// brz,a %o0, 0x100c; mov 20, %o1: the delay slot is annulled (skipped)
// when the branch is not taken. Its p-code first branches to the fallthrough
// when the condition is false, so `BRANCH_TAKEN` is the inverted condition.
TEST(SPARC64Lifts, AnnulledBranchTaken) {
  RunSpec(
      Spec(0x1000, Bytes("\x22\xc2\x00\x03\x92\x10\x20\x14"),
           Category::kCategoryConditionalBranch,
           {{"o0", uint64_t(0)}, {"o1", uint64_t(7)}, {"pc", uint64_t(0x1000)}},
           {{"o1", uint64_t(20)}, {"pc", uint64_t(0x100c)}}, Accessors()));
}

TEST(SPARC64Lifts, AnnulledBranchNotTaken) {
  RunSpec(
      Spec(0x1000, Bytes("\x22\xc2\x00\x03\x92\x10\x20\x14"),
           Category::kCategoryConditionalBranch,
           {{"o0", uint64_t(5)}, {"o1", uint64_t(7)}, {"pc", uint64_t(0x1000)}},
           {{"o1", uint64_t(7)}, {"pc", uint64_t(0x1008)}}, Accessors()));
}

// fcmps %fcc0, %f1, %f3: 1.0 < 2.0
TEST(SPARC64Lifts, FloatCompareSetsFcc0) {
  RunSpec(Spec(0x1000, Bytes("\x81\xa8\x4a\x23"), Category::kCategoryNormal,
               {{"fs1", uint32_t(0x3f800000)},
                {"fs3", uint32_t(0x40000000)},
                {"pc", uint64_t(0x1000)}},
               {{"fcc0", uint8_t(1)}, {"pc", uint64_t(0x1004)}}, Accessors()));
}

// fmovd %f2, %f0. (The test runner executes the lifted code with the host's
// byte order, so it does not check how `fs0`/`fs1` overlay `fd0`.)
TEST(SPARC64Lifts, MoveDouble) {
  RunSpec(
      Spec(0x1000, Bytes("\x81\xa0\x00\x42"), Category::kCategoryNormal,
           {{"fd2", uint64_t(0x1122334455667788)}, {"pc", uint64_t(0x1000)}},
           {{"fd0", uint64_t(0x1122334455667788)}, {"pc", uint64_t(0x1004)}},
           Accessors()));
}

// st %o0, [%o1]: Sleigh reads the low word of `o0` as the register varnode
// `(o0 + 4, 4)`. The lifted code must take it from the value of `o0`, not
// load the first 4 bytes of `o0`, which are its high word in SPARC's
// big-endian layout. The test runner executes with the host's byte order, so
// this is checked on the lifted code: every load of `o0` loads all of it.
TEST(SPARC64Lifts, StoreWordReadsLowWordOfRegister) {
  llvm::LLVMContext context;
  test_runner::LiftingTester lifter(context, remill::OSName::kOSLinux,
                                    remill::kArchSparc64);
  auto lifted = lifter.LiftInstructionFunction(
      "store_word", Bytes("\xd0\x22\x40\x00"), 0x1000,
      lifter.GetArch()->CreateInitialContext());
  ASSERT_TRUE(lifted.has_value());

  auto module = llvm::CloneModule(*lifted->first->getParent());
  remill::OptimizeBareModule(module.get());
  auto func = module->getFunction("store_word");
  ASSERT_NE(func, nullptr);

  const auto &dl = module->getDataLayout();
  const auto state = remill::NthArgument(func, remill::kStatePointerArgNum);
  const auto o0 = lifter.GetArch()->RegisterByName("O0");
  auto num_o0_loads = 0u;
  for (auto &inst : llvm::instructions(*func)) {
    auto load = llvm::dyn_cast<llvm::LoadInst>(&inst);
    if (!load) {
      continue;
    }
    llvm::APInt offset(dl.getIndexTypeSizeInBits(state->getType()), 0);
    auto base = load->getPointerOperand()->stripAndAccumulateConstantOffsets(
        dl, offset, true);
    if (base == state && offset == o0->offset) {
      EXPECT_EQ(dl.getTypeStoreSize(load->getType()), o0->size);
      ++num_o0_loads;
    }
  }
  EXPECT_GT(num_o0_loads, 0u);
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
