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

#include <remill/Arch/SPARC32/Runtime/State.h>

#include <unordered_map>

#include "SPARCTestRunner.h"

namespace {

using test_runner::RegisterValueRef;
using Spec = test_runner::TestOutputSpec<SPARC32State>;
using Category = remill::Instruction::Category;

const auto &Accessors() {
  static const auto accessors = [] {
    std::unordered_map<std::string,
                       std::function<RegisterValueRef(SPARC32State &)>>
        res;

    // Register pairs, as in the register table of `SPARC32Base.cpp`.
    auto pair = [&res](const char *even, const char *odd,
                       DoubleReg GPR::*field) {
      res[even] = [field](SPARC32State &st) -> RegisterValueRef {
        return &(st.gpr.*field).reg1.dword;
      };
      res[odd] = [field](SPARC32State &st) -> RegisterValueRef {
        return &(st.gpr.*field).reg2.dword;
      };
    };
    pair("i0", "i1", &GPR::i0_1);
    pair("i2", "i3", &GPR::i2_3);
    pair("i4", "i5", &GPR::i4_5);
    pair("fp", "i7", &GPR::fp_7);
    pair("l0", "l1", &GPR::l0_1);
    pair("o0", "o1", &GPR::o0_1);
    pair("o2", "o3", &GPR::o2_3);
    pair("o4", "o5", &GPR::o4_5);
    pair("sp", "o7", &GPR::sp_7);
    pair("g0", "g1", &GPR::g0_1);

    res["pc"] = [](SPARC32State &st) -> RegisterValueRef {
      return &st.pc.dword;
    };
    res["fcc0"] = [](SPARC32State &st) -> RegisterValueRef {
      return &st.fsr.fcc0;
    };

    // As in the register table: the state is laid out in the target's (big-
    // endian) byte order, where `fs0` and `fd0` are the first bytes of `fq0`.
    for (auto q = 0u; q < 8u; ++q) {
      for (auto f = 0u; f < 4u; ++f) {
        res["fs" + std::to_string(4u * q + f)] =
            [q, f](SPARC32State &st) -> RegisterValueRef {
          return reinterpret_cast<uint32_t *>(&st.fpreg.v[q].floats.elems[f]);
        };
      }
      for (auto d = 0u; d < 2u; ++d) {
        res["fd" + std::to_string(4u * q + 2u * d)] =
            [q, d](SPARC32State &st) -> RegisterValueRef {
          return reinterpret_cast<uint64_t *>(&st.fpreg.v[q].doubles.elems[d]);
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
  sparc_test::TestSpecRunner<SPARC32State> runner(
      context, remill::kArchSparc32,
      [](SPARC32State *st) -> uint64_t { return st->pc.dword; });
  runner.RunTestSpec(spec);
}

}  // namespace

// add %o0, %o1, %o0
TEST(SPARC32Lifts, Add) {
  RunSpec(Spec(0x1000, Bytes("\x90\x02\x00\x09"), Category::kCategoryNormal,
               {{"o0", uint32_t(0x7fffffff)},
                {"o1", uint32_t(1)},
                {"pc", uint32_t(0x1000)}},
               {{"o0", uint32_t(0x80000000)}, {"pc", uint32_t(0x1004)}},
               Accessors()));
}

// retl; add %o0, %o1, %o0 (delay slot)
TEST(SPARC32Lifts, ReturnWithDelaySlot) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x08\x90\x02\x00\x09"),
               Category::kCategoryFunctionReturn,
               {{"o0", uint32_t(5)},
                {"o1", uint32_t(7)},
                {"o7", uint32_t(0x2000)},
                {"pc", uint32_t(0x1000)}},
               {{"o0", uint32_t(12)}, {"pc", uint32_t(0x2008)}}, Accessors()));
}

// jmp %o7 + 12; nop (delay slot): a leaf function returning a structure
// returns past the `unimp` after the delay slot of its call.
TEST(SPARC32Lifts, LeafReturnPastUnimp) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x0c\x01\x00\x00\x00"),
               Category::kCategoryFunctionReturn,
               {{"o7", uint32_t(0x2000)}, {"pc", uint32_t(0x1000)}},
               {{"pc", uint32_t(0x200c)}}, Accessors()));
}

// jmp %i7 + 12; restore (delay slot): the same in a non-leaf function.
TEST(SPARC32Lifts, ReturnPastUnimp) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc7\xe0\x0c\x81\xe8\x00\x00"),
               Category::kCategoryFunctionReturn,
               {{"i7", uint32_t(0x3000)}, {"pc", uint32_t(0x1000)}},
               {{"o7", uint32_t(0x3000)}, {"pc", uint32_t(0x300c)}},
               Accessors()));
}

// jmp %o7 + 16; nop: any other displacement is an indirect jump.
TEST(SPARC32Lifts, JumpPastReturnAddress) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc3\xe0\x10\x01\x00\x00\x00"),
               Category::kCategoryIndirectJump,
               {{"o7", uint32_t(0x2000)}, {"pc", uint32_t(0x1000)}},
               {{"pc", uint32_t(0x2010)}}, Accessors()));
}

// call 0x1010; add %o0, 1, %o0 (delay slot)
TEST(SPARC32Lifts, CallWithDelaySlot) {
  RunSpec(Spec(0x1000, Bytes("\x40\x00\x00\x04\x90\x02\x20\x01"),
               Category::kCategoryDirectFunctionCall,
               {{"o0", uint32_t(41)}, {"pc", uint32_t(0x1000)}},
               {{"o0", uint32_t(42)},
                {"o7", uint32_t(0x1000)},
                {"pc", uint32_t(0x1010)}},
               Accessors()));
}

// save %sp, -96, %sp
TEST(SPARC32Lifts, Save) {
  RunSpec(Spec(0x1000, Bytes("\x9d\xe3\xbf\xa0"), Category::kCategoryNormal,
               {{"o0", uint32_t(1)},
                {"o7", uint32_t(0x3000)},
                {"sp", uint32_t(0x8000)},
                {"pc", uint32_t(0x1000)}},
               {{"i0", uint32_t(1)},
                {"i7", uint32_t(0x3000)},
                {"fp", uint32_t(0x8000)},
                {"sp", uint32_t(0x8000 - 96)},
                {"pc", uint32_t(0x1004)}},
               Accessors()));
}

// ret; restore %o0, %i0, %o0 (delay slot)
TEST(SPARC32Lifts, ReturnWithRestore) {
  RunSpec(Spec(0x1000, Bytes("\x81\xc7\xe0\x08\x91\xea\x00\x18"),
               Category::kCategoryFunctionReturn,
               {{"i0", uint32_t(10)},
                {"o0", uint32_t(32)},
                {"i7", uint32_t(0x4000)},
                {"fp", uint32_t(0x9000)},
                {"pc", uint32_t(0x1000)}},
               {{"o0", uint32_t(42)},
                {"sp", uint32_t(0x9000)},
                {"pc", uint32_t(0x4008)}},
               Accessors()));
}

// brz,pn %o0, 0x100c; mov 20, %o1 (delay slot, executed on both paths)
TEST(SPARC32Lifts, BranchOnZeroTaken) {
  RunSpec(Spec(0x1000, Bytes("\x02\xc2\x00\x03\x92\x10\x20\x14"),
               Category::kCategoryConditionalBranch,
               {{"o0", uint32_t(0)}, {"pc", uint32_t(0x1000)}},
               {{"o1", uint32_t(20)}, {"pc", uint32_t(0x100c)}}, Accessors()));
}

TEST(SPARC32Lifts, BranchOnZeroNotTaken) {
  RunSpec(Spec(0x1000, Bytes("\x02\xc2\x00\x03\x92\x10\x20\x14"),
               Category::kCategoryConditionalBranch,
               {{"o0", uint32_t(5)}, {"pc", uint32_t(0x1000)}},
               {{"o1", uint32_t(20)}, {"pc", uint32_t(0x1008)}}, Accessors()));
}

// fcmps %fcc0, %f1, %f3: 1.0 < 2.0
TEST(SPARC32Lifts, FloatCompareSetsFcc0) {
  RunSpec(Spec(0x1000, Bytes("\x81\xa8\x4a\x23"), Category::kCategoryNormal,
               {{"fs1", uint32_t(0x3f800000)},
                {"fs3", uint32_t(0x40000000)},
                {"pc", uint32_t(0x1000)}},
               {{"fcc0", uint8_t(1)}, {"pc", uint32_t(0x1004)}}, Accessors()));
}

// fmovd %f2, %f0. (The test runner executes the lifted code with the host's
// byte order, so it does not check how `fs0`/`fs1` overlay `fd0`.)
TEST(SPARC32Lifts, MoveDouble) {
  RunSpec(
      Spec(0x1000, Bytes("\x81\xa0\x00\x42"), Category::kCategoryNormal,
           {{"fd2", uint64_t(0x1122334455667788)}, {"pc", uint32_t(0x1000)}},
           {{"fd0", uint64_t(0x1122334455667788)}, {"pc", uint32_t(0x1004)}},
           Accessors()));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
