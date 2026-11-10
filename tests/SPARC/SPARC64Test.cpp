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

#include <remill/Arch/SPARC64/Runtime/State.h>

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

    // Big-endian register numbering: `fs0` is the high half of `fd0`, which
    // is the high half of `fq0`.
    for (auto q = 0u; q < 8u; ++q) {
      for (auto f = 0u; f < 4u; ++f) {
        res["fs" + std::to_string(4u * q + f)] =
            [q, f](SPARC64State &st) -> RegisterValueRef {
          return reinterpret_cast<uint32_t *>(
              &st.fpreg[q].floats.elems[3u - f]);
        };
      }
      for (auto d = 0u; d < 2u; ++d) {
        res["fd" + std::to_string(4u * q + 2u * d)] =
            [q, d](SPARC64State &st) -> RegisterValueRef {
          return reinterpret_cast<uint64_t *>(
              &st.fpreg[q].doubles.elems[1u - d]);
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

// fcmps %fcc0, %f1, %f3: 1.0 < 2.0
TEST(SPARC64Lifts, FloatCompareSetsFcc0) {
  RunSpec(Spec(0x1000, Bytes("\x81\xa8\x4a\x23"), Category::kCategoryNormal,
               {{"fs1", uint32_t(0x3f800000)},
                {"fs3", uint32_t(0x40000000)},
                {"pc", uint64_t(0x1000)}},
               {{"fcc0", uint8_t(1)}, {"pc", uint64_t(0x1004)}}, Accessors()));
}

// fmovd %f2, %f0: `fs0`/`fs1` are the high/low halves of `fd0`.
TEST(SPARC64Lifts, DoubleOverlaysSingles) {
  RunSpec(
      Spec(0x1000, Bytes("\x81\xa0\x00\x42"), Category::kCategoryNormal,
           {{"fd2", uint64_t(0x1122334455667788)}, {"pc", uint64_t(0x1000)}},
           {{"fs0", uint32_t(0x11223344)},
            {"fs1", uint32_t(0x55667788)},
            {"pc", uint64_t(0x1004)}},
           Accessors()));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
