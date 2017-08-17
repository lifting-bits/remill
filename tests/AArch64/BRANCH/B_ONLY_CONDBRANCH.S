/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

TEST_BEGIN(B_ONLY_CONDBRANCH_EQ, b_eq, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.eq 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_NE, b_ne, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.ne 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_CS, b_cs, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.cs 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_CC, b_cc, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.cc 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_MI, b_mi, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.mi 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_PL, b_pl, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.pl 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_VS, b_vs, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.vs 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_VC, b_vc, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.vc 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_HI, b_hi, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.hi 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_LS, b_ls, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.ls 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_GE, b_ge, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.ge 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_LT, b_lt, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.lt 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_GT, b_gt, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.gt 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_LE, b_la, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.le 99f
  mov x9, #0
99:
TEST_END

TEST_BEGIN(B_ONLY_CONDBRANCH_AL, b_al, 1)
TEST_INPUTS(0)
  mov x9, #1
  b.al 99f
  mov x9, #0
99:
TEST_END
