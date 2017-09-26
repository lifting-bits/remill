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

TEST_BEGIN(CCMP_32_CONDCMP_IMM_GE, ccmp_w0_ge_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, ge
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_GT, ccmp_w0_gt_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, gt
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_LE, ccmp_w0_le_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, le
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_LT, ccmp_w0_lt_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, lt
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_EQ, ccmp_w0_eq_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, eq
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_NE, ccmp_w0_ne_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, ne
TEST_END

TEST_BEGIN(CCMP_32_CONDCMP_IMM_CS, ccmp_w0_cs_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_32, #0x11, #0x0, cs
TEST_END

/* TODO(pag): Are more necessary? */


TEST_BEGIN(CCMP_64_CONDCMP_IMM_GE, ccmp_x0_ge_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, ge
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_GT, ccmp_x0_gt_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, gt
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_LE, ccmp_x0_le_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, le
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_LT, ccmp_x0_lt_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, lt
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_EQ, ccmp_x0_eq_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, eq
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_NE, ccmp_x0_ne_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, ne
TEST_END

TEST_BEGIN(CCMP_64_CONDCMP_IMM_CS, ccmp_x0_cs_11, 1)
TEST_INPUTS(
    0,
    1,
    0x10,
    0x11,
    0x12,
    0x0fffffff,
    0x7fffffff,
    0xffffffff)
    ccmp ARG1_64, #0x11, #0x0, cs
TEST_END

