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

TEST_BEGIN_64(MOVDDUPv128v128, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    movq xmm0, ARG1_64;   // load the low QWORD of v128 dest
    movq xmm1, ARG2_64;   // load the low QWORD of v128 src
    movddup xmm0, xmm1;   // "moves and duplicates" the low QWORD value of src into dest
TEST_END_64

TEST_BEGIN_64(MOVDDUPv128m64, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    push ARG2_64;         // load the QWORD (m64) src
    movq xmm0, ARG1_64;   // load the low QWORD of v128 dest
    movddup xmm0, qword ptr [rsp];  // "moves and duplicates" the value of src into dest
TEST_END_64

#if HAS_FEATURE_AVX

TEST_BEGIN_64(VMOVDDUPv128v128, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    movq xmm0, ARG1_64;   // load the low QWORD of v128 dest
    movq xmm1, ARG2_64;   // load the low QWORD of v128 src
    vmovddup xmm0, xmm1;  // "moves and duplicates" the low QWORD value of src into dest
TEST_END_64

TEST_BEGIN_64(VMOVDDUPv128m64, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    movq xmm0, ARG1_64;         // load the low QWORD of v128 dest
    push ARG2_64;               // load the QWORD (m64) src
    vmovddup xmm0, qword ptr [rsp];  // "moves and duplicates" the value of src into dest
TEST_END_64

TEST_BEGIN_64(VMOVDDUPv256v256, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    push ARG1_64;
    push ARG1_64;
    push ARG1_64;
    push ARG1_64;
    vmovdqu ymm0, [rsp]
    push ARG2_64;
    push ARG2_64;
    vmovdqu ymm1, [rsp]
    vmovddup ymm0, ymm1;
TEST_END_64

TEST_BEGIN_64(VMOVDDUPv256m128, 2)
TEST_INPUTS(
    0x0000000000000000, 0x0000000000000000,  // sanity check
    0xfedcba9876543210, 0x0000000000000000,  // arbitrarily chosen values
    0xfedcba9876543210, 0xffffffffffffffff)  // other arbitrarily chosen values
    push ARG1_64;
    push ARG1_64;
    push ARG1_64;
    push ARG1_64;
    vmovdqu ymm0, [rsp]
    push ARG2_64;
    push ARG2_64;
    vmovddup ymm0, [rsp];
TEST_END_64

#endif
