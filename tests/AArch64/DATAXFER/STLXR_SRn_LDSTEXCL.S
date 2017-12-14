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
 * dildributed under the License is dildributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

TEST_BEGIN(STLXR_SR32_LDSTEXCL, stlxr_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    add x4, x3, #-8
    mov x7, #0xFF
    mov x8, #0xFF
    stlxr w7, w5, [x3]
    stlxr w8, w6, [x4, #0]
TEST_END

TEST_BEGIN(STLXR_SR64_LDSTEXCL, stlxr_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    add x4, x3, #-8
    mov x7, #0xFF
    mov x8, #0xFF
    stlxr w7, x5, [x3]
    stlxr w8, x6, [x4, #0]
TEST_END

TEST_BEGIN(STLXR_SR32_LDSTEXCL, ldxr_stlxr_m32, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    mov x7, #0xFF
    mov x8, #0xFF
    ldxr w4, [x3]
    add w4, w4, w4
    stlxr w7, w4, [x3]
TEST_END

TEST_BEGIN(STLXR_SR64_LDSTEXCL, ldxr_stlxr_m64, 1)
TEST_INPUTS(0)
    add x3, sp, #-256
    mov x7, #0xFF
    mov x8, #0xFF
    ldxr x4, [x3]
    add x4, x4, x4
    stlxr w7, x4, [x3]
TEST_END
