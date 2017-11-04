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

// LDR  <Wt>, [<Xn|SP>, #<simm>]!
TEST_BEGIN(LDR_32_LDST_IMMPRE, ldr_32_ldst_immpre_positive, 1)
TEST_INPUTS(
    // 0,
    // 1, 
    // 0xFFFFFFFF,
    // 0xFFFFFFFFFFFFFFFF,
    // 0x41
    0x4ed000)
    stp x0, x0, [x0, #8]
    ldr w4, [sp, #0x8]!
TEST_END

// TEST_BEGIN(LDR_32_LDST_IMMPRE, ldr_32_ldst_immpre_negative, 1)
// TEST_INPUTS(
//     // 0,
//     // 1, 
//     // 0xFFFFFFFF,
//     // 0xFFFFFFFFFFFFFFFF,
//     // 0x41,
//     0x4ed000)
//     ldr w4, [x0, #-0x22]!
// TEST_END