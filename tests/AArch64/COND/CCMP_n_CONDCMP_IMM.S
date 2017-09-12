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

TEST_BEGIN(CCMP_32_CONDCMP_IMM_EQ, ccmp_w0_eq_1, 1)
TEST_INPUTS(
    0x11
    )
    ccmp w0, #0x11, #0x0, eq
TEST_END

// TEST_BEGIN(CCMP_32_CONDCMP_IMM_EQ, ccmp_32_cmpne_eq_11_c, 1)
// TEST_INPUTS(
//     0x11,
//     0x0,
//     0x1,
//     0xf,
//     0x7,
//     0xffffff
// )
//   mov w9, #0xdead
//   cmp w0, w0
//   ccmp w0, #0x11, #0xc, eq
//   b.eq 99f
//   mov w9, #0xface
// 99:
// TEST_END

// TEST_BEGIN(CCMP_32_CONDCMP_IMM_EQ, ccmp_32_cmpeq_eq_11_c, 1)
// TEST_INPUTS(
//     // 0x11
//     // 0x0,
//     0x1
//     // 0xf,
//     // 0x7,
//     // 0xffffff
// )
//   mov w9, #0xdead
//   cmp w0, w0
//   ccmp w0, #0x11, #0xc, eq
//   b.eq 99f
//   mov w9, #0xface
// 99:
// TEST_END

