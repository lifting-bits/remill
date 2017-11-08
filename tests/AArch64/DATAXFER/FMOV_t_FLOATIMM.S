
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


//instruction requires: fullfp16 feature
// FMOV  <Hd>, #<imm>
// TEST_BEGIN(FMOV_H_FLOATIMM, fmov_h, 1)
// TEST_INPUTS(0)
//     fmov h0, #0x0
//     fmov h1, #0x1
//     fmov h2, #0x40
//     fmov h3, #0x80
//     fmov h4, #0x7f
//     fmov h5, #0x3f
// TEST_END
// FMOV  <Sd>, #<imm>

TEST_BEGIN(FMOV_S_FLOATIMM, fmov_s_imm, 1)
TEST_INPUTS(0)
    fmov s0, #0x0
    fmov s1, #0x1
    fmov s2, #0x40
    fmov s3, #0x80
    fmov s4, #0x7f
    fmov s5, #0x3f
TEST_END

TEST_BEGIN(FMOV_D_FLOATIMM, fmov_d_imm, 1)
TEST_INPUTS(0)
    fmov d0, #0x0
    fmov d1, #0x1
    fmov d2, #0x40
    fmov d3, #0x80
    fmov d4, #0x7f
    fmov d5, #0x3f
TEST_END
