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

/* SMOV  <Wd>, <Vn>.<Ts>[<index>] */
TEST_BEGIN(SMOV_ASIMDINS_W_W_B, smov_wN_B, 1)
TEST_INPUTS(0)
  smov w0, v0.B[0]
  smov w1, v0.B[4]
  smov w2, v0.B[8]
  smov w4, v0.B[12]
TEST_END

TEST_BEGIN(SMOV_ASIMDINS_W_W_H, smov_wN_H, 1)
TEST_INPUTS(0)
  smov w0, v0.H[0]
  smov w1, v0.H[2]
  smov w2, v0.H[4]
  smov w4, v0.H[6]
TEST_END


/* SMOV  <Xd>, <Vn>.<Ts>[<index>] */

TEST_BEGIN(SMOV_ASIMDINS_X_X_B, smov_xN_B, 1)
TEST_INPUTS(0)
  smov x0, v0.B[0]
  smov x1, v0.B[4]
  smov x2, v0.B[8]
  smov x4, v0.B[12]
TEST_END

TEST_BEGIN(SMOV_ASIMDINS_X_X_H, smov_xN_H, 1)
TEST_INPUTS(0)
  smov x0, v0.H[0]
  smov x1, v0.H[2]
  smov x2, v0.H[4]
  smov x4, v0.H[6]
TEST_END

TEST_BEGIN(SMOV_ASIMDINS_X_X_S, smov_xN_S, 1)
TEST_INPUTS(0)
  smov x0, v0.S[0]
  smov x1, v0.S[1]
  smov x2, v0.S[2]
  smov x4, v0.S[3]
TEST_END
