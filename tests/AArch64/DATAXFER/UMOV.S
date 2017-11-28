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

/* UMOV  <Wd>, <Vn>.<Ts>[<index>] */
TEST_BEGIN(UMOV_ASIMDINS_W_W_B, umov_wN_B, 1)
TEST_INPUTS(0)
  umov w0, v0.B[0]
  umov w1, v0.B[4]
  umov w2, v0.B[8]
  umov w4, v0.B[12]
TEST_END

TEST_BEGIN(UMOV_ASIMDINS_W_W_H, umov_wN_H, 1)
TEST_INPUTS(0)
  umov w0, v0.H[0]
  umov w1, v0.H[2]
  umov w2, v0.H[4]
  umov w4, v0.H[6]
TEST_END

TEST_BEGIN(UMOV_ASIMDINS_W_W_S, umov_wN_S, 1)
TEST_INPUTS(0)
  umov w0, v0.S[0]
  umov w1, v0.S[1]
  umov w2, v0.S[2]
  umov w4, v0.S[3]
TEST_END

/* UMOV  <Xd>, <Vn>.<Ts>[<index>] */
TEST_BEGIN(UMOV_ASIMDINS_X_X_D, umov_xN_D, 1)
TEST_INPUTS(0)
  umov x0, v0.D[0]
  umov x1, v0.D[1]
TEST_END
