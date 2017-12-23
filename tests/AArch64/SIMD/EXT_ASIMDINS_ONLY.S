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

/* EXT <Vd>.<T>, <Vn>.<T>, <Vm>.<T>, #<index> */
TEST_BEGIN(EXT_ASIMDEXT_ONLY_8B, ext_asimdext_only_8b, 1)
TEST_INPUTS(0)
  movi v2.8b, #0
  movi v3.8b, #255
  ext v1.8b, v2.8b, v3.8b, #1
TEST_END

TEST_BEGIN(EXT_ASIMDEXT_ONLY_16B, ext_asimdext_only_16b, 1)
TEST_INPUTS(0)
  movi v2.16b, #0
  movi v3.16b, #255
  ext v1.16b, v2.16b, v3.16b, #1
TEST_END
