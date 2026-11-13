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

TEST_BEGIN(RETnear, 1)
TEST_INPUTS(
    0,
    1,
    0x12345678,
    0x7FFFFFFF)

    mov RET_32, ARG1_32
    TEST_CALL ret_target1
    add RET_32, 1
    jmp ret_done1
ret_target1:
    add RET_32, ARG1_32
    TEST_RET
ret_done1:
    nop
TEST_END
