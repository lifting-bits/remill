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

 TEST_BEGIN(CSEL_32_CONDSEL_EQ, csel_32_eq, 2)
 TEST_INPUTS(
     0x0, 0x1,
     0x22, 0x22,
     0xffffffff, 0x1,
     0x1, 0xffffffff
 )
    mov w3, #0xdead
    mov w4, #0xface
    csel w2, w3, w4, EQ
TEST_END

 TEST_BEGIN(CSEL_32_CONDSEL_HI, csel_32_HI, 2)
 TEST_INPUTS(
     0x0, 0x1,
     0x22, 0x22,
     0xffffffff, 0x1,
     0x1, 0xffffffff
 )
    mov w3, #0xdead
    mov w4, #0xface
    csel w2, w3, w4, HI
TEST_END
    
TEST_BEGIN(CSEL_64_CONDSEL_EQ, csel_64_eq, 2)
TEST_INPUTS(
     0x0, 0x1,
     0xfffffffffffffffc, 0xfffffffffffffffc
)
    mov x3, #0xdead
    mov x4, #0xface
    csel x2, x3, x4, EQ
TEST_END
    