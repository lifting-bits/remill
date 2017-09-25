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


TEST_BEGIN(CSINC_32_CONDSEL_EQ, csinc_32_eq, 2)
TEST_INPUTS(
    0x0, 0x1
)
    mov w3, #0xdead
    mov w4, #0xface
    csinc w2, w3, w4, eq
TEST_END
    
 TEST_BEGIN(CSINC_64_CONDSEL_EQ, csinc_64_eq, 2)
 TEST_INPUTS(
     0x0, 0x1,
     0xfffffffffffffffc, 0xfffffffffffffffc
 )
    mov x3, #0xdead
    mov x4, #0xface
    csinc x2, x3, x4, eq
TEST_END

TEST_BEGIN(CSINC_32_CONDSEL_EQ, cinc_csinc_32_ne, 2)
TEST_INPUTS(
    0x0, 0x1,
    0x22, 0x22
)
    mov w3, #0xface
    cinc w4, w3, ne
TEST_END
    
 TEST_BEGIN(CSINC_64_CONDSEL_EQ, cinc_csinc_64_ne, 2)
 TEST_INPUTS(
     0x0, 0x1,
     0xfffffffffffffffc, 0xfffffffffffffffc
 )
    mov x3, #0xface
    cinc x5, x3, ne
TEST_END

TEST_BEGIN(CSINC_32_CONDSEL_EQ, cset_csinc_32_ne, 2)
TEST_INPUTS(
    0x0, 0x1,
    0x22, 0x22
)
    cset w3, ne
TEST_END

TEST_BEGIN(CSINC_64_CONDSEL_EQ, cset_csinc_64_ne, 2)
TEST_INPUTS(
     0x0, 0x1,
     0xfffffffffffffffc, 0xfffffffffffffffc
 )
    cset x3, ne
TEST_END