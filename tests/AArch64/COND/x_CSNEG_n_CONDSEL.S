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

TEST_BEGIN(CSNEG_32_CONDSEL_EQ, csneg_32_eq, 2)
TEST_INPUTS(
     0x0, 0x1,
     0x51, 0x22,
     0xffffffff, 0x1,
     0x1, 0xffffffff
 )
    csneg w2, w0, w1, EQ
TEST_END

TEST_BEGIN(CSNEG_32_CONDSEL_HI, csneg_32_HI, 2)
TEST_INPUTS(
     0x0, 0x1,
     0x22, 0x22,
     0xffffffff, 0x1,
     0x1, 0xffffffff
 )
    csneg w2, w0, w1, HI
TEST_END

TEST_BEGIN(CSNEG_32_CONDSEL_EQ, cneg_csneg_32_ne, 1)
TEST_INPUTS(
     0x0,
     0x51, 
     0x22,
     0xffffffff
)
    cneg w2, w0, ne
TEST_END
    
TEST_BEGIN(CSNEG_64_CONDSEL_EQ, csneg_64_eq, 2)
TEST_INPUTS(
     0x0, 0x1,
     0xfffffffffffffffc, 0xfffffffffffffffc,
     0x1, 0xffffffffffffffff,
     0xffffffffffffffff, 0xfffffffffffffffe
)
    csneg x2, x0, x1, EQ
TEST_END
    
TEST_BEGIN(CSNEG_64_CONDSEL_EQ, cneg_csneg_64_ne, 1)
TEST_INPUTS(
     0x0,
     0xfffffffffffffffc,
     0xffffffffffffffff,
     0xfffffffffffffffe
)
    cneg x2, x0, ne
TEST_END