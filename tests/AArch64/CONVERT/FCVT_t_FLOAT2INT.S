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

TEST_BEGIN(FCVT_SD_FLOATDP1, fcvt_s1_d0, 1)
TEST_INPUTS(
    0x00000000, 
    0x3fffffff,
    0x40000000,     
    0x7FFFFFFF, 
    0x80000000,      
    0xffffffff,
    0xbf800000,
    0xc0000000,     
    0xcccccccccccccccc,
    0xbf8ccccccccccccc,
    0xffffffffffffffff)

    fmov d0, ARG1_64
    fcvt s1, d0
TEST_END

TEST_BEGIN(FCVT_DS_FLOATDP1, fcvt_d1_s0, 1)
TEST_INPUTS(
    0x00000000, 
    0x3fffffff,
    0x40000000,     
    0x7FFFFFFF, 
    0x80000000,      
    0xffffffff,
    0xbf800000,
    0xc0000000)
    
    fmov s0, ARG1_32
    fcvt d1, s0
TEST_END
