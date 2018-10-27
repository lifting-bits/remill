/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

TEST_BEGIN_64(FBLD, 2)
TEST_INPUTS(
    0x0000, 0x0000000000000000,  // +0
    0x8000, 0x0000000000000000,  // -0
    0x0000, 0x0000000000000123,  //  123
    0x8000, 0x0000000000000123,  // -123
    0xff00, 0x0000000000000123,  // -123 with set don't-care bits
    0x0012, 0x3456789123456789,  //  123456789123456789
    0x8012, 0x3456789123456789,  // -123456789123456789
    0x0000, 0x9007199254740993,  //  2^53 + 1, not representable as f64
    0x0099, 0x9999999999999999,  //  10^18 - 1, max packed BCD
    0x8099, 0x9999999999999999,  // -10^18 + 1, min packed BCD
    0x00aa, 0xaaaaaaaaaaaaaaaa,  // Invalid packed BCD
    0xffff, 0xffffffffffffffff)  // Invalid packed BCD, set high byte

    push ARG1_64
    push ARG2_64
    fbld [rsp]
TEST_END_64
