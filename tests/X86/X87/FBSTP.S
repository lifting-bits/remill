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


TEST_BEGIN_64(FBSTP, 1)
TEST_INPUTS(
    0x8000000000000000,  // -0
    0x0000000000000000,  //  0
    0x3fbf7ced916872b0,  //  0.123
    0xbfbf7ced916872b0,  // -0.123
    0xbfe0000000000000,  // -0.5
    0x3fe0000000000000,  //  0.5
    0xbff3ae147ae147ae,  // -1.23
    0x3ff3ae147ae147ae,  //  1.23
    0xc05ec00000000000,  // -123
    0x405ec00000000000,  //  123
    0xc05edd2f1a9fbe77,  // -123.456
    0x405edd2f1a9fbe77,  //  123.456
    0xbffe666666666666,  // -1.9
    0x3ffe666666666666,  //  1.9

    // Min, max finite f64 values that are in BCD range,
    // due to f64 floating-point aliasing.
    0xc3abc16d674ec7ff,  // -1e+18 + 65
    0x43abc16d674ec7ff,  //  1e+18 - 65

    // The below values are all invalid or out of BCD range.

    // Minimum-magnitude finite f64 values that are out of range.
    0xc3abc16d674ec800,  // -1e+18 + 64
    0x43abc16d674ec800,  //  1e+18 - 64

    0xfff8000000000001,  // -QNaN
    0x7ff8000000000001,  //  QNaN
    0xfff0000000000001,  // -SNan
    0x7ff0000000000001,  //  SNan
    0xfff0000000000000,  // -inf
    0x7ff0000000000000,  //  inf
    0xc3d158e460913d00,  // -2e+18
    0x43d158e460913d00,  //  2e+18
    0x433ffffffffffffe,  //  2^53 - 2, exactly representable as f64
    0x433fffffffffffff,  //  2^53 - 1, max contiguous int exactly representable as f64
    0x4340000000000000,  //  2^53, aliases 2^53 + 1
    0xc33ffffffffffffe,  // -2^53 + 2, exactly representable as f64
    0xc33fffffffffffff,  // -2^53 + 1, min contiguous int exactly representable as f64
    0xc340000000000000)  // -2^53, aliases -2^53 - 1

    push ARG1_64
    fld QWORD PTR [rsp]

    lea rsp, [rsp - 10]
    fbstp [rsp]
TEST_END_64
