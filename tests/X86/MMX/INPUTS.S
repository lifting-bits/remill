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

#define TEST_INPUTS_MMX_BYTE \
    0, 0,                    \
    1, 0,                    \
    0, 1,                    \
    0x3f, 0x3f,              \
    0x3f, 0x40,              \
    0x40, 0x3f,              \
    0x80, 0x7F,              \
    0x7F, 0x80,              \
    0x80, 0x80              \

#define TEST_INPUTS_MMX_WORD    \
    0x3fff, 0x3fff,             \
    0x3fff, 0x4000,             \
    0x4000, 0x3fff,             \
    0x7FFF, 0x8000,             \
    0x8000, 0x7FFF,             \
    0x8000, 0x8000             \

#define TEST_INPUTS_MMX_DWORD    \
    0x3fffffff, 0x3fffffff,      \
    0x3fffffff, 0x40000000,      \
    0x40000000, 0x3fffffff,      \
    0x7FFFFFFF, 0x7FFFFFFF,      \
    0x80000000, 0x7FFFFFFF,      \
    0x7FFFFFFF, 0x80000000,      \
    0x80000000, 0x80000000      \

#define TEST_INPUTS_MMX_QWORD    \
    0x3ff0000000000000 /* 1.000000 */, 0x3ff0000000000000, /* 1.000000 */    \
    0x3ff0000000000000 /* 1.000000 */, 0x4000000000000000, /* 2.000000 */    \
    0x4000000000000000 /* 2.000000 */, 0x3ff0000000000000, /* 1.000000 */    \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff0000000000000, /* inf */         \
    0x7ff0000000000000 /* inf */, 0x3ff0000000000000, /* 1.000000 */         \
    0x3ff0000000000000 /* 1.000000 */, 0xfff0000000000000, /* -inf */        \
    0xfff0000000000000 /* -inf */, 0x3ff0000000000000, /* 1.000000 */        \
    0x7ff0000000000000 /* inf */, 0x7ff0000000000000, /* inf */              \
    0xfff0000000000000 /* -inf */, 0xfff0000000000000, /* -inf */            \
    0x3ff0000000000000 /* 1.000000 */, 0x7ff8000000000000, /* nan */         \
    0x7ff8000000000000 /* nan */, 0x3ff0000000000000, /* 1.000000 */         \
    0x7ff8000000000000 /* nan */, 0x7ff8000000000000, /* nan */              \
    0x7ff0000000000000 /* inf */, 0x7ff8000000000000, /* nan */              \
    0x7ff8000000000000 /* nan */, 0x7ff0000000000000 /* inf */               \


#define TEST_INPUTS_MMX_2(...)    \
    TEST_INPUTS(    \
        TEST_INPUTS_MMX_BYTE,    \
        TEST_INPUTS_MMX_WORD,    \
        TEST_INPUTS_MMX_DWORD,   \
        TEST_INPUTS_MMX_QWORD   \
        )
