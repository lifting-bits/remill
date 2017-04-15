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

/* Itanium ABI, used by Linux and Mac. */

#if 64 == ADDRESS_SIZE_BITS
# define ARG1_8 dil
# define ARG2_8 sil
# define ARG3_8 dl
# define IF_64_BIT(...) __VA_ARGS__
# define IF_32_BIT(...)
#else
# define IF_64_BIT(...)
# define IF_32_BIT(...) __VA_ARGS__
#endif

#define ARG1_8 dil
#define ARG2_8 sil
#define ARG3_8 dl

#define ARG1_16 di
#define ARG2_16 si
#define ARG3_16 dx

#define ARG1_32 edi
#define ARG2_32 esi
#define ARG3_32 edx

#define ARG1_64 rdi
#define ARG2_64 rsi
#define ARG3_64 rdx

#define RET_32 eax
#define RET_64 rax

#ifdef IN_TEST_GENERATOR
# if 64 == ADDRESS_SIZE_BITS
#   define ARG1_ADDR ARG1_64
#   define ARG2_ADDR ARG2_64
#   define ARG3_ADDR ARG2_64
#   define SP_ADDR rsp
# else
#   define ARG1_ADDR ARG1_32
#   define ARG2_ADDR ARG2_32
#   define ARG3_ADDR ARG2_32
#   define SP_ADDR esp
# endif

/* Test code runs as 64-bit */
#else
# define ARG1_ADDR ARG1_64
# define ARG2_ADDR ARG2_64
# define ARG3_ADDR ARG2_64
# define SP_ADDR rsp
#endif
