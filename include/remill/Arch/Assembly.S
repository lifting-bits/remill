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

#ifndef _REMILL_ARCH_ASSEMBLY_S
#define _REMILL_ARCH_ASSEMBLY_S

#define CAT_3(a, b) a ## b
#define CAT_2(a, b) CAT_3(a, b)
#define CAT(a, b) CAT_2(a, b)

#define CAT3(a, b, c) CAT(a, CAT(b, c))

/* Note:    Apple mangles C symbol names to have a leading underscore. */
#ifdef __APPLE__
# define SYMBOL(x) CAT(_, x)
#else
# define SYMBOL(x) x
#endif

#if __APPLE__
#define TEXT_SECTION .section __TEXT,__text
#define DATA_SECTION .section __DATA,__data
#define CONST_SECTION .section __TEXT,__const
#else
#define TEXT_SECTION .text
#define DATA_SECTION .data
#define CONST_SECTION .rodata
#endif // __APPLE__

#define TO_STRING3(a) # a
#define TO_STRING2(a) TO_STRING3(a)
#define TO_STRING(a) TO_STRING2(a)

#endif  // _REMILL_ARCH_ASSEMBLY_S
