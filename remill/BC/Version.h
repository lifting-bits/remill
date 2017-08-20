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

#ifndef REMILL_BC_VERSION_H_
#define REMILL_BC_VERSION_H_

#include <llvm/Config/llvm-config.h>

#define LLVM_VERSION(major, minor) ((major * 100) + minor)

#define LLVM_VERSION_NUMBER \
    LLVM_VERSION(LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR)

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 5)
# error "Minimum supported LLVM version is 3.5"
#endif

#define IF_GTE_LLVM36(...) __VA_ARGS__
#define IF_GTE_LLVM37(...) __VA_ARGS__
#define IF_GTE_LLVM38(...) __VA_ARGS__
#define IF_GTE_LLVM39(...) __VA_ARGS__
#define IF_GTE_LLVM40(...) __VA_ARGS__

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 6)
# undef IF_GTE_LLVM36
# define IF_GTE_LLVM36(...)
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 7)
# undef IF_GTE_LLVM37
# define IF_GTE_LLVM37(...)
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 8)
# undef IF_GTE_LLVM38
# define IF_GTE_LLVM38(...)
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 9)
# undef IF_GTE_LLVM39
# define IF_GTE_LLVM39(...)
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(4, 0)
# undef IF_GTE_LLVM40
# define IF_GTE_LLVM40(...)
#endif

#endif  // REMILL_BC_VERSION_H_
