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

#pragma once

#include <llvm/Config/llvm-config.h>

#define LLVM_VERSION(major, minor) ((major * 100) + minor)

#define LLVM_VERSION_NUMBER \
    LLVM_VERSION(LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR)

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 5)
# error "Minimum supported LLVM version is 3.5"
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(5, 0)
# define IF_LLVM_LT_50(...) __VA_ARGS__
# define IF_LLVM_LT_50_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_50(...) , __VA_ARGS__
# define IF_LLVM_GTE_50(...)
# define IF_LLVM_GTE_50_(...)
# define _IF_LLVM_GTE_50(...)
#else
# define IF_LLVM_LT_50(...)
# define IF_LLVM_LT_50_(...)
# define _IF_LLVM_LT_50(...)
# define IF_LLVM_GTE_50(...) __VA_ARGS__
# define IF_LLVM_GTE_50_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_50(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(4, 0)
# define IF_LLVM_LT_40(...) __VA_ARGS__
# define IF_LLVM_LT_40_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_40(...) , __VA_ARGS__
# define IF_LLVM_GTE_40(...)
# define IF_LLVM_GTE_40_(...)
# define _IF_LLVM_GTE_40(...)
#else
# define IF_LLVM_LT_40(...)
# define IF_LLVM_LT_40_(...)
# define _IF_LLVM_LT_40(...)
# define IF_LLVM_GTE_40(...) __VA_ARGS__
# define IF_LLVM_GTE_40_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_40(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 9)
# define IF_LLVM_LT_39(...) __VA_ARGS__
# define IF_LLVM_LT_39_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_39(...) , __VA_ARGS__
# define IF_LLVM_GTE_39(...)
# define IF_LLVM_GTE_39_(...)
# define _IF_LLVM_GTE_39(...)
#else
# define IF_LLVM_LT_39(...)
# define IF_LLVM_LT_39_(...)
# define _IF_LLVM_LT_39(...)
# define IF_LLVM_GTE_39(...) __VA_ARGS__
# define IF_LLVM_GTE_39_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_39(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 8)
# define IF_LLVM_LT_38(...) __VA_ARGS__
# define IF_LLVM_LT_38_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_38(...) , __VA_ARGS__
# define IF_LLVM_GTE_38(...)
# define IF_LLVM_GTE_38_(...)
# define _IF_LLVM_GTE_38(...)
#else
# define IF_LLVM_LT_38(...)
# define IF_LLVM_LT_38_(...)
# define _IF_LLVM_LT_38(...)
# define IF_LLVM_GTE_38(...) __VA_ARGS__
# define IF_LLVM_GTE_38_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_38(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 7)
# define IF_LLVM_LT_37(...) __VA_ARGS__
# define IF_LLVM_LT_37_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_37(...) , __VA_ARGS__
# define IF_LLVM_GTE_37(...)
# define IF_LLVM_GTE_37_(...)
# define _IF_LLVM_GTE_37(...)
#else
# define IF_LLVM_LT_37(...)
# define IF_LLVM_LT_37_(...)
# define _IF_LLVM_LT_37(...)
# define IF_LLVM_GTE_37(...) __VA_ARGS__
# define IF_LLVM_GTE_37_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_37(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 6)
# define IF_LLVM_LT_36(...) __VA_ARGS__
# define IF_LLVM_LT_36_(...) __VA_ARGS__ ,
# define _IF_LLVM_LT_36(...) , __VA_ARGS__
# define IF_LLVM_GTE_36(...)
# define IF_LLVM_GTE_36_(...)
# define _IF_LLVM_GTE_36(...)
#else
# define IF_LLVM_LT_36(...)
# define IF_LLVM_LT_36_(...)
# define _IF_LLVM_LT_36(...)
# define IF_LLVM_GTE_36(...) __VA_ARGS__
# define IF_LLVM_GTE_36_(...) __VA_ARGS__ ,
# define _IF_LLVM_GTE_36(...) , __VA_ARGS__
#endif

#define IF_LLVM_LT(major, minor, ...) \
    IF_LLVM_LT_ ## major ## minor (__VA_ARGS__)

#define IF_LLVM_LT_(major, minor, ...) \
    IF_LLVM_LT_ ## major ## minor ## _ (__VA_ARGS__)

#define _IF_LLVM_LT(major, minor, ...) \
    _IF_LLVM_LT_ ## major ## minor (__VA_ARGS__)

#define IF_LLVM_GTE(major, minor, ...) \
    IF_LLVM_GTE_ ## major ## minor (__VA_ARGS__)

#define IF_LLVM_GTE_(major, minor, ...) \
    IF_LLVM_GTE_ ## major ## minor ## _ (__VA_ARGS__)

#define _IF_LLVM_GTE(major, minor, ...) \
    _IF_LLVM_GTE_ ## major ## minor (__VA_ARGS__)
