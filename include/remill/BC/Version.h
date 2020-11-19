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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <llvm/Config/llvm-config.h>
#pragma clang diagnostic pop

#define LLVM_VERSION(major, minor) ((major * 100) + minor)

#define LLVM_VERSION_NUMBER LLVM_VERSION(LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR)

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 5)
#  error "Minimum supported LLVM version is 3.5"
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(5, 0)
#  define IF_LLVM_LT_500(...) __VA_ARGS__
#  define IF_LLVM_LT_500_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_500(...) , __VA_ARGS__
#  define IF_LLVM_GTE_500(...)
#  define IF_LLVM_GTE_500_(...)
#  define _IF_LLVM_GTE_500(...)
#else
#  define IF_LLVM_LT_500(...)
#  define IF_LLVM_LT_500_(...)
#  define _IF_LLVM_LT_500(...)
#  define IF_LLVM_GTE_500(...) __VA_ARGS__
#  define IF_LLVM_GTE_500_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_500(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(4, 0)
#  define IF_LLVM_LT_400(...) __VA_ARGS__
#  define IF_LLVM_LT_400_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_400(...) , __VA_ARGS__
#  define IF_LLVM_GTE_400(...)
#  define IF_LLVM_GTE_400_(...)
#  define _IF_LLVM_GTE_400(...)
#else
#  define IF_LLVM_LT_400(...)
#  define IF_LLVM_LT_400_(...)
#  define _IF_LLVM_LT_400(...)
#  define IF_LLVM_GTE_400(...) __VA_ARGS__
#  define IF_LLVM_GTE_400_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_400(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 9)
#  define IF_LLVM_LT_390(...) __VA_ARGS__
#  define IF_LLVM_LT_390_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_390(...) , __VA_ARGS__
#  define IF_LLVM_GTE_390(...)
#  define IF_LLVM_GTE_390_(...)
#  define _IF_LLVM_GTE_390(...)
#else
#  define IF_LLVM_LT_390(...)
#  define IF_LLVM_LT_390_(...)
#  define _IF_LLVM_LT_390(...)
#  define IF_LLVM_GTE_390(...) __VA_ARGS__
#  define IF_LLVM_GTE_390_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_390(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 8)
#  define IF_LLVM_LT_380(...) __VA_ARGS__
#  define IF_LLVM_LT_380_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_380(...) , __VA_ARGS__
#  define IF_LLVM_GTE_380(...)
#  define IF_LLVM_GTE_380_(...)
#  define _IF_LLVM_GTE_380(...)
#else
#  define IF_LLVM_LT_380(...)
#  define IF_LLVM_LT_380_(...)
#  define _IF_LLVM_LT_380(...)
#  define IF_LLVM_GTE_380(...) __VA_ARGS__
#  define IF_LLVM_GTE_380_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_380(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 7)
#  define IF_LLVM_LT_370(...) __VA_ARGS__
#  define IF_LLVM_LT_370_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_370(...) , __VA_ARGS__
#  define IF_LLVM_GTE_370(...)
#  define IF_LLVM_GTE_370_(...)
#  define _IF_LLVM_GTE_370(...)
#else
#  define IF_LLVM_LT_370(...)
#  define IF_LLVM_LT_370_(...)
#  define _IF_LLVM_LT_370(...)
#  define IF_LLVM_GTE_370(...) __VA_ARGS__
#  define IF_LLVM_GTE_370_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_370(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 6)
#  define IF_LLVM_LT_360(...) __VA_ARGS__
#  define IF_LLVM_LT_360_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_360(...) , __VA_ARGS__
#  define IF_LLVM_GTE_360(...)
#  define IF_LLVM_GTE_360_(...)
#  define _IF_LLVM_GTE_360(...)
#else
#  define IF_LLVM_LT_360(...)
#  define IF_LLVM_LT_360_(...)
#  define _IF_LLVM_LT_360(...)
#  define IF_LLVM_GTE_360(...) __VA_ARGS__
#  define IF_LLVM_GTE_360_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_360(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(8, 0)
#  define IF_LLVM_LT_800(...) __VA_ARGS__
#  define IF_LLVM_LT_800_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_800(...) , __VA_ARGS__
#  define IF_LLVM_GTE_800(...)
#  define IF_LLVM_GTE_800_(...)
#  define _IF_LLVM_GTE_800(...)
#else
#  define IF_LLVM_LT_800(...)
#  define IF_LLVM_LT_800_(...)
#  define _IF_LLVM_LT_800(...)
#  define IF_LLVM_GTE_800(...) __VA_ARGS__
#  define IF_LLVM_GTE_800_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_800(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(9, 0)
#  define IF_LLVM_LT_900(...) __VA_ARGS__
#  define IF_LLVM_LT_900_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_900(...) , __VA_ARGS__
#  define IF_LLVM_GTE_900(...)
#  define IF_LLVM_GTE_900_(...)
#  define _IF_LLVM_GTE_900(...)
#else
#  define IF_LLVM_LT_900(...)
#  define IF_LLVM_LT_900_(...)
#  define _IF_LLVM_LT_900(...)
#  define IF_LLVM_GTE_900(...) __VA_ARGS__
#  define IF_LLVM_GTE_900_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_900(...) , __VA_ARGS__
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(10, 0)
#  define IF_LLVM_LT_1000(...) __VA_ARGS__
#  define IF_LLVM_LT_1000_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_1000(...) , __VA_ARGS__
#  define IF_LLVM_GTE_1000(...)
#  define IF_LLVM_GTE_1000_(...)
#  define _IF_LLVM_GTE_1000(...)
#else
#  define IF_LLVM_LT_1000(...)
#  define IF_LLVM_LT_1000_(...)
#  define _IF_LLVM_LT_1000(...)
#  define IF_LLVM_GTE_1000(...) __VA_ARGS__
#  define IF_LLVM_GTE_1000_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_1000(...) , __VA_ARGS__
#endif

#define IF_LLVM_LT(major, minor, ...) IF_LLVM_LT_##major##minor##0(__VA_ARGS__)

#define IF_LLVM_LT_(major, minor, ...) \
  IF_LLVM_LT_##major##minor##0##_(__VA_ARGS__)

#define _IF_LLVM_LT(major, minor, ...) \
  _IF_LLVM_LT_##major##minor##0(__VA_ARGS__)

#define IF_LLVM_GTE(major, minor, ...) \
  IF_LLVM_GTE_##major##minor##0(__VA_ARGS__)

#define IF_LLVM_GTE_(major, minor, ...) \
  IF_LLVM_GTE_##major##minor##0##_(__VA_ARGS__)

#define _IF_LLVM_GTE(major, minor, ...) \
  _IF_LLVM_GTE_##major##minor##0(__VA_ARGS__)
