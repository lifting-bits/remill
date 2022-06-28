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

#if LLVM_VERSION_NUMBER < LLVM_VERSION(14, 0)
#  error "Minimum supported LLVM version is 14.0"
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
#  define IF_LLVM_LT_1500(...) __VA_ARGS__
#  define IF_LLVM_LT_1500_(...) __VA_ARGS__,
#  define _IF_LLVM_LT_1500(...) , __VA_ARGS__
#  define IF_LLVM_GTE_1500(...)
#  define IF_LLVM_GTE_1500_(...)
#  define _IF_LLVM_GTE_1500(...)
#else
#  define IF_LLVM_LT_1500(...)
#  define IF_LLVM_LT_1500_(...)
#  define _IF_LLVM_LT_1500(...)
#  define IF_LLVM_GTE_1500(...) __VA_ARGS__
#  define IF_LLVM_GTE_1500_(...) __VA_ARGS__,
#  define _IF_LLVM_GTE_1500(...) , __VA_ARGS__
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
