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
#ifndef REMILL_BC_COMPAT_ERROR_H_
#define REMILL_BC_COMPAT_ERROR_H_

#include <system_error>

#include <llvm/Support/ErrorOr.h>

#include "remill/BC/Version.h"

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
# include <llvm/Support/Error.h>
#endif
namespace remill {

template <typename T>
bool IsError(llvm::ErrorOr<T> &val) {
  return !val;
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
template <typename T>
bool IsError(llvm::Expected<T> &val) {
  return !val;
}
#endif

template <typename T>
bool IsError(T *ptr) {
  return nullptr == ptr;
}

template <typename T>
bool IsError(T &ptr) {
  return false;
}

template <typename T>
std::string GetErrorString(llvm::ErrorOr<T> &val) {
  return val.getError().message();
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
template <typename T>
std::string GetErrorString(llvm::Expected<T> &val) {
  auto err = val.takeError();
  return llvm::errorToErrorCode(std::move(err)).message();
}
#endif

std::string GetErrorString(const char *message) {
  return message;
}

std::string GetErrorString(const std::string *message) {
  return message ? *message : "";
}

std::string GetErrorString(const std::string &message) {
  return message;
}

template <typename T>
std::string GetErrorString(T *) {
  return "";
}

template <typename T>
T *GetPointer(llvm::ErrorOr<T> &val) {
  return val.operator->();
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
template <typename T>
T *GetPointer(llvm::Expected<T> &val) {
  return val.operator->();
}
#endif

template <typename T>
T *GetPointer(T *val) {
  return val;
}

template <typename T>
T *GetPointer(T &val) {
  return &val;
}

template <typename T>
T &GetReference(llvm::ErrorOr<T> &val) {
  return val.operator*();
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
template <typename T>
T &GetReference(llvm::Expected<T> &val) {
  return val.operator*();
}
#endif

template <typename T>
T *GetReference(T *val) {
  return *val;
}

template <typename T>
T &GetReference(T &val) {
  return val;
}

}  // namespace remill


#endif  // REMILL_BC_COMPAT_ERROR_H_
