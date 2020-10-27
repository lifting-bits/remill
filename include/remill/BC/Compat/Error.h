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

#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/raw_ostream.h>

#include <system_error>

#include "remill/BC/Version.h"

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)
#  include <llvm/Support/Error.h>
#endif

namespace remill {

template <typename T>
inline static bool IsError(llvm::ErrorOr<T> &val) {
  return !val;
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)
template <typename T>
inline static bool IsError(llvm::Expected<T> &val) {
  return !val;
}
#endif

template <typename T>
inline static bool IsError(T *ptr) {
  return nullptr == ptr;
}

template <typename T>
inline static bool IsError(T &ptr) {
  return false;
}

inline static bool IsError(llvm::Error &err) {
  return !!err;
}

template <typename T>
inline static std::string GetErrorString(llvm::ErrorOr<T> &val) {
  return val.getError().message();
}

inline static std::string GetErrorString(llvm::Error &val) {
  std::string err;
  llvm::raw_string_ostream os(err);
  llvm::handleAllErrors(std::move(val),
                        [&os](llvm::ErrorInfoBase &eib) { eib.log(os); });
  os.flush();
  return err;
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)

template <typename T>
inline static std::string GetErrorString(llvm::Expected<T> &val) {
  auto err = val.takeError();
  return GetErrorString(err);
}
#endif

inline static std::error_code GetErrorCode(const char *) {
  return std::make_error_code(std::errc::invalid_argument);
}

inline static std::string GetErrorString(const char *message) {
  return message;
}

inline static std::error_code GetErrorCode(const std::string *) {
  return std::make_error_code(std::errc::invalid_argument);
}

inline static std::string GetErrorString(const std::string *message) {
  return message ? *message : "";
}

inline static std::error_code GetErrorCode(const std::string &) {
  return std::make_error_code(std::errc::invalid_argument);
}

inline static std::string GetErrorString(const std::string &message) {
  return message;
}

template <typename T>
inline static std::error_code GetErrorCode(T *) {
  return std::make_error_code(std::errc::invalid_argument);
}

template <typename T>
inline static std::string GetErrorString(T *) {
  return "";
}

template <typename T>
inline static std::error_code GetErrorCode(llvm::ErrorOr<T> &val) {
  return val.getError();
}

template <typename T>
inline static T *GetPointer(llvm::ErrorOr<T> &val) {
  return val.operator->();
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)
template <typename T>
inline static T *GetPointer(llvm::Expected<T> &val) {
  return val.operator->();
}
#endif

template <typename T>
inline static T *GetPointer(T *val) {
  return val;
}

template <typename T>
inline static T *GetPointer(T &val) {
  return &val;
}

template <typename T>
inline static T &GetReference(llvm::ErrorOr<T> &val) {
  return val.operator*();
}

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)
template <typename T>
inline static T &GetReference(llvm::Expected<T> &val) {
  return val.operator*();
}
#endif

template <typename T>
inline static T &GetReference(T *val) {
  return *val;
}

template <typename T>
inline static T &GetReference(T &val) {
  return val;
}

}  // namespace remill
namespace llvm {

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(6, 0)
inline static Error createStringError(std::error_code EC, char const *Msg) {
  return make_error<StringError>(Msg, EC);
}

/// Create formatted StringError object.
template <typename... Ts>
inline static Error createStringError(std::error_code EC, char const *Fmt,
                                      const Ts &... Vals) {
  std::string Buffer;
  raw_string_ostream Stream(Buffer);
  Stream << format(Fmt, Vals...);
  return make_error<StringError>(Stream.str(), EC);
}
#endif

#if LLVM_VERSION_NUMBER <= LLVM_VERSION(8, 0)

template <typename... Ts>
inline static Error createStringError(std::errc EC, char const *Fmt,
                                      const Ts &... Vals) {
  return createStringError(std::make_error_code(EC), Fmt, Vals...);
}
#endif

}  // namespace llvm
