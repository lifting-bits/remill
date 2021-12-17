/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
#include <glog/logging.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#pragma clang diagnostic pop

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "Version.h"

namespace remill {

// For all function holds that OriginType should have two static strings
// * metadata_kind that is the identifier (kind) of metadata
// * metadata_value that is the value that identifies the OriginType itself


struct BaseFunction {
  static const std::string metadata_kind;

  // Each class that inherits from some parent class appends its own metadata_value string with dot
  // to the parents one, therefore it is possible for search to easily include all subclasses as well
  static const std::string metadata_value;
};

// Unfortunately we must define the values of static vars in .cpp file
#define DECLARE_FUNC_ORIGIN_TYPE(children, parent) \
  struct children : parent { \
    static const std::string metadata_value; \
  }

DECLARE_FUNC_ORIGIN_TYPE(LiftedFunction, BaseFunction);
DECLARE_FUNC_ORIGIN_TYPE(EntrypointFunction, BaseFunction);
DECLARE_FUNC_ORIGIN_TYPE(ExternalFunction, BaseFunction);
DECLARE_FUNC_ORIGIN_TYPE(AbiLibraries, ExternalFunction);
DECLARE_FUNC_ORIGIN_TYPE(CFGExternal, ExternalFunction);
DECLARE_FUNC_ORIGIN_TYPE(ExtWrapper, ExternalFunction);
DECLARE_FUNC_ORIGIN_TYPE(Helper, BaseFunction);
DECLARE_FUNC_ORIGIN_TYPE(RemillHelper, Helper);
DECLARE_FUNC_ORIGIN_TYPE(McSemaHelper, Helper);
DECLARE_FUNC_ORIGIN_TYPE(Semantics, Helper);

#undef DECLARE_FUNC_ORIGIN_TYPE

// Default kind to be used, user is free to choose different, for example if each function
// is supposed to be part of multiple pairs
const std::string TieKind = "remill.function.tie";

// Versions before LLVM-4.0 do not have metadata for functions. There is (probably) no reasonable way
// to simulate them, therefore older version do not provide this functionality. However, since these
// annotations are not crucial to lift itself, definition of functions are provided (so that project)
// compiles. They issue error and return negative answers and nullptrs.

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(4, 0)

template <typename OriginType>
static bool Contains(llvm::MDString *node) {
  return node && node->getString().contains(OriginType::metadata_value);
}

template <typename OriginType>
static llvm::MDNode *GetNode(llvm::Function *func) {

  auto metadata_node = func->getMetadata(OriginType::metadata_kind);

  // There should be exactly one string there
  if (!metadata_node || metadata_node->getNumOperands() != 1) {
    return nullptr;
  }

  auto metadata_s =
      llvm::dyn_cast<llvm::MDString>(metadata_node->getOperand(0));
  return (Contains<OriginType>(metadata_s)) ? metadata_node : nullptr;
}

template <typename OriginType>
static bool Remove(llvm::Function *func) {
  auto node = GetNode<OriginType>(func);
  if (!node) {
    return false;
  }

  func->eraseMetadata(node->getMetadataID());
  return true;
}

// Give function OriginType
template <typename OriginType>
static void Annotate(llvm::Function *func) {
  auto &C = func->getContext();
  auto node =
      llvm::MDNode::get(C, llvm::MDString::get(C, OriginType::metadata_value));
  func->setMetadata(OriginType::metadata_kind, node);
}

template <typename OriginType>
static bool HasOriginType(llvm::Function *func) {
  return GetNode<OriginType>(func);
}

template <typename Type, typename Second, typename... OriginTypes>
static bool HasOriginType(llvm::Function *func) {
  return HasOriginType<Type>(func) ||
         HasOriginType<Second, OriginTypes...>(func);
}

// Return list of functions that are one of chosen OriginType
template <typename Container, typename... OriginTypes>
static void GetFunctionsByOrigin(llvm::Module &module, Container &result) {
  for (auto &func : module) {
    if (HasOriginType<OriginTypes...>(&func)) {

      // Method that is both in std::set and std::vector
      result.insert(result.end(), &func);
    }
  }
}

template <typename Container, typename... OriginTypes>
static Container GetFunctionsByOrigin(llvm::Module &module) {
  Container result;
  GetFunctionsByOrigin<Container, OriginTypes...>(module, result);
  return result;
}

template <typename OriginType>
static void ChangeOriginType(llvm::Function *func) {
  Annotate<OriginType>(func);
}

template <typename OriginType, typename OldType>
static bool ChangeOriginType(llvm::Function *func) {
  if (HasOriginType<OldType>(func)) {
    ChangeOriginType<OriginType>(func);
    return true;
  }
  return false;
}
/* Functions that "tie" together two functions via specific metada:
 * Both of them will contain metadata of specified kind, that is the other function.
 * This is useful for example to tie entrypoints and their corresponding sub_ functions
 */

// Get node that is holding the tie information
static inline llvm::MDNode *GetTieNode(llvm::Function *func,
                                       const std::string &kind = TieKind) {
  return func->getMetadata(kind);
}

static inline bool IsTied(llvm::Function *func,
                          const std::string &kind = TieKind) {
  return GetTieNode(func, kind);
}

// Add metadata to first with information about second
llvm::MDNode *TieFunction(llvm::Function *first, llvm::Function *second,
                          const std::string &kind = TieKind);

std::pair<llvm::MDNode *, llvm::MDNode *>
TieFunctions(llvm::Function *first, llvm::Function *second,
             const std::string &kind = TieKind);

// Get function that is tied to func, or nullptr if there is no such function
llvm::Function *GetTied(llvm::Function *func,
                        const std::string &kind = TieKind);


/* Filter Tied functions in meaningful way. Several overloads are prepared depending on customization
 * required.
 */
template <typename BinaryPredicate>
static void
GetTieMapping(llvm::Module &module, BinaryPredicate pred,
              std::unordered_map<llvm::Function *, llvm::Function *> &result,
              const std::string &kind = TieKind) {

  for (auto &func : module) {
    auto tied_to = GetTied(&func, kind);
    if (tied_to && pred(&func, tied_to)) {
      result.insert({&func, tied_to});
    }
  }
}

// TODO(C++14): Deduced return types
template <typename BinaryPredicate, typename Container>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, BinaryPredicate pred,
              const Container &kinds) {

  std::unordered_map<llvm::Function *, llvm::Function *> result;
  for (const auto &kind : kinds) {
    GetTieMapping(module, pred, result, kind);
  }
  return result;
}

// TODO(C++14): Deduced return types
// If functions are annotated with OriginTypes, this overload filters based on these annotations.
template <typename FromType, typename ToType = BaseFunction,
          typename Container = std::vector<std::string>>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const Container &kinds) {

  auto filter = [](llvm::Function *from, llvm::Function *to) {
    return HasOriginType<FromType>(from) && HasOriginType<ToType>(to);
  };
  return GetTieMapping(module, filter, kinds);
}

// TODO(C++14): Deduced return types
template <typename FromType, typename ToType = BaseFunction>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const std::string &kind = TieKind) {

  return GetTieMapping<FromType, ToType>(module,
                                         std::vector<std::string>{kind});
}


static inline std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const std::string &kind = TieKind) {

  // TODO(C++14): auto in lambda
  return GetTieMapping(
      module, [](llvm::Function *, llvm::Function *) { return true; },
      std::vector<std::string>{kind});
}

#else

#  define NOT_AVAILABLE(Err) \
    LOG(Err) \
        << "LLVM version is less than 4.0, functions metadata are not avalaible"

template <typename OriginType>
static bool Contains(llvm::MDString *node) {
  NOT_AVAILABLE(ERROR);
  return false;
}

template <typename OriginType>
static llvm::MDNode *GetNode(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
  return nullptr;
}

template <typename OriginType>
static bool Remove(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
  return false;
}

// Give function OriginType
template <typename OriginType>
static void Annotate(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
}

template <typename OriginType>
static bool HasOriginType(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
  return false;
}

template <typename Type, typename Second, typename... OriginTypes>
static bool HasOriginType(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
  return false;
}

template <typename Container, typename... OriginTypes>
static void GetFunctionsByOrigin(llvm::Module &module, Container &result) {
  NOT_AVAILABLE(ERROR);
}

template <typename Container, typename... OriginTypes>
static Container GetFunctionsByOrigin(llvm::Module &module) {
  NOT_AVAILABLE(ERROR);
  return {};
}

template <typename OriginType>
static void ChangeOriginType(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
}

template <typename OriginType, typename OldType>
static bool ChangeOriginType(llvm::Function *func) {
  NOT_AVAILABLE(ERROR);
  return false;
}

static inline llvm::MDNode *GetTieNode(llvm::Function *func,
                                       const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return nullptr;
}

static inline bool IsTied(llvm::Function *func,
                          const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return false;
}

static inline llvm::MDNode *TieFunction(llvm::Function *first,
                                        llvm::Function *second,
                                        const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return nullptr;
}

static inline std::pair<llvm::MDNode *, llvm::MDNode *>
TieFunctions(llvm::Function *first, llvm::Function *second,
             const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return {};
}

static inline llvm::Function *GetTied(llvm::Function *func,
                                      const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return nullptr;
}

template <typename BinaryPredicate>
static void
GetTieMapping(llvm::Module &module, BinaryPredicate pred,
              std::unordered_map<llvm::Function *, llvm::Function *> &result,
              const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
}

template <typename BinaryPredicate, typename Container>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, BinaryPredicate pred,
              const Container &kinds) {
  NOT_AVAILABLE(ERROR);
  return {};
}

template <typename FromType, typename ToType = BaseFunction,
          typename Container = std::vector<std::string>>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const Container &kinds) {
  NOT_AVAILABLE(ERROR);
  return {};
}

template <typename FromType, typename ToType = BaseFunction>
static std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return {};
}

static inline std::unordered_map<llvm::Function *, llvm::Function *>
GetTieMapping(llvm::Module &module, const std::string &kind = TieKind) {
  NOT_AVAILABLE(ERROR);
  return {};
}

#  undef NOT_AVAILABLE

#endif


}  // namespace remill
