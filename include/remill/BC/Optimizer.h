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

#pragma once

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <llvm/IR/Module.h>
#pragma clang diagnostic pop

#include <functional>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {

class Arch;

struct OptimizationGuide {
  bool slp_vectorize;
  bool loop_vectorize;
  bool verify_input;
  bool verify_output;
};

template <typename T>
inline static void
OptimizeModule(const std::unique_ptr<const remill::Arch> &arch,
               const std::unique_ptr<llvm::Module> &module, T &&generator,
               OptimizationGuide guide = {}) {
  return OptimizeModule(arch.get(), module.get(), generator, guide);
}

void OptimizeModule(const remill::Arch *arch, llvm::Module *module,
                    std::function<llvm::Function *(void)> generator,
                    OptimizationGuide guide = {});

inline static void
OptimizeModule(const remill::Arch *arch, llvm::Module *module,
               std::initializer_list<llvm::Function *> traces,
               OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = *trace_it;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

template <typename K>
inline static void
OptimizeModule(const remill::Arch *arch, llvm::Module *module,
               const std::unordered_map<K, llvm::Function *> &traces,
               OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = trace_it->second;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

template <typename K>
inline static void OptimizeModule(const remill::Arch *arch,
                                  llvm::Module *module,
                                  const std::map<K, llvm::Function *> &traces,
                                  OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = trace_it->second;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

inline static void OptimizeModule(const remill::Arch *arch,
                                  llvm::Module *module,
                                  const std::set<llvm::Function *> &traces,
                                  OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = *trace_it;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

inline static void
OptimizeModule(const remill::Arch *arch, llvm::Module *module,
               const std::unordered_set<llvm::Function *> &traces,
               OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = *trace_it;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

inline static void OptimizeModule(const remill::Arch *arch,
                                  llvm::Module *module,
                                  const std::vector<llvm::Function *> &traces,
                                  OptimizationGuide guide = {}) {
  auto trace_it = traces.begin();
  auto trace_func_gen = [&trace_it, &traces](void) -> llvm::Function * {
    if (trace_it != traces.end()) {
      auto lifted_func = *trace_it;
      trace_it++;
      return lifted_func;
    } else {
      return nullptr;
    }
  };
  return OptimizeModule(arch, module, trace_func_gen, guide);
}

// Optimize a normal module. This might not contain special Remill-specific
// intrinsics functions like `__remill_jump`, etc.
void OptimizeBareModule(llvm::Module *module, OptimizationGuide guide = {});

inline static void
OptimizeBareModule(const std::unique_ptr<llvm::Module> &module,
                   OptimizationGuide guide = {}) {
  std::vector<llvm::Function *> funcs;
  for (auto &func : *module) {
    funcs.push_back(&func);
  }
  return OptimizeBareModule(module.get(), guide);
}

}  // namespace remill
