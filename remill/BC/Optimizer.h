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

#ifndef REMILL_BC_OPTIMIZER_H_
#define REMILL_BC_OPTIMIZER_H_

#include <memory>

namespace llvm {
class Function;
class Module;

}  // namespace llvm
namespace remill {
class Optimizer {
 public:
  virtual ~Optimizer(void);

  static std::unique_ptr<Optimizer> Create(llvm::Module *module_);

  virtual void Optimize(void) = 0;

 protected:
  explicit Optimizer(llvm::Module *module_);

  llvm::Module *module;

 private:
  Optimizer(void) = delete;

};
}  // namespace remill

#endif  // REMILL_BC_OPTIMIZER_H_
