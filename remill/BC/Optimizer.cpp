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

#include <glog/logging.h>

#include <llvm/ADT/Triple.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/BC/Compat/TargetLibraryInfo.h"

#include "remill/BC/DeadStoreEliminator.h"
#include "remill/BC/Optimizer.h"
#include "remill/BC/Util.h"

namespace remill {

void OptimizeModule(llvm::Module *module,
                    std::function<llvm::Function *(void)> generator,
                    OptimizationGuide guide) {

  auto bb_func = BasicBlockFunction(module);
  auto slots = StateSlots(module);

  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  auto TLI = new llvm::TargetLibraryInfoImpl(
      llvm::Triple(module->getTargetTriple()));

  TLI->disableAllFunctions();  // `-fno-builtin`.

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 0;
  builder.Inliner = llvm::createFunctionInliningPass(
      std::numeric_limits<int>::max());
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.RerollLoops = false;
  builder.SLPVectorize = guide.slp_vectorize;
  builder.LoopVectorize = guide.loop_vectorize;
  IF_LLVM_GTE_36(builder.VerifyInput = guide.verify_input;)
  IF_LLVM_GTE_36(builder.VerifyOutput = guide.verify_output;)

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  llvm::Function *func = nullptr;
  while (nullptr != (func = generator())) {
    func_manager.run(*func);
  }
  func_manager.doFinalization();
  module_manager.run(*module);

  if (guide.eliminate_dead_stores) {
    RemoveDeadStores(module, bb_func, slots);
  }
}

}  // namespace remill
