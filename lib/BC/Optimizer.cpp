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

#include "remill/BC/Optimizer.h"

#include <glog/logging.h>
#include <llvm/ADT/Triple.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Compat/ScalarTransforms.h"
#include "remill/BC/Compat/TargetLibraryInfo.h"
#include "remill/BC/Util.h"

namespace remill {

void OptimizeModule(const remill::Arch *arch, llvm::Module *module,
                    std::function<llvm::Function *(void)> generator,
                    OptimizationGuide guide) {

  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  auto TLI =
      new llvm::TargetLibraryInfoImpl(llvm::Triple(module->getTargetTriple()));

  TLI->disableAllFunctions();  // `-fno-builtin`.

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 0;
  builder.Inliner = llvm::createFunctionInliningPass(250);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  IF_LLVM_LT_900(builder.DisableUnitAtATime = false;)
  builder.RerollLoops = false;
  builder.SLPVectorize = guide.slp_vectorize;
  builder.LoopVectorize = guide.loop_vectorize;
  IF_LLVM_GTE_360(builder.VerifyInput = guide.verify_input;)
  IF_LLVM_GTE_360(builder.VerifyOutput = guide.verify_output;)

  // TODO(pag): Not sure when this became available.
  IF_LLVM_GTE_800(builder.MergeFunctions = false;)

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  llvm::Function *func = nullptr;
  while (nullptr != (func = generator())) {
    func_manager.run(*func);
  }
  func_manager.doFinalization();
  module_manager.run(*module);
}

// Optimize a normal module. This might not contain special Remill-specific
// intrinsics functions like `__remill_jump`, etc.
void OptimizeBareModule(llvm::Module *module, OptimizationGuide guide) {
  llvm::legacy::FunctionPassManager func_manager(module);
  llvm::legacy::PassManager module_manager;

  auto TLI =
      new llvm::TargetLibraryInfoImpl(llvm::Triple(module->getTargetTriple()));

  TLI->disableAllFunctions();  // `-fno-builtin`.

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 0;
  builder.Inliner = llvm::createFunctionInliningPass(250);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  IF_LLVM_LT_900(builder.DisableUnitAtATime = false;)
  builder.RerollLoops = false;
  builder.SLPVectorize = guide.slp_vectorize;
  builder.LoopVectorize = guide.loop_vectorize;
  IF_LLVM_GTE_360(builder.VerifyInput = guide.verify_input;)
  IF_LLVM_GTE_360(builder.VerifyOutput = guide.verify_output;)

  // TODO(pag): Not sure when this became available.
  IF_LLVM_GTE_800(builder.MergeFunctions = false;)

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  for (auto &func : *module) {
    func_manager.run(func);
  }
  func_manager.doFinalization();
  module_manager.run(*module);
}

}  // namespace remill
