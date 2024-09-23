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
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/InlineCost.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
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
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/Pass.h>
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/Inliner.h>
#include <llvm/Transforms/IPO/ModuleInliner.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

namespace remill {

void OptimizeModule(const remill::Arch *arch, llvm::Module *module,
                    std::function<llvm::Function *(void)> generator,
                    OptimizationGuide guide) {
  OptimizeBareModule(module, guide);
}

// Optimize a normal module. This might not contain special Remill-specific
// intrinsics functions like `__remill_jump`, etc.
void OptimizeBareModule(llvm::Module *module, OptimizationGuide guide) {

  llvm::ModuleAnalysisManager mam;
  llvm::FunctionAnalysisManager fam;
  llvm::LoopAnalysisManager lam;
  llvm::CGSCCAnalysisManager cam;


  llvm::PipelineTuningOptions opts;
#if LLVM_VERSION_MAJOR >= 16
  opts.InlinerThreshold = 250;
#endif // LLVM_VERSION_MAJOR
  llvm::PassBuilder pb(nullptr, opts);

  pb.registerModuleAnalyses(mam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.registerCGSCCAnalyses(cam);
  pb.crossRegisterProxies(lam, fam, cam, mam);

  llvm::ModulePassManager mpm;
  mpm.addPass(llvm::ModuleInlinerPass(llvm::getInlineParams(250)));

  mpm.run(*module, mam);


  mam.clear();
  fam.clear();
  lam.clear();
  cam.clear();
}

}  // namespace remill
