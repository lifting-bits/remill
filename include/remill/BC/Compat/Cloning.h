/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "remill/BC/Version.h"

/* This compatibility relates to the changes made in CallSite.h.
 */

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(11, 0)

#include <llvm/IR/AbstractCallSite.h>
#include <llvm/Analysis/InlineCost.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace llvm {

  inline static InlineResult InlineFunction(CallBase *CB, InlineFunctionInfo &IFI,
                                            AAResults *CalleeAAR = nullptr,
                                            bool InsertLifetime = true,
                                            Function *ForwardVarArgsTo = nullptr) {
    return InlineFunction(*CB, IFI, CalleeAAR, InsertLifetime, ForwardVarArgsTo);
  }

}  // namespace llvm

#endif
