/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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

#include <remill/Arch/Context.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill::sleighmips {

class SleighMIPSDecoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighMIPSDecoder(const remill::Arch &);

  llvm::Value *LiftPcFromCurrPc(llvm::IRBuilder<> &, llvm::Value *, size_t,
                                const DecodingContext &) const override;

  void InitializeSleighContext(uint64_t addr,
                               remill::sleigh::SingleInstructionSleighContext &,
                               const ContextValues &) const override;
};

}  // namespace remill::sleighmips
