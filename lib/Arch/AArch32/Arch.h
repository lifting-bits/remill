/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <remill/Arch/AArch32/AArch32Base.h>

namespace remill {
class AArch32Arch final : public AArch32ArchBase {
 public:
  AArch32Arch(llvm::LLVMContext *context_, OSName os_name_,
              ArchName arch_name_);

  virtual ~AArch32Arch(void);

  bool DecodeInstruction(uint64_t address, std::string_view inst_bytes,
                         Instruction &inst) const override;

 private:
  AArch32Arch(void) = delete;
};

}  // namespace remill
