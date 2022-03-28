/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
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

#include <sleigh/libsleigh.hh>

#include "../Arch.h"


// Unifies shared functionality between sleigh architectures

namespace remill::sleigh {

class PcodeDecoder final : public PcodeEmit {
 public:
  PcodeDecoder(Sleigh &engine_, Instruction &inst_);

  void dump(const Address &, OpCode op, VarnodeData *outvar, VarnodeData *vars,
            int32_t isize) override;

 private:
  void DecodeOperand(VarnodeData &var);

  void DecodeRegister(const VarnodeData &var);

  void DecodeMemory(const VarnodeData &var);

  void DecodeConstant(const VarnodeData &var);

  void DecodeCategory(OpCode op);

  Sleigh &engine;
  Instruction &inst;
};

class CustomLoadImage final : public LoadImage {
 public:
  CustomLoadImage(void);

  void AppendInstruction(std::string_view instr_bytes);

  void loadFill(unsigned char *ptr, int size, const Address &addr) override;
  std::string getArchType(void) const override;

  void adjustVma(long) override;

 private:
  std::string image_buffer;
};

class SleighArch : public Arch {
 public:
  SleighArch(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_,
             std::string sla_name);


 public:
  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         Instruction &inst) const override;

 protected:
  bool DecodeInstructionImpl(uint64_t address, std::string_view instr_bytes,
                             Instruction &inst);
  CustomLoadImage image;
  ContextInternal ctx;
  Sleigh engine;
  Address cur_addr;
};
}  // namespace remill::sleigh