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

#include <glog/logging.h>

#include <cstddef>
#include <map>
#include <mutex>
#include <sleigh/libsleigh.hh>
#include <variant>
#include <vector>

#include "lib/Arch/Sleigh/ControlFlowStructuring.h"


namespace remill::sleigh {

// A zero-indexed pointer to a PcodeOp within an instruction, relative
// to the first PcodeOp of the instruction.
struct IntrainstructionIndex {
  size_t target_block_index;
};

struct InstrExit {};

using Exit = std::variant<IntrainstructionIndex, InstrExit>;

struct ConditionalExit {
  Exit true_branch;
  Exit false_branch;
};

using BlockExit = std::variant<Exit, ConditionalExit>;

class PcodeBlock {
 public:
  size_t base_index;
  std::vector<RemillPcodeOp> ops;
  BlockExit block_exit;

  // Default block with an instruction exit and no ops.
  PcodeBlock(size_t base_index);

  PcodeBlock(size_t base_index, std::vector<RemillPcodeOp> ops,
             BlockExit block_exit);
};

class PcodeCFG {
 public:
  std::map<size_t, PcodeBlock> blocks;

  PcodeCFG(std::map<size_t, PcodeBlock> blocks);
};

PcodeCFG CreateCFG(const std::vector<RemillPcodeOp> &linear_ops,
                   const remill::Arch &arch);

class PcodeCFGBuilder {
 public:
  explicit PcodeCFGBuilder(const std::vector<RemillPcodeOp> &linear_ops,
                           const remill::Arch &arch);
  PcodeCFG Build() const;

 private:
  PcodeBlock BuildBlock(size_t start_ind, size_t next_start) const;
  std::optional<BlockExit> GetControlFlowExitsForIndex(size_t index) const;
  BlockExit GetBlockExitsForIndex(size_t index) const;
  std::vector<size_t> GetIntraProcTargets(size_t index) const;
  std::vector<size_t> GetBlockStarts() const;

  const std::vector<RemillPcodeOp> &linear_ops;
  const remill::Arch &arch;
};


}  // namespace remill::sleigh
