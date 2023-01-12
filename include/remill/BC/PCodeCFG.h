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
#include <mutex>
#include <sleigh/libsleigh.hh>
#include <unordered_map>
#include <variant>
#include <vector>

#include "lib/Arch/Sleigh/ControlFlowStructuring.h"


namespace remill {
namespace sleigh {


struct IntrainstructionIndex {
  size_t target_block_ind;
};

struct InstrExit {};

using Exit = std::variant<IntrainstructionIndex, InstrExit>;

struct ConditionalExit {
  Exit true_branch;
  Exit false_branch;
};

class PcodeBlock {
 public:
  size_t base_index;
  std::vector<RemillPcodeOp> ops;
  std::variant<Exit, ConditionalExit> block_exit;

  // Default block with an instruction exit and no ops.
  PcodeBlock(size_t base_index);

  PcodeBlock(size_t base_index, std::vector<RemillPcodeOp> ops,
             std::variant<Exit, ConditionalExit> block_exit);
};

class PcodeCFG {
 public:
  std::unordered_map<size_t, PcodeBlock> blocks;

  PcodeCFG(std::unordered_map<size_t, PcodeBlock> blocks);
};

class PcodeCFGBuilder {
 private:
  const std::vector<RemillPcodeOp> &linear_ops;


  PcodeCFGBuilder(const std::vector<RemillPcodeOp> &linear_ops);


  PcodeBlock BuildBlock(size_t start_ind, size_t next_start);
  std::variant<Exit, ConditionalExit> GetBlockExitsForIndex(size_t index);

  std::vector<size_t> GetIntraProcTargets(size_t index);

  std::vector<size_t> GetBlockStarts();

 public:
  static PcodeCFG CreateCFG(const std::vector<RemillPcodeOp> &linear_ops);

  PcodeCFG Build();
};


}  // namespace sleigh
}  // namespace remill