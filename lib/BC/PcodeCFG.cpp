#include <remill/BC/PCodeCFG.h>

#include <algorithm>
#include <cstddef>
#include <sleigh/op.hh>
#include <sleigh/opcodes.hh>
#include <sleigh/pcoderaw.hh>
#include <unordered_map>
#include <variant>
#include <vector>

#include "lib/Arch/Sleigh/ControlFlowStructuring.h"

namespace remill {
namespace sleigh {

PcodeCFG
PcodeCFGBuilder::CreateCFG(const std::vector<RemillPcodeOp> &linear_ops) {
  return PcodeCFGBuilder(linear_ops).Build();
}


std::vector<size_t> PcodeCFGBuilder::GetBlockStarts() {
  std::vector<size_t> res;
  res.push_back(0);


  for (size_t curr_index = 0; curr_index < this->linear_ops.size();
       curr_index += 1) {
    auto interproc = this->GetIntraProcTargets(curr_index);
    res.insert(res.end(), interproc.begin(), interproc.end());
  }
  return res;
}

PcodeBlock PcodeCFGBuilder::BuildBlock(size_t start_ind, size_t next_start) {
  std::vector<RemillPcodeOp> ops;

  for (size_t i = start_ind; i < next_start; i++) {
    ops.push_back(this->linear_ops[i]);
  }

  return PcodeBlock(start_ind, std::move(ops),
                    this->GetBlockExitsForIndex(next_start - 1));
}


namespace {
struct IntraProcTransferCollector {
  std::vector<size_t> operator()(const InstrExit &ex) {
    return std::vector<size_t>();
  }

  std::vector<size_t> operator()(const IntrainstructionIndex &ex) {
    return std::vector<size_t>(1, ex.target_block_ind);
  }


  std::vector<size_t> operator()(const Exit &ex) {
    return std::visit(*this, ex);
  }

  std::vector<size_t> operator()(const ConditionalExit &ex) {
    std::vector<size_t> res = std::visit(*this, ex.true_branch);
    std::vector<size_t> other = std::visit(*this, ex.false_branch);
    res.insert(res.end(), other.begin(), other.end());
    return res;
  }
};
}  // namespace

std::vector<size_t> PcodeCFGBuilder::GetIntraProcTargets(size_t index) {
  std::variant<Exit, ConditionalExit> ex = this->GetBlockExitsForIndex(index);
  return std::visit(IntraProcTransferCollector{}, ex);
}

std::variant<Exit, ConditionalExit>
PcodeCFGBuilder::GetBlockExitsForIndex(size_t index) {
  CHECK(index < this->linear_ops.size());
  const auto &curr_op = this->linear_ops[index];

  auto build_direct_target_exit = [](VarnodeData target,
                                     size_t curr_ind) -> Exit {
    if (isVarnodeInConstantSpace(target)) {
      // need to treat as signed?
      return IntrainstructionIndex{curr_ind + target.offset};
    } else {
      return InstrExit{};
    }
  };
  switch (curr_op.op) {
    case CPUI_BRANCH:
    case CPUI_CALL: {
      return Exit{build_direct_target_exit(curr_op.vars[0], index)};
    }
    case CPUI_CBRANCH: {


      auto taken_exit = build_direct_target_exit(curr_op.vars[0], index);

      Exit fallthrough_exit = InstrExit{};
      // if we are not the last pcodeop then we have an intraproc fallthrough
      if (index < this->linear_ops.size() - 1) {
        fallthrough_exit = IntrainstructionIndex{index + 1};
      }

      return ConditionalExit{taken_exit, fallthrough_exit};
    }
    case CPUI_CALLIND:
    case CPUI_BRANCHIND: {
      return Exit{InstrExit{}};
    }

    default: {
      return Exit{InstrExit{}};
    }
  }
}


PcodeBlock::PcodeBlock(size_t base_index)
    : base_index(base_index),
      ops(),
      block_exit(Exit{InstrExit{}}) {}

PcodeCFG PcodeCFGBuilder::Build() {

  auto starts = this->GetBlockStarts();
  std::set s(starts.begin(), starts.end());
  starts.assign(s.begin(), s.end());

  std::unordered_map<size_t, PcodeBlock> blocks;

  if (this->linear_ops.empty()) {
    // There is no insturction at 0 to build a block at
    // build an empty block so we transfer through to exit by terminating the block
    blocks.insert({0, PcodeBlock(0)});
    return blocks;
  }

  for (size_t i = 0; i < starts.size(); i++) {
    auto next_start = this->linear_ops.size();
    if ((i + 1) < starts.size()) {
      next_start = starts[i + 1];
    }
    blocks.emplace(starts[i], this->BuildBlock(starts[i], next_start));
  }

  return PcodeCFG(blocks);
}


PcodeCFGBuilder::PcodeCFGBuilder(const std::vector<RemillPcodeOp> &linear_ops)
    : linear_ops(linear_ops) {}

PcodeCFG::PcodeCFG(std::unordered_map<size_t, PcodeBlock> blocks)
    : blocks(std::move(blocks)) {}

PcodeBlock::PcodeBlock(size_t base_index, std::vector<RemillPcodeOp> ops,
                       std::variant<Exit, ConditionalExit> block_exit)
    : base_index(base_index),
      ops(std::move(ops)),
      block_exit(std::move(block_exit)) {}

}  // namespace sleigh
}  // namespace remill