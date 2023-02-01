#include <remill/BC/PCodeCFG.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <sleigh/op.hh>
#include <sleigh/opcodes.hh>
#include <sleigh/pcoderaw.hh>
#include <variant>
#include <vector>

#include "lib/Arch/Sleigh/ControlFlowStructuring.h"

namespace remill {
namespace sleigh {

PcodeCFG CreateCFG(const std::vector<RemillPcodeOp> &linear_ops) {
  return PcodeCFGBuilder(linear_ops).Build();
}


std::vector<size_t> PcodeCFGBuilder::GetBlockStarts() const {
  std::vector<size_t> res = {0};

  for (size_t curr_index = 0; curr_index < linear_ops.size(); curr_index += 1) {
    auto interproc = GetIntraProcTargets(curr_index);
    res.insert(res.end(), interproc.begin(), interproc.end());
  }
  return res;
}

PcodeBlock PcodeCFGBuilder::BuildBlock(size_t start_ind,
                                       size_t next_start) const {
  std::vector<RemillPcodeOp> ops;

  for (size_t i = start_ind; i < next_start; i++) {
    ops.push_back(linear_ops[i]);
  }

  return PcodeBlock(start_ind, std::move(ops),
                    GetBlockExitsForIndex(next_start - 1));
}


namespace {
struct IntraProcTransferCollector {
  std::vector<size_t> operator()(const InstrExit &ex) {
    return {};
  }

  std::vector<size_t> operator()(const IntrainstructionIndex &ex) {
    return {ex.target_block_index};
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

std::vector<size_t> PcodeCFGBuilder::GetIntraProcTargets(size_t index) const {
  auto ex = GetBlockExitsForIndex(index);
  return std::visit(IntraProcTransferCollector{}, ex);
}

BlockExit PcodeCFGBuilder::GetBlockExitsForIndex(size_t index) const {
  CHECK(index < linear_ops.size());
  const auto &curr_op = linear_ops[index];

  auto build_direct_target_exit = [](VarnodeData target,
                                     size_t curr_ind) -> Exit {
    if (isVarnodeInConstantSpace(target)) {
      // need to treat as signed?
      return IntrainstructionIndex{curr_ind + target.offset};
    }
    return InstrExit{};
  };
  switch (curr_op.op) {
    case CPUI_BRANCH:
    case CPUI_CALL: {
      return Exit{build_direct_target_exit(curr_op.vars[0], index)};
    }
    case CPUI_CBRANCH: {

      auto fallthrough_exit = [this, index]() -> Exit {
        // if we are not the last pcodeop then we have an intraproc fallthrough
        if (index < linear_ops.size() - 1) {
          return IntrainstructionIndex{index + 1};
        }
        return InstrExit{};
      }();

      auto taken_exit = build_direct_target_exit(curr_op.vars[0], index);

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

PcodeCFG PcodeCFGBuilder::Build() const {

  auto starts = GetBlockStarts();
  std::set s(starts.begin(), starts.end());
  starts.assign(s.begin(), s.end());

  std::map<size_t, PcodeBlock> blocks;

  if (linear_ops.empty()) {
    // There is no insturction at 0 to build a block at
    // build an empty block so we transfer through to exit by terminating the block
    blocks.emplace(0, PcodeBlock(0));
    return blocks;
  }

  for (size_t i = 0; i < starts.size(); i++) {
    auto next_start =
        (i + 1) < starts.size() ? starts[i + 1] : linear_ops.size();
    blocks.emplace(starts[i], BuildBlock(starts[i], next_start));
  }

  return PcodeCFG(blocks);
}


PcodeCFGBuilder::PcodeCFGBuilder(const std::vector<RemillPcodeOp> &linear_ops)
    : linear_ops(linear_ops) {}

PcodeCFG::PcodeCFG(std::map<size_t, PcodeBlock> blocks)
    : blocks(std::move(blocks)) {}

PcodeBlock::PcodeBlock(size_t base_index, std::vector<RemillPcodeOp> ops,
                       BlockExit block_exit)
    : base_index(base_index),
      ops(std::move(ops)),
      block_exit(std::move(block_exit)) {}

}  // namespace sleigh
}  // namespace remill
