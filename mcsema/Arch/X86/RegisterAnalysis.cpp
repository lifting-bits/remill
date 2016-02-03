/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>

#include "mcsema/Arch/X86/Decode.h"
#include "mcsema/Arch/X86/RegisterAnalysis.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(aggressive_dataflow_analysis);

namespace mcsema {
namespace x86 {

struct Function {
  std::vector<uint64_t> tail_call_source_blocks;
  std::vector<uint64_t> return_target_blocks;
};

namespace {

// Find the successor blocks of an instruction.
static FlowType FindSuccessors(const xed_decoded_inst_t *xedd,
                               uint64_t curr_pc, uint64_t next_pc,
                               std::vector<uint64_t> &succs) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, 0);
  auto op_name = xed_operand_name(xedo);
  auto disp = xed_decoded_inst_get_branch_displacement(xedd);
  auto target_pc = static_cast<uintptr_t>(next_pc + disp);

  switch (auto category = xed_decoded_inst_get_category(xedd)) {
    case XED_CATEGORY_UNCOND_BR:
    case XED_CATEGORY_CALL:
      if (XED_OPERAND_RELBR == op_name) {
        succs.push_back(target_pc);
        if (XED_CATEGORY_CALL == category) {
          return kFlowCall;
        } else {
          return kFlowLocal;
        }
      } else {
        if (XED_CATEGORY_CALL == category) {
          return kFlowIndirectCall;
        } else {
          return kFlowUnknown;
        }
      }

    case XED_CATEGORY_COND_BR:
      if (XED_OPERAND_RELBR == op_name) {
        succs.push_back(target_pc);
        succs.push_back(next_pc);
        return kFlowLocal;
      } else {
        return kFlowUnknown;
      }

    case XED_CATEGORY_RET:
      return kFlowReturn;

    case XED_CATEGORY_SYSCALL:
      return kFlowSysCall;

    case XED_CATEGORY_SYSRET:
      return kFlowUnknown;

    default:
      succs.push_back(next_pc);
      return kFlowLocal;
  }
}

}  // namespace

void RegisterAnalysis::AddFunction(const cfg::Function &func) {
  if (!FLAGS_aggressive_dataflow_analysis) return;
  if (func.is_imported() || func.is_weak()) return;
  auto &f = functions[func.address()];
  if (!f) {
    f = new Function;
  }
}

void RegisterAnalysis::AddBlock(const cfg::Block &block) {
  auto bb = new BasicBlockRegs;
  bb->live_exit.flat = 0U;
  bb->live_entry.flat = 0U;
  bb->keep_alive.flat = 0U;
  bb->address = block.address();
  bb->flow = kFlowUnknown;

  auto it_begin = block.instructions().rbegin();
  auto it_end = block.instructions().rend();
  for (auto it = it_begin; it != it_end; ++it) {
    const auto &instr = *it;
    const auto xedd = DecodeInstruction(instr, arch_name);

    if (it == it_begin) {
      const auto next_pc = instr.address() + instr.size();
      bb->flow = FindSuccessors(
          &xedd, instr.address(), next_pc, bb->successors);

      if (!FLAGS_aggressive_dataflow_analysis) continue;

      // Identify functions as those pieces of code that are observed to be
      // the targets of function calls.
      if (kFlowCall == bb->flow) {
        auto target_pc = bb->successors[0];
        auto &func = functions[target_pc];
        if (!func) {
          func = new Function;
        }

        // Tell functions about where we think they return to, and connect
        // the before/after call blocks so that we can propagate function
        // identification around calls.
        func->return_target_blocks.push_back(next_pc);
        ret_blocks[block.address()] = next_pc;

      // Connect blocks before/after syscalls and indirect calls as being
      // potentially belonging to the same function.
      } else if (kFlowSysCall == bb->flow || kFlowIndirectCall == bb->flow) {
        ret_blocks[block.address()] = next_pc;
      }
    }

    if (const auto rflags = xed_decoded_inst_get_rflags_info(&xedd)) {
      bb->keep_alive.flat |= rflags->written.flat;
      bb->keep_alive.flat |= rflags->undefined.flat;
      bb->keep_alive.flat &= ~(rflags->read.flat);
    }
  }

  bb->keep_alive.flat = ~bb->keep_alive.flat;
  bb->live_entry.flat = bb->live_exit.flat & bb->keep_alive.flat;

  blocks[block.address()] = bb;
}

void RegisterAnalysis::InitWorkList(AnalysisWorkList &work_list) {
  std::set<BasicBlockRegs *> func_wl;

  for (auto b : blocks) {
    auto block_pc = b.first;
    auto block = b.second;

    // Initialize function entry points.
    if (FLAGS_aggressive_dataflow_analysis) {
      if (functions[block_pc]) {
        func_wl.insert(block);
      }
    }

    // Connect successors to predecessors.
    for (auto succ_pc : block->successors) {
      auto succ_block = blocks[succ_pc];
      succ_block->predecessors.push_back(block_pc);

      if (!FLAGS_aggressive_dataflow_analysis) continue;

      // If a successor is marked as a function entry point and if the flow
      // from this block to its successor is "local", i.e. direct jump or
      // conditional branch, then consider it to be a tail-call.
      if (kFlowLocal == block->flow) {
        if (auto succ_func = functions[succ_pc]) {
          succ_func->tail_call_source_blocks.push_back(block_pc);
        }
      }
    }
  }

  // Iteratively "spread" the function assignments.
  while (func_wl.size()) {

    // Propagate function identification through control-flows.
    while (func_wl.size()) {
      std::set<BasicBlockRegs *> next_func_wl;
      for (auto block : next_func_wl) {
        if (kFlowLocal != block->flow) continue;
        for (auto succ_pc : block->successors) {
          auto succ_block = blocks[succ_pc];
          auto &succ_func = functions[succ_pc];
          if (!succ_func) {
            succ_func = functions[block->address];
            next_func_wl.insert(succ_block);
          }
        }
      }
      func_wl.swap(next_func_wl);
    }

    // Try to push the work forward by propagation function identification
    // around function calls.
    for (auto rb : ret_blocks) {
      auto call_block_pc = rb.first;
      auto ret_block_pc = rb.second;
      if (auto call_func = functions[call_block_pc]) {
        if (auto ret_block = blocks[ret_block_pc]) {
          auto &ret_func = functions[ret_block_pc];
          if (!ret_func) {
            ret_func = call_func;
            func_wl.insert(ret_block);
          }
        }
      }
    }
  }

  // Function assignments have been spread.
  for (auto f : functions) {
    auto func = f.second;
    if (!func) continue;

    // Spread return addresses through tail-called functions.
    for (auto tail_call_block_pc : func->tail_call_source_blocks) {
      if (auto caller = functions[tail_call_block_pc]) {
        func->return_target_blocks.insert(func->return_target_blocks.end(),
                                          caller->return_target_blocks.begin(),
                                          caller->return_target_blocks.end());
      }
    }
  }

  // Connect return instructions to their return points.
  if (FLAGS_aggressive_dataflow_analysis) {
    for (auto b : blocks) {
      auto block_pc = b.first;
      auto block = b.second;
      if (!block || kFlowReturn != block->flow) continue;

      if (auto block_func = functions[block_pc]) {
        for (auto target_pc : block_func->return_target_blocks) {
          if (auto target_block = blocks[target_pc]) {
            target_block->predecessors.push_back(block_pc);
            block->successors.push_back(target_pc);
          }
        }
      }
    }
  }

  // Initialize the worklist for dead flags and register analysis across the
  // control-flow graph.
  for (auto b : blocks) {
    auto block_pc = b.first;
    auto block = b.second;
    work_list.insert({block->predecessors.size(), block_pc});
  }
}

void RegisterAnalysis::AnalyzeBlock(AnalysisWorkItem item,
                                    AnalysisWorkList &work_list) {
  auto bb = blocks[item.pc];
  if (!bb) return;

  // If we're not being conservative, then we'll assume that every indirect flow
  // kills all the flags.
  auto incoming_live = FLAGS_aggressive_dataflow_analysis ? 0U : ~0U;

  for (auto succ_pc : bb->successors) {
    incoming_live |= LiveFlags(succ_pc);
  }

  auto live_entry = incoming_live & bb->keep_alive.flat;
  if (live_entry != bb->live_entry.flat) {
    bb->live_entry.flat = live_entry;

    // Update the work list.
    for (auto pred_pc : bb->predecessors) {
      auto pred_bb = blocks[pred_pc];
      work_list.insert({pred_bb->predecessors.size(), pred_pc});
    }
  }
}

uint32_t RegisterAnalysis::LiveFlags(uint64_t pc) {
  if (const auto block = blocks[pc]) {
    return block->live_entry.flat;

  // This is basically an error case anyway, i.e. we have a direct flow that
  // we can't resolve. This will be warned about during the lifting phase.
  } else {
    return ~0U;
  }
}

}  // namespace x86
}  // namespace mcsema
