/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

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

inline uint16_t operator "" _u16(unsigned long long value) {
  return static_cast<uint16_t>(value);
}

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
    case XED_CATEGORY_INTERRUPT:
      return kFlowSysCall;

    case XED_CATEGORY_SYSRET:
      return kFlowUnknown;

    default:
      succs.push_back(next_pc);
      return kFlowLocal;
  }
}

static void UpdateSet(RegisterSet *regs, xed_reg_enum_t reg, bool is_live) {

  // Writes of 8- and 16-bit regs don't clear all bits.
  if (!is_live && 32 > xed_get_register_width_bits64(reg)) {
    is_live = true;
  }

  switch (xed_get_largest_enclosing_register(reg)) {
    case XED_REG_RAX: regs->s.rax = is_live; break;
    case XED_REG_RCX: regs->s.rcx = is_live; break;
    case XED_REG_RDX: regs->s.rdx = is_live; break;
    case XED_REG_RBX: regs->s.rbx = is_live; break;
    case XED_REG_RSP: regs->s.rsp = is_live; break;
    case XED_REG_RBP: regs->s.rbp = is_live; break;
    case XED_REG_RSI: regs->s.rsi = is_live; break;
    case XED_REG_RDI: regs->s.rdi = is_live; break;
    case XED_REG_R8: regs->s.r8 = is_live; break;
    case XED_REG_R9: regs->s.r9 = is_live; break;
    case XED_REG_R10: regs->s.r10 = is_live; break;
    case XED_REG_R11: regs->s.r11 = is_live; break;
    case XED_REG_R12: regs->s.r12 = is_live; break;
    case XED_REG_R13: regs->s.r13 = is_live; break;
    case XED_REG_R14: regs->s.r14 = is_live; break;
    case XED_REG_R15: regs->s.r15 = is_live; break;
    default: break;
  }
}

static void VisitMemory(RegisterSet *revive, RegisterSet *kill,
                        const xed_decoded_inst_t *xedd, unsigned mem_index) {
  auto base = xed_decoded_inst_get_base_reg(xedd, mem_index);
  auto index = xed_decoded_inst_get_index_reg(xedd, mem_index);
  UpdateSet(revive, base, true);
  UpdateSet(revive, index, true);

  UpdateSet(kill, base, true);
  UpdateSet(kill, index, true);
}

static void VisitRegister(RegisterSet *revive, RegisterSet *kill,
                          const xed_decoded_inst_t *xedd,
                          const xed_operand_t *xedo, unsigned op_num) {
  auto op_name = xed_operand_name(xedo);
  auto reg = xed_decoded_inst_get_reg(xedd, op_name);
  auto is_live = xed_operand_read(xedo) || xed_operand_conditional_write(xedo);
  UpdateSet(revive, reg, is_live);
  UpdateSet(kill, reg, is_live);
}

static void VisitOperand(RegisterSet *revive, RegisterSet *kill,
                         const xed_decoded_inst_t *xedd, unsigned op_num) {
  auto xedi = xed_decoded_inst_inst(xedd);
  auto xedo = xed_inst_operand(xedi, op_num);
  switch (auto op_name = xed_operand_name(xedo)) {
    case XED_OPERAND_AGEN:
    case XED_OPERAND_MEM0:
      VisitMemory(revive, kill, xedd, 0);
      break;
    case XED_OPERAND_MEM1:
      VisitMemory(revive, kill, xedd, 1);
      break;

    case XED_OPERAND_REG:
    case XED_OPERAND_REG0:
    case XED_OPERAND_REG1:
    case XED_OPERAND_REG2:
    case XED_OPERAND_REG3:
    case XED_OPERAND_REG4:
    case XED_OPERAND_REG5:
    case XED_OPERAND_REG6:
    case XED_OPERAND_REG7:
    case XED_OPERAND_REG8:
      VisitRegister(revive, kill, xedd, xedo, op_num);
      break;

    default:
      break;
  }
}

// Update the live registers based on the current instructions.
static void VisitInstruction(RegisterSet *revive, RegisterSet *kill,
                             const xed_decoded_inst_t *xedd) {
  auto num_operands = xed_decoded_inst_noperands(xedd);
  for (auto i = 0U; i < num_operands; ++i) {
    VisitOperand(revive, kill, xedd, i);
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
  bb->flags.live_anywhere.flat = 0U;
  bb->flags.live_exit.flat = ~0U;
  bb->flags.live_entry.flat = 0U;
  bb->flags.kill.flat = ~0U;
  bb->flags.revive.flat = 0U;

  bb->regs.live_exit.flat = ~0_u16;
  bb->regs.live_entry.flat = 0_u16;
  bb->regs.kill.flat = ~0_u16;
  bb->flags.revive.flat = 0_u16;

  bb->address = block.address();
  bb->flow = kFlowUnknown;

  auto it_begin = block.instructions().rbegin();
  auto it_end = block.instructions().rend();
  for (auto it = it_begin; it != it_end; ++it) {
    const auto &instr = *it;
    const auto xedd = DecodeInstruction(instr, arch_name);

    if (const auto rflags = xed_decoded_inst_get_rflags_info(&xedd)) {
      bb->flags.live_anywhere.flat |= rflags->read.flat;

      bb->flags.kill.flat &= ~rflags->written.flat;
      bb->flags.kill.flat &= ~rflags->undefined.flat;
      bb->flags.kill.flat |= rflags->read.flat;

      bb->flags.revive.flat &= ~rflags->written.flat;
      bb->flags.revive.flat &= ~rflags->undefined.flat;
      bb->flags.revive.flat |= rflags->read.flat;
    }

    VisitInstruction(&(bb->regs.revive), &(bb->regs.kill), &xedd);

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
  }

  bb->regs.live_entry = bb->regs.kill;
  bb->flags.live_entry = bb->flags.kill;

  blocks[block.address()] = bb;
}

void RegisterAnalysis::InitWorkList(AnalysisWorkList &work_list) {
  std::set<BasicBlockRegs *> func_wl;

  for (auto b : blocks) {
    auto block_pc = b.first;
    auto block = b.second;

    if (!block) continue;

    // Initialize function entry points.
    if (FLAGS_aggressive_dataflow_analysis) {
      if (functions[block_pc]) {
        func_wl.insert(block);
      }
    }

    // Connect successors to predecessors.
    for (auto succ_pc : block->successors) {
      auto succ_block = blocks[succ_pc];
      if (!succ_block) {
        LOG(WARNING)
            << "Block " << succ_pc << ", successor of "
            << block_pc << " is missing.";
        continue;
      }

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

  // Do some ahead-of-time work to kill any flags that are never read anywhere
  // in the program.
  live_anywhere = 0U;
  for (auto b : blocks) {
    if (auto block = b.second) {
      live_anywhere |= block->flags.live_anywhere.flat;
    }
  }

  // Initialize the worklist for dead flags and register analysis across the
  // control-flow graph.
  for (auto b : blocks) {
    if (auto block = b.second) {

      // Try to kill globally unused flags.
      block->flags.live_entry.flat &= live_anywhere;
      block->flags.live_exit.flat &= live_anywhere;
      block->flags.kill.flat &= live_anywhere;

      work_list.insert({block->predecessors.size(), b.first});
    }
  }
}

void RegisterAnalysis::AnalyzeBlock(AnalysisWorkItem item,
                                    AnalysisWorkList &work_list) {
  auto bb = blocks[item.pc];
  if (!bb) {
    return;
  }

  // If we're not being conservative, then we'll assume that every indirect flow
  // kills all the flags.
  uint32_t incoming_flags = FLAGS_aggressive_dataflow_analysis ?
                            0U :
                            live_anywhere;
  uint16_t incoming_regs = bb->successors.empty() ? ~0_u16 : 0_u16;

  // Try to collect flags across system calls.
  if (kFlowSysCall == bb->flow) {
    if (auto succ_pc = ret_blocks[item.pc]) {
      incoming_flags |= LiveFlags(succ_pc);
    }

  } else {
    for (auto succ_pc : bb->successors) {
      incoming_flags |= LiveFlags(succ_pc);
      incoming_regs |= LiveRegs(succ_pc);
    }
  }

  auto changed = false;
  auto new_entry_flags = (incoming_flags & bb->flags.kill.flat) |
                         bb->flags.revive.flat;
  auto new_entry_regs = (incoming_regs & bb->regs.kill.flat) |
                        bb->regs.revive.flat;

  bb->flags.live_exit.flat = incoming_flags;

  if (new_entry_flags != bb->flags.live_entry.flat) {
    bb->flags.live_entry.flat = new_entry_flags;
    changed = true;
  }

  bb->regs.live_exit.flat = incoming_regs;
  if (new_entry_regs != bb->regs.live_entry.flat) {
    bb->regs.live_entry.flat = new_entry_regs;
    changed = true;
  }

  // Update the work list.
  if (changed) {
    for (auto pred_pc : bb->predecessors) {
      auto pred_bb = blocks[pred_pc];
      work_list.insert({pred_bb->predecessors.size(), pred_pc});
    }
  }
}

void RegisterAnalysis::Finalize(void) {
  for (auto bp : blocks) {
    if (0x4026c0 == bp.first) {
      asm("nop;");
    }
    if (auto block = bp.second) {
      block->flags.revive = block->flags.live_exit;
      block->flags.kill = block->flags.live_exit;
      block->regs.revive = block->regs.live_exit;
      block->regs.kill = block->regs.live_exit;
    }
  }
}

uint32_t RegisterAnalysis::LiveFlags(uint64_t pc) {
  if (const auto block = blocks[pc]) {
    return block->flags.live_entry.flat;

  // This is basically an error case anyway, i.e. we have a direct flow that
  // we can't resolve. This will be warned about during the lifting phase.
  } else {
    return FLAGS_aggressive_dataflow_analysis ? 0U : live_anywhere;
  }
}

uint16_t RegisterAnalysis::LiveRegs(uint64_t pc) {
  if (const auto block = blocks[pc]) {
    return block->regs.live_entry.flat;
  } else {
    return ~0_u16;
  }
}

void BasicBlockRegs::UpdateEntryLive(const xed_decoded_inst_t *xedd) {
  if (const auto rflags = xed_decoded_inst_get_rflags_info(xedd)) {
    flags.revive.flat &= ~(rflags->written.flat | rflags->undefined.flat);
    flags.revive.flat |= rflags->read.flat;


    flags.kill.flat &= ~(rflags->written.flat | rflags->undefined.flat);
    flags.kill.flat |= rflags->read.flat;
  }

  VisitInstruction(&(regs.revive), &(regs.kill), xedd);
}

}  // namespace x86
}  // namespace mcsema
