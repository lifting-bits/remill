/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <string>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/CFG/CFG.h"

#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"

namespace remill {
namespace vmill {
namespace {
enum : uint64_t {
  kMaxNumInstrBytes = 15ULL,
  kMaxNumInstrsPerBlock = 64ULL,
};

static std::string ReadInstructionBytes(
    uint64_t pc, ByteReaderCallback byte_reader) {
  std::string instr_bytes;
  instr_bytes.reserve(kMaxNumInstrBytes);
  for (uint64_t i = 0; i < kMaxNumInstrBytes; ++i) {
    uint8_t byte = 0;
    if (!byte_reader(pc + i, &byte)) {
      break;
    }
    instr_bytes.push_back(static_cast<char>(byte));
  }
  return instr_bytes;
}


}  // namespace

InstructionDecoder::InstructionDecoder(const Arch *arch_,
                                       const Translator *translator_)
    : arch(arch_),
      translator(translator_) {}

void InstructionDecoder::DecodeToCFG(
    uint64_t start_pc, ByteReaderCallback byte_reader,
    CFGCallback with_cfg) const {

  auto cfg_module = new cfg::Module;

  std::unordered_set<uint64_t> seen_blocks;
  std::vector<uint64_t> work_list;

  DLOG(INFO)
      << "Recursively decoding machine code, beginning at "
      << std::hex << start_pc;

  work_list.push_back(start_pc);

  auto expected_num_lifted_blocks = 0U;
  while (!work_list.empty()) {
    auto block_pc = work_list.back();
    work_list.pop_back();
    if (seen_blocks.count(block_pc)) {
      continue;  // We've already decoded this block.
    }

    seen_blocks.insert(block_pc);
    cfg_module->add_addressed_blocks(block_pc);

    // This block has already been translated.
    if (translator->HaveLiftedFunctionFor(block_pc)) {
      DLOG(INFO)
          << "Not decoding already lifted basic block at "
          << std::hex << block_pc;
      cfg_module->add_referenced_blocks(block_pc);
      continue;
    }

    DLOG(INFO)
        << "Decoding basic block at " << std::hex << block_pc;

    auto cfg_block = cfg_module->add_blocks();
    cfg_block->set_address(block_pc);

    ++expected_num_lifted_blocks;

    Instruction *instr = nullptr;
    do {
      if (instr) {
        delete instr;
      }

      auto instr_bytes = ReadInstructionBytes(block_pc, byte_reader);
      instr = arch->DecodeInstruction(block_pc, instr_bytes);
      if (instr_bytes.size() != instr->NumBytes()) {
        instr_bytes = instr_bytes.substr(0, instr->NumBytes());
      }

      auto cfg_instr = cfg_block->add_instructions();
      cfg_instr->set_address(block_pc);
      cfg_instr->set_bytes(instr_bytes);

      block_pc += instr->NumBytes();

      auto num_decoded = static_cast<size_t>(cfg_block->instructions_size());
      if (num_decoded >= kMaxNumInstrsPerBlock) {
        break;  // Early termination.
      }

    } while (instr->IsValid() && !instr->IsControlFlow());

    // Enqueue control flow targets for processing.
    switch (instr->category) {
      case Instruction::kCategoryDirectJump:
        work_list.push_back(instr->branch_taken_pc);
        break;

      case Instruction::kCategoryConditionalBranch:
        work_list.push_back(instr->branch_not_taken_pc);
        work_list.push_back(instr->branch_taken_pc);
        break;

      case Instruction::kCategoryDirectFunctionCall:
        work_list.push_back(instr->next_pc);  // Return address.
        work_list.push_back(instr->branch_taken_pc);
        break;

      case Instruction::kCategoryIndirectFunctionCall:
      case Instruction::kCategoryConditionalAsyncHyperCall:
        work_list.push_back(instr->next_pc);  // Return address.
        break;

      default:
        if (instr->IsValid() && !instr->IsControlFlow()) {
          work_list.push_back(instr->next_pc);
        }
        break;
    }

    delete instr;
  }

  DLOG(INFO)
      << "Decoded " << cfg_module->blocks_size() << " basic blocks.";
  with_cfg(cfg_module);

  delete cfg_module;
}

}  // namespace vmill
}  // namespace remill
