/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <algorithm>
#include <limits>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/CFG/BlockHasher.h"
#include "remill/CFG/CFG.h"

#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"

namespace remill {
namespace vmill {
namespace {

enum : uint64_t {
  kMaxNumInstrBytes = 15ULL,
};

// Read instruction bytes using `byte_reader`.
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

union WorkListItem {
  enum ScanType {
    kScanRecursive = 0,
    kScanLinear = 1
  };

  uint64_t flat;

  struct {
    int64_t address:63;
    ScanType scan_type:1;
  } __attribute__((packed));

  WorkListItem(uint64_t a, ScanType s)
      : address(static_cast<int64_t>(a)),
        scan_type(s)  {}

  // Sort recursive scans by preference, and within recursive scans,
  // process code in linear order.
  inline bool operator<(const WorkListItem &other) const {
    return flat < other.flat;
  }

  inline bool operator==(const WorkListItem &other) const {
    return flat == other.flat;
  }

  inline bool operator!=(const WorkListItem &other) const {
    return flat != other.flat;
  }
} __attribute__((packed));

using DecoderWorkList = std::set<WorkListItem>;

// Enqueue control flow targets for processing. In some cases we enqueue
// work as being derived from a linear scan rather tha from a recursive
// scan.
static void AddEntries(const Instruction *instr, DecoderWorkList &work_list) {
  switch (instr->category) {
    case Instruction::kCategoryInvalid:
    case Instruction::kCategoryError:
      break;

    case Instruction::kCategoryIndirectJump:
    case Instruction::kCategoryFunctionReturn:
    case Instruction::kCategoryAsyncHyperCall:
      work_list.insert({instr->next_pc, WorkListItem::kScanLinear});
      break;

    case Instruction::kCategoryNormal:
      work_list.insert(  // Return address / not taken target.
          {instr->next_pc, WorkListItem::kScanRecursive});
      break;

    case Instruction::kCategoryNoOp:
      work_list.insert({instr->next_pc, WorkListItem::kScanLinear});
      break;

    case Instruction::kCategoryDirectJump:
      work_list.insert(
          {instr->branch_taken_pc, WorkListItem::kScanRecursive});
      work_list.insert({instr->next_pc, WorkListItem::kScanLinear});
      break;

    case Instruction::kCategoryIndirectFunctionCall:
      work_list.insert(  // Return address.
          {instr->next_pc, WorkListItem::kScanRecursive});
      break;

    case Instruction::kCategoryDirectFunctionCall:
      work_list.insert(
          {instr->branch_taken_pc, WorkListItem::kScanRecursive});
      work_list.insert(  // Return address.
          {instr->next_pc, WorkListItem::kScanRecursive});
      break;

    case Instruction::kCategoryConditionalBranch:
      work_list.insert(
          {instr->branch_taken_pc, WorkListItem::kScanRecursive});
      work_list.insert(  // Not-taken path.
          {instr->next_pc, WorkListItem::kScanRecursive});
      break;

    case Instruction::kCategoryConditionalAsyncHyperCall:
      work_list.insert(  // Return address.
          {instr->next_pc, WorkListItem::kScanRecursive});
      break;
  }
}

}  // namespace

std::unique_ptr<Decoder> Decoder::Create(const Arch *arch_, DecodeMode mode_) {
  return std::unique_ptr<Decoder>(new Decoder(arch_, mode_));
}

Decoder::Decoder(const Arch *arch_, DecodeMode mode_)
    : arch(arch_),
      mode(mode_) {}

std::unique_ptr<cfg::Module> Decoder::DecodeToCFG(
    uint64_t start_pc, ByteReaderCallback byte_reader,
    BlockHasher &hasher) {

  std::unique_ptr<cfg::Module> cfg_module(new cfg::Module);
  DecoderWorkList work_list;

  DLOG(INFO)
      << "Recursively decoding machine code, beginning at "
      << std::hex << start_pc;

  work_list.insert({start_pc, WorkListItem::kScanRecursive});

  auto min_recursive_pc = std::numeric_limits<uint64_t>::max();
  auto max_recursive_pc = std::numeric_limits<uint64_t>::min();

  while (!work_list.empty()) {
    auto entry_it = work_list.begin();
    const auto entry = *entry_it;
    work_list.erase(entry_it);

    const auto scan_type = entry.scan_type;
    auto block_pc = static_cast<uint64_t>(entry.address  /* sign extends */);

    if (seen_blocks.count(block_pc)) {
      continue;
    }

    if (WorkListItem::kScanRecursive == scan_type) {
      min_recursive_pc = std::min(min_recursive_pc, block_pc);
      max_recursive_pc = std::max(max_recursive_pc, block_pc);

    // Only follow linear scans as long as they are within the bounds of
    // the min/max bounds of the recursive scans.
    //
    // Note: Linear scans that induce recursive ones, e.g. linear scanning
    //       a block ending in a conditional jump, can result in the bounds
    //       widening over time to encompass increasingly more code.
    } else if (min_recursive_pc > block_pc || max_recursive_pc <= block_pc) {
      DLOG(INFO)
          << "Stopping linear decoding; block at " << std::hex << block_pc
          << " is outside of recursively discovered bounds ["
          << min_recursive_pc << ", " << max_recursive_pc << ")";
      work_list.clear();
      break;

    } else if (kDecodeRecursive == mode) {
      work_list.clear();
      break;
    }

    Instruction *instr = nullptr;
    cfg::Block *cfg_block = nullptr;

    do {
      if (instr) {
        delete instr;
        instr = nullptr;
      }

      // End this block early; the subsequent block already exists.
      if (seen_blocks.count(block_pc)) {
        break;
      }

      auto instr_bytes = ReadInstructionBytes(block_pc, byte_reader);
      instr = arch->DecodeInstruction(block_pc, instr_bytes);
      if (instr_bytes.size() != instr->NumBytes()) {
        instr_bytes = instr_bytes.substr(0, instr->NumBytes());
      }

      if (!cfg_block) {

        // If we're doing a linear scan and we find a NOP then split the block
        // early. The idea here is that some functions are aligned to certain
        // byte boundaries, and the alignment may sometimes use NOPs. The net
        // effect is that NOPs will only be included in recursively decoded
        // blocks, and will otherwise be skipped.
        if (WorkListItem::kScanLinear == scan_type && instr->IsNoOp()) {
          DLOG(INFO)
              << "Skipping block starting with a NOP at "
              << std::hex << block_pc;
          break;
        }

        cfg_block = cfg_module->add_blocks();
        cfg_block->set_address(block_pc);
        seen_blocks.insert(block_pc);
      }

      auto cfg_instr = cfg_block->add_instructions();
      cfg_instr->set_address(block_pc);
      cfg_instr->set_bytes(instr_bytes);
      block_pc += instr->NumBytes();

    } while (instr->IsValid() && !instr->IsControlFlow());

    if (cfg_block) {
      cfg_block->set_id(hasher.HashBlock(*cfg_block));
      if (instr) {
        AddEntries(instr, work_list);
        delete instr;
        instr = nullptr;
      }
    }
  }

  seen_blocks.clear();

  DLOG(INFO)
      << "Decoded " << cfg_module->blocks_size() << " basic blocks.";

  return cfg_module;
}

}  // namespace vmill
}  // namespace remill
