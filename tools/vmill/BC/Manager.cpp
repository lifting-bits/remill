/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <utility>

#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/CFG/BlockHasher.h"
#include "remill/CFG/CFG.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/BC/Manager.h"
#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Context/AddressSpace.h"
#include "tools/vmill/Context/Context.h"

DECLARE_string(arch);
DECLARE_string(workspace);

DEFINE_bool(enable_linear_decode, false, "Enable linear scanning within "
                                         "the basic block decoder.");

#ifndef REMILL_OS
# if defined(__APPLE__)
#   define REMILL_OS "mac"
# elif defined(__linux__)
#   define REMILL_OS "linux"
# else
#   error "Cannot infer current OS."
# endif
#endif

namespace remill {
namespace vmill {
namespace {

static DecodeMode GetDecodeMode(void) {
  return FLAGS_enable_linear_decode ? kDecodeLinear : kDecodeRecursive;
}

// Get the path to the bitcode cache file.
static std::string GetBitcodeFile(CodeVersion version) {
  std::stringstream ss;
  ss << FLAGS_workspace << "/cache." << std::hex << version << ".bc";
  auto file_name = ss.str();

  if (!FileExists(file_name) || !FileSize(file_name)) {
    auto sem_path = FindSemanticsBitcodeFile("", FLAGS_arch);
    CopyFile(sem_path, file_name);
  }

  return file_name;
}

}  // namespace

// Represents a versioned segment of code. The idea is that code will generally
// live within some contiguous range of memory, and that range can be treated
// as its own "segment". We assume that references between segments are
class BitcodeSegment {
 public:
  BitcodeSegment(llvm::LLVMContext *context, CodeVersion version_);
  ~BitcodeSegment(void);

  void UpdateIndex(void);

  std::unordered_set<uintptr_t> lifted_pcs;

  // Path the file that contains all bitcode lifted into `module`.
  const std::string bitcode_file_path;

  const std::shared_ptr<llvm::Module> module;

  const std::unique_ptr<Translator> translator;
};

BitcodeSegment::BitcodeSegment(llvm::LLVMContext *context,
                               CodeVersion version)
    : bitcode_file_path(GetBitcodeFile(version)),
      module(LoadModuleFromFile(context, bitcode_file_path)),
      translator(Translator::Create(module.get())) {

#ifndef __x86_64__
# error "Expected __x86_64__ to be defined for Arch::PrepareModule."
#endif

  Arch::Get(GetOSName(REMILL_OS), kArchAMD64) \
      ->PrepareModule(module.get());

  UpdateIndex();
}

BitcodeSegment::~BitcodeSegment(void) {
  StoreModuleToFile(module.get(), bitcode_file_path);
}

void BitcodeSegment::UpdateIndex(void) {
  // Used to update the segment's index mapping program counters
  // to the lifted functions.
  BlockCallback updater = [=] (uint64_t block_pc, uint64_t, llvm::Function *) {
    lifted_pcs.insert(block_pc);
  };

  // Run the index updated for every lifted function in the
  ForEachBlock(module.get(), updater);
}

std::unique_ptr<BitcodeManager> BitcodeManager::Create(
    llvm::LLVMContext *context_) {
  return std::unique_ptr<BitcodeManager>(new BitcodeManager(context_));
}

BitcodeManager::BitcodeManager(llvm::LLVMContext *context_)
    : context(context_),
      decoder(Decoder::Create(GetGlobalArch(), GetDecodeMode())) {}

BitcodeManager::~BitcodeManager(void) {}

std::shared_ptr<llvm::Module> BitcodeManager::GetModuleWithLiftedBlock(
    const AddressSpacePtr &memory, uint64_t pc) {

  CodeVersion version = 0;
  uint8_t first_byte = 0;

  DLOG(INFO)
      << "GetModuleWithLiftedBlock: Requesting executable code at "
      << std::hex << pc;

  if (!memory->TryReadExecutable(pc, &first_byte, &version)) {
    LOG(ERROR)
        << "Trying to translate non-executable code at " << std::hex << pc;

  } else {
    CHECK(0 != version)
        << "Version number for valid executable segment must not be 0.";
  }

  DLOG(INFO)
      << "  Segment version for " << std::hex << pc
      << " is " << std::hex << version;

  if (!segments.count(version)) {
    segments[version] = std::unique_ptr<BitcodeSegment>(
        new BitcodeSegment(context, version));
  }

  auto &segment = segments[version];

  // We haven't yet lifted the code associated with `pc`.
  if (!segment->lifted_pcs.count(pc)) {

    // Used by the decoder to read instruction bytes.
    ByteReaderCallback reader = [=] (uint64_t addr, uint8_t *byte_out) -> bool {
      return memory->TryReadExecutable(addr, byte_out, nullptr);
    };

    // Used by the decoder to name lifted functions using a hash of their
    // location and contents.
    BlockHasher hasher(version);

    // Decode bytes from memory, and place them into a CFG structure for
    // lifting.
    auto cfg = decoder->DecodeToCFG(pc, reader, hasher);

    // Lift the CFG structure into the segment's module. This will create an
    // LLVM function for every basic block of machine code.
    segment->translator->LiftCFG(cfg.get());

    segment->UpdateIndex();
  }

  return segment->module;
}

}  // namespace vmill
}  // namespace remill
