/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/Util.h"
#include "remill/CFG/CFG.h"
#include "remill/OS/FileSystem.h"
#include "remill/OS/OS.h"

#include "tools/vmill/BC/Lifter.h"
#include "tools/vmill/BC/Translator.h"

DECLARE_string(workspace);
DECLARE_string(os);
DECLARE_string(arch);

namespace remill {
namespace vmill {
namespace {

enum : uint64_t {
  kMaxNumInstrBytes = 15ULL,
  kMaxNumInstrsPerBlock = 16ULL,
};

// Names the bitcode file containing the lifted function at address `addr`
// in the process memory.
struct PersistentFunction {
  uint32_t file_id;
  uint32_t _0;
  uint64_t pc;
} __attribute__((packed));

static_assert (16 == sizeof(PersistentFunction),
               "Invalid packing of struct PersistentFunction");

// Get the path to the code version-specific bitcode cache directory.
static std::string GetBitcodeDir(CodeVersion code_version) {
  std::stringstream ss;
  ss << FLAGS_workspace << "/bitcode.cache/";
  CHECK(TryCreateDirectory(ss.str()))
      << "Could not create bitcode cache directory " << ss.str()
      << ": " << strerror(errno);

  ss << std::hex << code_version;
  CHECK(TryCreateDirectory(ss.str()))
      << "Could not create code version-specific bitcode cache directory "
      << ss.str() << ": " << strerror(errno);
  return ss.str();
}

static std::string ReadInstructionBytes(uint64_t pc,
                                        ByteReaderCallback byte_reader) {
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

// Handles translating binary code to bitcode, and caching that bitcode.
class TE final : public Translator {
 public:
  explicit TE(CodeVersion code_version_);
  virtual ~TE(void);

  // Execute a callback function on the module lifted by this translation.
  void WithLiftedModule(
      const uint64_t pc,
      ByteReaderCallback byte_reader,
      LiftedModuleCallback on_module) override;

  // Loads in the index of all translated code (for this version);
  void LoadIndexFromDisk(void);

  // Stores the index to disk.
  void StoreIndexToDisk(void);

 private:
  llvm::Module *LiftToModule(const uint64_t pc, ByteReaderCallback byte_reader);

  // Get the path to a bitcode file associated with a function index entry.
  std::string BitcodeFilePath(const PersistentFunction &entry) const;

  // Tries to get the lifted bitcode of the function at address `addr` in
  // the process memory, as well as all related bitcode functions in the
  // same module. Returns `false` if we can't lazy load a suitable module.
  llvm::Module *TryLazyLoadRelatedCode(llvm::LLVMContext *context,
                                       const uint64_t pc);

  // Update our internal indexes with the functions found in a module. Returns
  // the number of functions added into the index.
  uint32_t UpdateIndexWithNewModule(llvm::Module *module);

  // Architecture of the code in the process memory.
  const Arch *arch;

  // Context in which all translated code modules are stored.
  llvm::LLVMContext *context;

  // Machine code to bitcode lifter. Runs `remill-lift` and `remill-opt` as
  // a server.
  Lifter *lifter;

  // The index of function PCs and the IDs of the bitcode files containing
  // those functions.
  std::unordered_map<uintptr_t, PersistentFunction> index;

  // Directory containing cached bitcode files, each containing lifted code.
  const std::string bitcode_dir;

  // The maximum file ID.
  uint32_t next_file_id;
};

Translator::Translator(CodeVersion code_version_)
    : code_version(code_version_) {}

Translator::~Translator(void) {}

// Create a new translation engine for a given version of the code in
// memory. Code version changes happen due to self-modifying code, or
// runtime code loading.
Translator *Translator::Create(CodeVersion code_version_) {
  DLOG(INFO)
      << "Creating machine code to bitcode translator.";
  auto translator = new TE(code_version_);
  translator->LoadIndexFromDisk();
  return translator;
}

// Initialize the translation engine.
TE::TE(CodeVersion code_version_)
    : Translator(code_version_),
      arch(Arch::Create(GetOSName(FLAGS_os), GetArchName(FLAGS_arch))),
      context(new llvm::LLVMContext),
      lifter(Lifter::Create()),
      index(),
      bitcode_dir(GetBitcodeDir(code_version)),
      next_file_id(0) {}

// Destroy the translation engine.
TE::~TE(void) {
  delete context;
  delete lifter;
  delete arch;
}

llvm::Module *TE::LiftToModule(const uint64_t pc,
                               ByteReaderCallback byte_reader) {
  auto module = TryLazyLoadRelatedCode(context, pc);
  if (module) {
    return module;
  }

  auto cfg_module = new cfg::Module;
  std::set<uint64_t> seen_blocks;
  std::vector<uint64_t> work_list;

  DLOG(INFO)
      << "Recursively decoding machine code, beginning at "
      << std::hex << pc;

  work_list.push_back(pc);

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
    if (index.count(block_pc)) {
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

  module = lifter->LiftIntoContext(cfg_module, context);
  delete cfg_module;

  auto num_lifted_blocks = UpdateIndexWithNewModule(module);
  DLOG_IF(WARNING, num_lifted_blocks != expected_num_lifted_blocks)
      << "Not as many blocks were lifted as was expected. Expected "
      << expected_num_lifted_blocks << " but got " << num_lifted_blocks;

  return module;
}

// Execute a callback function on the module lifted by this translation.
void TE::WithLiftedModule(
    const uint64_t pc,
    ByteReaderCallback byte_reader,
    LiftedModuleCallback on_module) {
  auto module = LiftToModule(pc, byte_reader);
  on_module(module);
  delete module;
}

// Opens the backing file for the index and loads the entries into memory.
void TE::LoadIndexFromDisk(void) {
  auto index_path = bitcode_dir + "/index";
  auto fd = open(
      index_path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_LARGEFILE, 0666);

  CHECK(-1 != fd)
      << "Could not open or create bitcode index file " << index_path
      << ": " << strerror(errno);

  // Read the index if it's not empty.
  if (auto index_file_size = FileSize(index_path, fd)) {
    DLOG(INFO)
        << "Loading LLVM function index from " << index_path;

    auto num_entries = index_file_size / sizeof(PersistentFunction);

    auto scaled_file_size = (index_file_size + 4095ULL) & ~4095ULL;
    if (scaled_file_size > index_file_size) {
      CHECK(!ftruncate64(fd, static_cast<off64_t>(scaled_file_size)))
          << "Could not resize bitcode index file " << index_path
          << " from " << index_file_size << " to " << scaled_file_size
          << ": " << strerror(errno);
    }
    auto ret = mmap64(nullptr, scaled_file_size, PROT_READ,
                      MAP_PRIVATE | MAP_POPULATE | MAP_FILE, fd, 0);
    CHECK(MAP_FAILED != ret)
        << "Could not map bitcode index file " << index_path
        << ": " << strerror(errno);

    // Load every entry in the index into memory.
    auto entry = reinterpret_cast<const PersistentFunction *>(ret);
    const auto max_entry = entry + num_entries;
    for (; entry < max_entry; ++entry) {
      if (entry->pc) {
        index[entry->pc] = *entry;
        next_file_id = std::max(next_file_id, entry->file_id);
      }
    }

    ++next_file_id;

    DLOG(INFO)
        << "LLVM function index references " << next_file_id
        << " bitcode files, containing " << index.size()
        << " total LLVM functions for lifted basic blocks.";

    munmap(ret, scaled_file_size);
  }
  close(fd);
}

// Stores the index to disk.
void TE::StoreIndexToDisk(void) {
  DLOG(INFO)
      << "Updating bitcode index file.";

  auto tmp_index_path = bitcode_dir + "/index.tmp";
  auto fp = fopen(tmp_index_path.c_str(), "w");  // Uses `fopen` for buffering.
  if (!fp) {
    LOG(ERROR)
        << "Could not create temporary bitcode index file " << tmp_index_path
        << ": " << strerror(errno);
    return;
  }

  // Write the index to a file.
  for (const auto &entry : index) {
    if (!fwrite(&(entry.second), sizeof(PersistentFunction), 1, fp)) {
      LOG(ERROR)
          << "Could not write index entry into temporary bitcode index file "
          << tmp_index_path << ": " << strerror(errno);
      return;
    }
  }

  if (EOF == fclose(fp)) {
    LOG(ERROR)
        << "Could not close temporary bitcode index file "
        << tmp_index_path << ": " << strerror(errno);
    return;
  }

  DLOG(INFO)
      << "Saved bitcode index referencing " << next_file_id
      << " bitcode files containing " << index.size() << " functions to "
      << tmp_index_path;

  // Atomically replace the existing index file.
  auto index_path = bitcode_dir + "/index";
  LOG_IF(ERROR, rename(tmp_index_path.c_str(), index_path.c_str()))
      << "Could not overwrite " << index_path << " with "
      << tmp_index_path << ": " << strerror(errno);
}

// Get the path to a bitcode file associated with a function index entry.
std::string TE::BitcodeFilePath(const PersistentFunction &entry) const {
  std::stringstream ss;
  ss << bitcode_dir << "/" << entry.file_id << ".bc";
  return ss.str();
}

// Tries to get the lifted bitcode of the function at address `addr` in
// the process memory, as well as all related bitcode functions in the
// same module. Returns `false` if we can't lazy load a suitable module.
llvm::Module *TE::TryLazyLoadRelatedCode(llvm::LLVMContext *context,
                                         const uint64_t pc) {
  auto entry_it = index.find(pc);
  if (index.end() == entry_it) {
    DLOG(INFO)
        << "LLVM function for machine code at " << std::hex << pc
        << " doesn't exist in memory or in the persistent cache.";

    return nullptr;  // Have never seen this function; need to translate.
  }

  DLOG(INFO)
      << "Loading LLVM function for machine code at " << std::hex << pc
      << " from the persistent cache.";

  // OK, the function exists in our index and is contained in a bitcode
  // file named by the entry's `file_id`.
  PersistentFunction entry = entry_it->second;

  auto bc_path = BitcodeFilePath(entry);
  CHECK(FileExists(bc_path))
      << "Bitcode file " << bc_path << " doesn't exist!";

  // Load every function in the module into our lookup table.
  auto module = LoadModuleFromFile(context, bc_path);

  // The function should not be loaded in; we assume that it is in the bitcode
  // module that we just loaded.
  CHECK(index.count(pc))
      << "Could not find __remill_sub_" << std::hex << pc
      << " in bitcode file " << bc_path;

  return module;
}

// Update our internal indexes with the functions found in a module. Returns
// the number of functions added into the index.
uint32_t TE::UpdateIndexWithNewModule(llvm::Module *module) {
  const auto &module_id = module->getModuleIdentifier();

  auto old_index_size = index.size();

  Lifter::ForEachLiftedFunctionInModule(module,
      [&module_id, this] (uint64_t block_pc, llvm::Function *lifted_func) {
        auto func_name = lifted_func->getName().str();
        auto in_index = index.count(block_pc);

        if (lifted_func->isDeclaration()) {
          CHECK(in_index)
              << "Function " << func_name << " is declared in "
              << module_id << " but not available in the global index.";
          return;
        }

        CHECK(!in_index)
            << "Function " << func_name << " is defined in "
            << module_id << " but has a conflicting entry in the global index.";

        index[block_pc] = {next_file_id, 0, block_pc};
      });

  auto num_loaded = index.size() - old_index_size;
  CHECK(num_loaded)
      << "No lifted functions loaded from module " << module_id;

  // Save the bitcode to disk.
  DLOG(INFO)
      << "Persisting " << num_loaded << " LLVM functions to disk.";

  PersistentFunction dummy_entry = {next_file_id++, 0, 0};
  remill::StoreModuleToFile(module, BitcodeFilePath(dummy_entry));
  StoreIndexToDisk();

  return num_loaded;
}

}  // namespace vmill
}  // namespace remill
