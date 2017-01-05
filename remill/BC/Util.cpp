/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/Bitcode/ReaderWriter.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

namespace remill {

// Initialize the attributes for a lifted function.
void InitFunctionAttributes(llvm::Function *function) {

  // Make sure functions are treated as if they return. LLVM doesn't like
  // mixing must-tail-calls with no-return.
  function->removeFnAttr(llvm::Attribute::NoReturn);

  // Don't use any exception stuff.
  function->addFnAttr(llvm::Attribute::NoUnwind);
  function->removeFnAttr(llvm::Attribute::UWTable);

  // To use must-tail-calls everywhere we need to use the `fast` calling
  // convention, where it's up the LLVM to decide how to pass arguments.
  //
  // TODO(pag): This may end up being finicky down the line when trying to
  //            integrate lifted code function with normal C/C++-defined
  //            intrinsics.
  function->setCallingConv(llvm::CallingConv::Fast);

  // Mark everything for inlining.
  function->addFnAttr(llvm::Attribute::AlwaysInline);
  function->addFnAttr(llvm::Attribute::InlineHint);
}

// Create a tail-call from one lifted function to another.
void AddTerminatingTailCall(llvm::Function *source_func,
                            llvm::Value *dest_func) {
  if (source_func->isDeclaration()) {
    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(
        source_func->getContext(), "", source_func));

    std::vector<llvm::Value *> args;
    for (llvm::Argument &arg : source_func->args()) {
      args.push_back(&arg);
    }
    llvm::CallInst *call_target_instr = ir.CreateCall(dest_func, args);

    // Make sure we tail-call from one block method to another.
    call_target_instr->setTailCallKind(llvm::CallInst::TCK_MustTail);
    call_target_instr->setCallingConv(llvm::CallingConv::Fast);
    ir.CreateRetVoid();
  } else {
    AddTerminatingTailCall(&(source_func->back()), dest_func);
  }
}

void AddTerminatingTailCall(llvm::BasicBlock *source_block,
                            llvm::Value *dest_func) {
  CHECK(nullptr != dest_func)
      << "Target function/block does not exist!";

  LOG_IF(ERROR, source_block->getTerminator() ||
                source_block->getTerminatingMustTailCall())
      << "Block already has a terminator; not adding fall-through call to: "
      << (dest_func ? dest_func->getName().str() : "<unreachable>");

  llvm::IRBuilder<> ir(source_block);

  // Set up arguments according to our ABI.
  std::vector<llvm::Value *> args(kNumBlockArgs);
  args[kMemoryPointerArgNum] = LoadMemoryPointer(source_block);
  args[kStatePointerArgNum] = LoadStatePointer(source_block);
  args[kPCArgNum] = LoadProgramCounter(source_block);

  // We may introduce variables like `__remill_jump_0xf00` that boils down to
  // meaning the `__remill_jump` at offset `0xf00` within the lifted binary.
  // Being able to know what jump in the lifted bitcode corresponds with a
  // jump as a specific area in the binary is useful for introducing things
  // switch instructions to handle statically known jump tables.
  if (!llvm::isa<llvm::Function>(dest_func)) {
    dest_func = ir.CreateLoad(dest_func);
  }

  llvm::CallInst *call_target_instr = ir.CreateCall(dest_func, args);

  // Make sure we tail-call from one block method to another.
  call_target_instr->setTailCallKind(llvm::CallInst::TCK_MustTail);
  call_target_instr->setCallingConv(llvm::CallingConv::Fast);
  ir.CreateRetVoid();
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::BasicBlock *block,
                               std::string name,
                               bool allow_failure) {
  return FindVarInFunction(block->getParent(), name, allow_failure);
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::Function *function, std::string name,
                               bool allow_failure) {
  for (auto &instr : function->getEntryBlock()) {
    if (instr.getName() == name) {
      return &instr;
    }
  }

  CHECK(allow_failure)
      << "Could not find variable " << name << " in function "
      << function->getName().str();
  return nullptr;
}

// Find the machine state pointer.
llvm::Value *LoadStatePointer(llvm::Function *function) {
  CHECK(kNumBlockArgs == function->arg_size())
      << "Invalid block-like function. Expected two arguments: state "
      << "pointer and program counter in function "
      << function->getName().str();

  static_assert(1 == kStatePointerArgNum,
                "Expected state pointer to be the first operand.");

  return NthArgument(function, kStatePointerArgNum);
}

llvm::Value *LoadStatePointer(llvm::BasicBlock *block) {
  return LoadStatePointer(block->getParent());
}

// Return the current program counter.
llvm::Value *LoadProgramCounter(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(LoadProgramCounterRef(block));
}

// Return a reference to the current program counter.
llvm::Value *LoadProgramCounterRef(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(FindVarInFunction(block->getParent(), "PC"));
}

// Return the current memory pointer.
llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(LoadMemoryPointerRef(block));
}

// Return a reference to the memory pointer.
llvm::Value *LoadMemoryPointerRef(llvm::BasicBlock *block) {
  return FindVarInFunction(block->getParent(), "MEMORY");
}

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(const llvm::Module *module, std::string name) {
  return module->getFunction(name);
}

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(const llvm::Module *module,
                                        std::string name) {
  return module->getGlobalVariable(name);
}

// Reads an LLVM module from a file.
llvm::Module *LoadModuleFromFile(llvm::LLVMContext *context,
                                 std::string file_name) {
  llvm::SMDiagnostic err;
  auto mod_ptr = llvm::parseIRFile(file_name, err, *context);
  auto module = mod_ptr.get();
  mod_ptr.release();

  CHECK(nullptr != module)
      << "Unable to parse module file: " << file_name << ".";

  module->materializeAll();  // Just in case.

  std::string error;
  llvm::raw_string_ostream error_stream(error);
  if (llvm::verifyModule(*module, &error_stream)) {
    error_stream.flush();
    LOG(FATAL)
        << "Error reading module from file " << file_name << ": " << error;
  }

  return module;
}

// Store an LLVM module into a file.
void StoreModuleToFile(llvm::Module *module, std::string file_name) {
  std::stringstream ss;
  ss << file_name << ".tmp." << getpid();
  auto tmp_name = ss.str();

  std::string error;
  llvm::raw_string_ostream error_stream(error);

  if (llvm::verifyModule(*module, &error_stream)) {
    error_stream.flush();
    LOG(FATAL)
        << "Error writing module to file " << file_name << ": " << error;
  }

  std::error_code ec;
  llvm::tool_output_file bc(tmp_name.c_str(), ec, llvm::sys::fs::F_RW);

  CHECK(!ec)
      << "Unable to open output bitcode file for writing: " << tmp_name;

  llvm::WriteBitcodeToFile(module, bc.os());
  bc.keep();
  if (!ec) {
    RenameFile(tmp_name, file_name);
  } else {
    RemoveFile(tmp_name);
    LOG(FATAL)
        << "Error writing bitcode to file: " << file_name << ".";
  }
}

namespace {

#ifndef BUILD_SEMANTICS_DIR
# error "Macro `BUILD_SEMANTICS_DIR` must be defined."
# define BUILD_SEMANTICS_DIR
#endif  // BUILD_SEMANTICS_DIR

#ifndef INSTALL_SEMANTICS_DIR
# error "Macro `INSTALL_SEMANTICS_DIR` must be defined."
# define INSTALL_SEMANTICS_DIR
#endif  // INSTALL_SEMANTICS_DIR

static const char *gSearchPaths[] = {
    // Derived from the build.
    BUILD_SEMANTICS_DIR "\0",
    INSTALL_SEMANTICS_DIR "\0",

    // Linux.
    "/usr/local/share/remill/semantics",
    "/usr/share/remill/semantics",

    // Other?
    "/opt/local/share/remill/semantics",
    "/opt/share/remill/semantics",
    "/opt/remill/semantics",

    // FreeBSD.
    "/usr/share/compat/linux/remill/semantics",
    "/usr/local/share/compat/linux/remill/semantics",
    "/compat/linux/usr/share/remill/semantics",
    "/compat/linux/usr/local/share/remill/semantics",
};

}  // namespace

// Find the path to the semantics bitcode file.
std::string FindSemanticsBitcodeFile(const std::string &path,
                                     const std::string &arch) {
  if (!path.empty()) {
    return path;
  }

  for (auto path : gSearchPaths) {
    std::stringstream ss;
    ss << path << "/" << arch << ".bc";
    auto sem_path = ss.str();
    if (FileExists(sem_path)) {
      return sem_path;
    }
  }

  LOG(FATAL)
      << "Cannot find path to " << arch << " semantics bitcode file.";
}

llvm::Argument *NthArgument(llvm::Function *func, size_t index) {
  auto it = func->arg_begin();
  for (size_t i = 0; i < index; ++i) {
    ++it;
  }
  return &*it;
}

void ForEachIndirectBlock(
    llvm::Module *module,
    IndirectBlockCallback on_each_function) {
  auto table_var = module->getGlobalVariable("__remill_indirect_blocks");
  auto init = table_var->getInitializer();
  auto module_id = module->getModuleIdentifier();

  if (llvm::isa<llvm::ConstantAggregateZero>(init)) {
    return;
  }

  // Read in the addressable blocks from the indirect blocks table. Below,
  // the translator marks every decoded basic block in the CFG as being
  // addressable, so we expect all of them to be in the table.
  auto entries = llvm::dyn_cast<llvm::ConstantArray>(init);
  if (!entries) {
    LOG(FATAL)
        << "No entries in __remill_indirect_blocks (0x" << std::hex
        << reinterpret_cast<uintptr_t>(init) << "): "
        << LLVMThingToString(table_var);
  }

  std::vector<llvm::ConstantStruct *> recorded_entries;
  recorded_entries.reserve(entries->getNumOperands());

  for (const auto &entry : entries->operands()) {
    if (llvm::isa<llvm::ConstantAggregateZero>(entry)) {
      continue;  // Sentinel.
    }
    auto indirect_block = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
    recorded_entries.push_back(indirect_block);
  }

  for (auto indirect_block : recorded_entries) {
    // Note: Each entry has the following type:
    //    struct IndirectBlock final {
    //      const uint64_t lifted_address;
    //      void (* const lifted_func)(State &, Memory &, addr_t);
    //    };
    auto block_pc = llvm::dyn_cast<llvm::ConstantInt>(
        indirect_block->getOperand(0))->getZExtValue();
    auto lifted_func = llvm::dyn_cast<llvm::Function>(
        indirect_block->getOperand(1));
    on_each_function(block_pc, lifted_func);
  }
}

namespace {

// Pull the `name` out of a `NamedBlock`.
static std::string GetSubroutineName(llvm::ConstantStruct *exported_block) {
  auto name_gep = exported_block->getOperand(0);
  auto name_var = llvm::dyn_cast<llvm::GlobalVariable>(
      name_gep->getOperand(0));
  auto name_arr = llvm::dyn_cast<llvm::ConstantDataArray>(
      name_var->getOperand(0));
  return name_arr->getAsCString();
}

// Run a callback function for every named block entry in a remill-lifted
// bitcode module.
static void ForEachNamedBlock(llvm::Module *module, const char *table_name,
                              NamedBlockCallback on_each_function) {
  auto table_var = module->getGlobalVariable(table_name);
  auto init = table_var->getInitializer();

  if (llvm::isa<llvm::ConstantAggregateZero>(init)) {
    return;
  }

  auto entries = llvm::dyn_cast<llvm::ConstantArray>(init);
  if (!entries) {
    LOG(FATAL)
        << "No entries in " << table_name << " (0x" << std::hex
        << reinterpret_cast<uintptr_t>(init) << "): "
        << LLVMThingToString(table_var);
  }

  std::vector<llvm::ConstantStruct *> recorded_entries;
  recorded_entries.reserve(entries->getNumOperands());

  for (const auto &entry : entries->operands()) {
    if (llvm::isa<llvm::ConstantAggregateZero>(entry)) {
      continue;
    }
    auto exported_block = llvm::dyn_cast<llvm::ConstantStruct>(entry.get());
    recorded_entries.push_back(exported_block);
  }

  for (auto exported_block : recorded_entries) {
    // Note: Each `entry` has the following type:
    //    struct NamedBlock final {
    //      const char * const name;
    //      void (* const lifted_func)(Memory &, State &, addr_t);
    //      void (* const native_func)(void);
    //    };
    auto func_name = GetSubroutineName(exported_block);
    auto lifted_func = llvm::dyn_cast<llvm::Function>(
        exported_block->getOperand(1));
    auto native_func = llvm::dyn_cast<llvm::Function>(
        exported_block->getOperand(2));

    on_each_function(func_name, lifted_func, native_func);
  }
}

}  // namespace

// Run a callback function for every exported block entry in a remill-lifted
// bitcode module.
void ForEachExportedBlock(
    llvm::Module *module, NamedBlockCallback on_each_function) {
  ForEachNamedBlock(module, "__remill_exported_blocks", on_each_function);
}

// Run a callback function for every imported block entry in a remill-lifted
// bitcode module.
void ForEachImportedBlock(
    llvm::Module *module, NamedBlockCallback on_each_function) {
  ForEachNamedBlock(module, "__remill_imported_blocks", on_each_function);
}

// Clone function `source_func` into `dest_func`. This will strip out debug
// info during the clone.
void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func) {
  auto func_name = source_func->getName().str();
  auto source_mod = source_func->getParent();
  auto dest_mod = dest_func->getParent();
  auto new_args = dest_func->arg_begin();

  dest_func->setAttributes(source_func->getAttributes());
  dest_func->setLinkage(source_func->getLinkage());
  dest_func->setVisibility(source_func->getVisibility());
  dest_func->setCallingConv(source_func->getCallingConv());
  dest_func->setIsMaterializable(source_func->isMaterializable());

  std::unordered_map<llvm::Value *, llvm::Value *> value_map;
  for (llvm::Argument &old_arg : source_func->args()) {
    new_args->setName(old_arg.getName());
    value_map[&old_arg] = &*new_args;
    ++new_args;
  }

  // Clone the basic blocks and their instructions.
  std::unordered_map<llvm::BasicBlock *, llvm::BasicBlock *> block_map;
  for (auto &old_block : *source_func) {
    auto new_block = llvm::BasicBlock::Create(
        dest_func->getContext(), old_block.getName(), dest_func);
    value_map[&old_block] = new_block;
    block_map[&old_block] = new_block;

    auto &new_insts = new_block->getInstList();
    for (auto &old_inst : old_block) {
      if (llvm::isa<llvm::DbgInfoIntrinsic>(old_inst)) {
        continue;
      }

      auto new_inst = old_inst.clone();
      new_insts.push_back(new_inst);
      value_map[&old_inst] = new_inst;
    }
  }

  llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> mds;

  // Fixup the references in the cloned instructions so that they point into
  // the cloned function, or point to declared globals in the module containing
  // `dest_func`.
  for (auto &old_block : *source_func) {
    for (auto &old_inst : old_block) {
      if (llvm::isa<llvm::DbgInfoIntrinsic>(old_inst)) {
        continue;
      }

      auto new_inst = llvm::dyn_cast<llvm::Instruction>(value_map[&old_inst]);

      // Clear out all metadata from the new instruction.
      old_inst.getAllMetadata(mds);
      for (auto md_info : mds) {
        new_inst->setMetadata(md_info.first, nullptr);
      }

      new_inst->setDebugLoc(llvm::DebugLoc());
      new_inst->setName(old_inst.getName());

      for (auto &new_op : new_inst->operands()) {
        auto old_op_val = new_op.get();

        if (llvm::isa<llvm::Constant>(old_op_val) &&
            !llvm::isa<llvm::GlobalValue>(old_op_val)) {
          continue;  // Don't clone constants.
        }

        // Already cloned the value, replace the old with the new.
        auto new_op_val_it = value_map.find(old_op_val);
        if (value_map.end() != new_op_val_it) {
          new_op.set(new_op_val_it->second);
          continue;
        }

        // At this point, all we should have is a global.
        auto global_val = llvm::dyn_cast<llvm::GlobalValue>(old_op_val);
        if (!global_val) {
          LOG(FATAL)
              << "Cannot clone value " << LLVMThingToString(old_op_val)
              << " into function " << func_name << " because it isn't "
              << "a global value.";
        }

        // If it's a global and we're in the same module, then use it.
        if (global_val && dest_mod == source_mod) {
          value_map[global_val] = global_val;
          new_op.set(global_val);
          continue;
        }

        // Declare the global in the new module.
        llvm::GlobalValue *new_global_val = nullptr;
        if (llvm::isa<llvm::Function>(global_val)) {
          new_global_val = llvm::dyn_cast<llvm::GlobalValue>(
              dest_mod->getOrInsertFunction(
                  global_val->getName(),
                  llvm::dyn_cast<llvm::FunctionType>(
                      global_val->getValueType())));

        } else if (llvm::isa<llvm::GlobalVariable>(global_val)) {
          new_global_val = llvm::dyn_cast<llvm::GlobalValue>(
              dest_mod->getOrInsertGlobal(
                  global_val->getName(), global_val->getValueType()));

        } else {
          LOG(FATAL)
              << "Cannot clone value " << LLVMThingToString(old_op_val)
              << " into new module for function " << func_name;
        }

        auto old_name = global_val->getName().str();
        auto new_name = new_global_val->getName().str();

        CHECK(new_global_val->getName() == global_val->getName())
            << "Name of cloned global value declaration for " << old_name
            << "does not match global value definition of " << new_name
            << " in the source module. The cloned value probably has the "
            << "same name as another value in the dest module, but with a "
            << "different type.";

        // Mark the global as extern, so that it can link back to the old
        // module.
        new_global_val->setLinkage(llvm::GlobalValue::ExternalLinkage);
        new_global_val->setVisibility(llvm::GlobalValue::DefaultVisibility);

        value_map[global_val] = new_global_val;
        new_op.set(new_global_val);
      }

      // Remap PHI node predecessor blocks.
      if (auto phi = llvm::dyn_cast<llvm::PHINode>(new_inst)) {
        for (auto i = 0UL; i < phi->getNumIncomingValues(); ++i) {
          phi->setIncomingBlock(i, block_map[phi->getIncomingBlock(i)]);
        }
      }
    }
  }
}

}  // namespace remill
