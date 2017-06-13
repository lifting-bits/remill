/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <glog/logging.h>

#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <llvm/ADT/SmallVector.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/ToolOutputFile.h>
#include <llvm/Support/raw_ostream.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Compat/BitcodeReaderWriter.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Compat/IRReader.h"
#include "remill/BC/Compat/Verifier.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
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

  function->addFnAttr(llvm::Attribute::InlineHint);
}

// Create a tail-call from one lifted function to another.
llvm::CallInst *AddTerminatingTailCall(llvm::Function *source_func,
                                       llvm::Value *dest_func) {
  if (source_func->isDeclaration()) {
    llvm::IRBuilder<> ir(
        llvm::BasicBlock::Create(source_func->getContext(), "", source_func));

    std::vector<llvm::Value *> args;
    for (llvm::Argument &arg : source_func->args()) {
      args.push_back(&arg);
    }
    llvm::CallInst *call_target_instr = ir.CreateCall(dest_func, args);

    // Make sure we tail-call from one block method to another.
    call_target_instr->setTailCallKind(llvm::CallInst::TCK_Tail);
    call_target_instr->setCallingConv(llvm::CallingConv::Fast);
    ir.CreateRet(call_target_instr);
    return call_target_instr;
  } else {
    return AddTerminatingTailCall(&(source_func->back()), dest_func);
  }
}

llvm::CallInst *AddTerminatingTailCall(llvm::BasicBlock *source_block,
                                       llvm::Value *dest_func) {
  CHECK(nullptr != dest_func) << "Target function/block does not exist!";

  LOG_IF(ERROR, source_block->getTerminator())
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
  call_target_instr->setTailCallKind(llvm::CallInst::TCK_Tail);
  call_target_instr->setCallingConv(llvm::CallingConv::Fast);
  ir.CreateRet(call_target_instr);
  return call_target_instr;
}

// Find a local variable defined in the entry block of the function. We use
// this to find register variables.
llvm::Value *FindVarInFunction(llvm::BasicBlock *block, std::string name,
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

  CHECK(allow_failure) << "Could not find variable " << name << " in function "
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

// Update the program counter in the state struct with a hard-coded value.
void StoreProgramCounter(llvm::BasicBlock *block, uint64_t pc) {
  auto pc_ptr = LoadProgramCounterRef(block);
  auto type = llvm::dyn_cast<llvm::PointerType>(pc_ptr->getType());
  (void)new llvm::StoreInst(llvm::ConstantInt::get(type->getElementType(), pc),
                            pc_ptr, block);
}

// Return the current memory pointer.
llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  return ir.CreateLoad(LoadMemoryPointerRef(block));
}

// Return an `llvm::Value *` that is an `i1` (bool type) representing whether
// or not a conditional branch is taken.
llvm::Value *LoadBranchTaken(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  auto cond = ir.CreateLoad(
      ir.CreateLoad(FindVarInFunction(block->getParent(), "BRANCH_TAKEN")));
  auto true_val = llvm::ConstantInt::get(cond->getType(), 1);
  return ir.CreateICmpEQ(cond, true_val);
}

// Return a reference to the memory pointer.
llvm::Value *LoadMemoryPointerRef(llvm::BasicBlock *block) {
  return FindVarInFunction(block->getParent(), "MEMORY");
}

// Find a function with name `name` in the module `M`.
llvm::Function *FindFunction(llvm::Module *module, std::string name) {
  return module->getFunction(name);
}

// Find a global variable with name `name` in the module `M`.
llvm::GlobalVariable *FindGlobaVariable(llvm::Module *module,
                                        std::string name) {
  return module->getGlobalVariable(name, true);
}

// Reads an LLVM module from a file.
llvm::Module *LoadModuleFromFile(llvm::LLVMContext *context,
                                 std::string file_name) {
  llvm::SMDiagnostic err;
  auto mod_ptr = llvm::parseIRFile(file_name, err, *context);
  auto module = mod_ptr.get();
  mod_ptr.release();

  CHECK(nullptr != module) << "Unable to parse module file: " << file_name
                           << ".";

  auto ec = module->materializeAll();  // Just in case.
  CHECK(!ec) << "Unable to materialize everything from " << file_name;

  std::string error;
  llvm::raw_string_ostream error_stream(error);
  if (llvm::verifyModule(*module, &error_stream)) {
    error_stream.flush();
    LOG(FATAL) << "Error reading module from file " << file_name << ": "
               << error;
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
    LOG(FATAL) << "Error writing module to file " << file_name << ": " << error;
  }

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 5)
  std::error_code ec;
  llvm::tool_output_file bc(tmp_name.c_str(), ec, llvm::sys::fs::F_RW);
  CHECK(!ec) << "Unable to open output bitcode file for writing: " << tmp_name;
#else
  llvm::tool_output_file bc(tmp_name.c_str(), error, llvm::sys::fs::F_RW);
  CHECK(error.empty() && !bc.os().has_error())
      << "Unable to open output bitcode file for writing: " << tmp_name << ": "
      << error;
#endif

  llvm::WriteBitcodeToFile(module, bc.os());
  bc.keep();
  if (!bc.os().has_error()) {
    RenameFile(tmp_name, file_name);
  } else {
    RemoveFile(tmp_name);
    LOG(FATAL) << "Error writing bitcode to file: " << file_name << ".";
  }
}

namespace {

#ifndef BUILD_SEMANTICS_DIR
#error "Macro `BUILD_SEMANTICS_DIR` must be defined."
#define BUILD_SEMANTICS_DIR
#endif  // BUILD_SEMANTICS_DIR

#ifndef BUILD_SEMANTICS_DIR_ARM
#error \
    "Macro `BUILD_SEMANTICS_DIR_ARM` must be defined to support ARM architecture."
#define BUILD_SEMANTICS_DIR_ARM
#endif  // BUILD_SEMANTICS_DIR

#ifndef INSTALL_SEMANTICS_DIR
#error "Macro `INSTALL_SEMANTICS_DIR` must be defined."
#define INSTALL_SEMANTICS_DIR
#endif  // INSTALL_SEMANTICS_DIR

static const char *gSemanticsSearchPaths[] = {
    // Derived from the build.
    BUILD_SEMANTICS_DIR "\0", BUILD_SEMANTICS_DIR_ARM "\0",
    INSTALL_SEMANTICS_DIR "\0",
};

}  // namespace

// Find the path to the semantics bitcode file.
std::string FindSemanticsBitcodeFile(const std::string &path,
                                     const std::string &arch) {
  if (!path.empty()) {
    return path;
  }

  for (auto sem_dir : gSemanticsSearchPaths) {
    std::stringstream ss;
    ss << sem_dir << "/" << arch << ".bc";
    auto sem_path = ss.str();
    if (FileExists(sem_path)) {
      return sem_path;
    }
  }

  LOG(FATAL) << "Cannot find path to " << arch << " semantics bitcode file.";
  return "";
}

namespace {

// Convert an LLVM thing (e.g. `llvm::Value` or `llvm::Type`) into
// a `std::string`.
template <typename T>
inline static std::string DoLLVMThingToString(T *thing) {
  if (thing) {
    std::string str;
    llvm::raw_string_ostream str_stream(str);
    thing->print(str_stream);
    return str;
  } else {
    return "(null)";
  }
}

}  // namespace

std::string LLVMThingToString(llvm::Value *thing) {
  return DoLLVMThingToString(thing);
}

std::string LLVMThingToString(llvm::Type *thing) {
  return DoLLVMThingToString(thing);
}

llvm::Argument *NthArgument(llvm::Function *func, size_t index) {
  auto it = func->arg_begin();
  for (size_t i = 0; i < index; ++i) {
    ++it;
  }
  return &*it;
}

// Apply a callback function to every semantics bitcode function.
void ForEachISel(llvm::Module *module, ISelCallback callback) {
  for (auto &global : module->globals()) {
    if (!global.hasInitializer() || !global.getName().startswith("ISEL_")) {
      continue;
    }

    auto sem = llvm::dyn_cast<llvm::Function>(
        global.getInitializer()->stripPointerCasts());

    callback(&global, sem);
  }
}

// Declare a lifted function of the correct type.
llvm::Function *DeclareLiftedFunction(llvm::Module *module,
                                      const std::string &name) {
  auto bb = module->getFunction("__remill_basic_block");
  CHECK(nullptr != bb) << "Cannot declare lifted function " << name
                       << " because the "
                       << " intrinsics __remill_basic_block cannot be found.";
  auto func_type = bb->getFunctionType();

  auto func = llvm::dyn_cast<llvm::Function>(
      module->getOrInsertFunction(name, func_type));

  CHECK(nullptr != func) << "Could not insert function " << name
                         << " into module";

  InitFunctionAttributes(func);

  return func;
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

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
  dest_func->setIsMaterializable(source_func->isMaterializable());
#endif

  std::unordered_map<llvm::Value *, llvm::Value *> value_map;
  for (llvm::Argument &old_arg : source_func->args()) {
    new_args->setName(old_arg.getName());
    value_map[&old_arg] = &*new_args;
    ++new_args;
  }

  // Clone the basic blocks and their instructions.
  std::unordered_map<llvm::BasicBlock *, llvm::BasicBlock *> block_map;
  for (auto &old_block : *source_func) {
    auto new_block = llvm::BasicBlock::Create(dest_func->getContext(),
                                              old_block.getName(), dest_func);
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
          LOG(FATAL) << "Cannot clone value " << LLVMThingToString(old_op_val)
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
          new_global_val =
              llvm::dyn_cast<llvm::GlobalValue>(dest_mod->getOrInsertFunction(
                  global_val->getName(), llvm::dyn_cast<llvm::FunctionType>(
                                             GetValueType(global_val))));

        } else if (llvm::isa<llvm::GlobalVariable>(global_val)) {
          new_global_val =
              llvm::dyn_cast<llvm::GlobalValue>(dest_mod->getOrInsertGlobal(
                  global_val->getName(), GetValueType(global_val)));

        } else {
          LOG(FATAL) << "Cannot clone value " << LLVMThingToString(old_op_val)
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

namespace {

// Initialize some attributes that are common to all newly created block
// functions. Also, give pretty names to the arguments of block functions.
static void InitBlockFunctionAttributes(llvm::Function *block_func) {
  block_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  block_func->setVisibility(llvm::GlobalValue::DefaultVisibility);

  remill::NthArgument(block_func, kMemoryPointerArgNum)->setName("memory");
  remill::NthArgument(block_func, kStatePointerArgNum)->setName("state");
  remill::NthArgument(block_func, kPCArgNum)->setName("pc");
}

// These variables must always be defined within `__remill_basic_block`.
static bool BlockHasSpecialVars(llvm::Function *basic_block) {
  return FindVarInFunction(basic_block, "STATE", true) &&
         FindVarInFunction(basic_block, "MEMORY", true) &&
         FindVarInFunction(basic_block, "PC", true) &&
         FindVarInFunction(basic_block, "BRANCH_TAKEN", true);
}

// Clang isn't guaranteed to play nice and name the LLVM values within the
// `__remill_basic_block` intrinsic with the same names as we find in the
// C++ definition of that function. However, we compile that function with
// debug information, and so we will try to recover the variables names for
// later lookup.
static void FixupBasicBlockVariables(llvm::Function *basic_block) {
  if (BlockHasSpecialVars(basic_block)) {
    return;
  }

  for (auto &block : *basic_block) {
    for (auto &inst : block) {
      if (auto decl_inst = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
        auto addr = decl_inst->getAddress();
        addr->setName(decl_inst->getVariable()->getName());
      }
    }
  }

  CHECK(BlockHasSpecialVars(basic_block))
      << "Unable to locate required variables in `__remill_basic_block`.";
}

}  // namespace

// Make `func` a clone of the `__remill_basic_block` function.
void CloneBlockFunctionInto(llvm::Function *func) {
  llvm::Module *module = func->getParent();
  auto basic_block = module->getFunction("__remill_basic_block");
  CHECK(nullptr != basic_block)
      << "Unable to find __remill_basic_block in module";

  if (!BlockHasSpecialVars(basic_block)) {
    InitFunctionAttributes(basic_block);
    FixupBasicBlockVariables(basic_block);
    InitBlockFunctionAttributes(basic_block);

    basic_block->addFnAttr(llvm::Attribute::OptimizeNone);
    basic_block->removeFnAttr(llvm::Attribute::AlwaysInline);
    basic_block->removeFnAttr(llvm::Attribute::InlineHint);
    basic_block->addFnAttr(llvm::Attribute::NoInline);
    basic_block->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }

  CloneFunctionInto(basic_block, func);

  // Remove the `return` in `__remill_basic_block`.
  auto &entry = func->front();
  auto term = entry.getTerminator();
  term->eraseFromParent();
  func->removeFnAttr(llvm::Attribute::OptimizeNone);
}

}  // namespace remill
