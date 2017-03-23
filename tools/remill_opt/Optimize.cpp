/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <bitset>
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>

#include <llvm/Pass.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>

#include "remill/BC/ABI.h"
#include "remill/BC/Optimizer.h"
#include "remill/BC/Util.h"
#include "remill/OS/FileSystem.h"

DEFINE_string(bc_in, "", "Input bitcode file to be optimized.");

DEFINE_string(bc_out, "", "Optimized bitcode.");

DEFINE_bool(server, false, "Run the optimizer as a server. This will allow "
                           "remill-opt to receive bitcode from remill-lift.");

DEFINE_bool(strip, false, "Strip out all debug information.");

//DEFINE_bool(lower_mem, false, "Lower memory access intrinsics into "
//                              "LLVM load and store instructions. "
//                              "Note: the memory class pointer is replaced "
//                              "with a i8 pointer.");

//DEFINE_bool(lower_fp_mem, false, "Lower floating-point memory access "
//                                 "intrinsics into LLVM load and store "
//                                 "instructions.");

namespace {

static void RemoveISelVars(llvm::Module *module) {
  std::vector<llvm::GlobalVariable *> isels;
  for (auto &var : module->globals()) {
    if (!var.getName().startswith("__remill")) {
      DLOG(INFO)
          << "Removing ISEL definition " << var.getName().str();
      isels.push_back(&var);
    }
  }
  for (auto isel : isels) {
    isel->eraseFromParent();
  }
}

static void StripDebugInfo(llvm::Module *module) {
  if (FLAGS_strip) {
    llvm::legacy::PassManager module_manager;
    module_manager.add(llvm::createStripDebugDeclarePass());
    module_manager.add(llvm::createStripSymbolsPass(true /* OnlyDebugInfo */));
    module_manager.add(llvm::createStripDeadDebugInfoPass());
    module_manager.run(*module);
  }
}

static void RemoveFunction(llvm::Module *module, llvm::StringRef name) {
  if (auto func = module->getFunction(name)) {
    if (!func->hasNUsesOrMore(1)) {
      func->removeFromParent();
      delete func;
    }
  }
}

static void RemoveDeadIntrinsics(llvm::Module *module) {
  RemoveFunction(module, "__remill_intrinsics");
  RemoveFunction(module, "__remill_mark_as_used");
  RemoveFunction(module, "__remill_defer_inlining");
  RemoveFunction(module, "__remill_undefined_8");
  RemoveFunction(module, "__remill_undefined_16");
  RemoveFunction(module, "__remill_undefined_32");
  RemoveFunction(module, "__remill_undefined_64");
  RemoveFunction(module, "__remill_undefined_f32");
  RemoveFunction(module, "__remill_undefined_f64");
}

static void RemoveUnusedSemantics(llvm::Module *module) {
  std::vector<llvm::Function *> to_remove;
  for (auto &func : *module) {
    if (!func.getName().startswith("__remill")) {
      to_remove.push_back(&func);
    }
  }
  for (auto func : to_remove) {
    if (!func->hasNUsesOrMore(1)) {
      func->eraseFromParent();
    }
  }
}

#if 0
// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(llvm::Module *module, const char *name,
                               llvm::Type *val_type) {
  auto func = module->getFunction(name);
  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  std::vector<llvm::CallInst *> callers;
  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      if (call_inst->getCalledFunction() == func) {
        callers.push_back(call_inst);
      }
    }
  }

  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    auto addr = call_inst->getArgOperand(1);
    llvm::Value *indexes[] = {addr};
    llvm::IRBuilder<> ir(call_inst);
    auto gep = ir.CreateInBoundsGEP(mem_ptr, indexes);
    auto ptr = ir.CreatePointerCast(gep, llvm::PointerType::get(val_type, 0));
    llvm::Value *val = ir.CreateLoad(ptr);
    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPTrunc(val, func->getReturnType());
    }
    call_inst->replaceAllUsesWith(val);
  }
}

// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(llvm::Module *module, const char *name,
                               llvm::Type *val_type) {
  auto func = module->getFunction(name);
  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  std::vector<llvm::CallInst *> callers;
  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      if (call_inst->getCalledFunction() == func) {
        callers.push_back(call_inst);
      }
    }
  }

  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    auto addr = call_inst->getArgOperand(1);
    auto val = call_inst->getArgOperand(2);

    llvm::Value *indexes[] = {addr};
    llvm::IRBuilder<> ir(call_inst);
    auto gep = ir.CreateInBoundsGEP(mem_ptr, indexes);
    auto ptr = ir.CreatePointerCast(gep, llvm::PointerType::get(val_type, 0));
    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPExt(val, func->getReturnType());
    }
    ir.CreateStore(val, ptr);
    call_inst->replaceAllUsesWith(mem_ptr);
  }
}

static void LowerMemOps(llvm::Module *module) {
  auto &context = module->getContext();
  auto mem_func = module->getFunction("__remill_write_memory_8");
  auto mem_ptr_type = llvm::dyn_cast<llvm::PointerType>(
      mem_func->getReturnType());
  auto mem_type = llvm::dyn_cast<llvm::StructType>(
      mem_ptr_type->getElementType());
  mem_type->setBody(llvm::Type::getInt8Ty(context), nullptr, nullptr);

  ReplaceMemReadOp(module, "__remill_read_memory_8",
                   llvm::Type::getInt8Ty(context));
  ReplaceMemReadOp(module, "__remill_read_memory_16",
                   llvm::Type::getInt16Ty(context));
  ReplaceMemReadOp(module, "__remill_read_memory_32",
                   llvm::Type::getInt32Ty(context));
  ReplaceMemReadOp(module, "__remill_read_memory_64",
                   llvm::Type::getInt64Ty(context));
  ReplaceMemReadOp(module, "__remill_read_memory_f32",
                   llvm::Type::getFloatTy(context));
  ReplaceMemReadOp(module, "__remill_read_memory_f64",
                   llvm::Type::getDoubleTy(context));

  ReplaceMemWriteOp(module, "__remill_write_memory_8",
                    llvm::Type::getInt8Ty(context));
  ReplaceMemWriteOp(module, "__remill_write_memory_16",
                    llvm::Type::getInt16Ty(context));
  ReplaceMemWriteOp(module, "__remill_write_memory_32",
                    llvm::Type::getInt32Ty(context));
  ReplaceMemWriteOp(module, "__remill_write_memory_64",
                    llvm::Type::getInt64Ty(context));
  ReplaceMemWriteOp(module, "__remill_write_memory_f32",
                    llvm::Type::getFloatTy(context));
  ReplaceMemWriteOp(module, "__remill_write_memory_f64",
                    llvm::Type::getDoubleTy(context));

  if (FLAGS_lower_fp_mem) {
    ReplaceMemReadOp(module, "__remill_read_memory_f80",
                     llvm::Type::getX86_FP80Ty(context));
    ReplaceMemWriteOp(module, "__remill_write_memory_f80",
                      llvm::Type::getX86_FP80Ty(context));
  }
}
#endif
}  // namespace

int main(int argc, char *argv[]) {
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --bc_in INPUT_BC_FILE \\" << std::endl
     << "    --bc_out OUTPUT_BC_FILE \\" << std::endl
     << "    [--server]" << std::endl
     << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(!FLAGS_bc_in.empty())
      << "Please specify an input bitcode file with --bc_in.";

  CHECK(remill::FileExists(FLAGS_bc_in))
      << "Input bitcode file " << FLAGS_bc_in << " does not exist.";

  CHECK(!FLAGS_bc_out.empty())
      << "Please specify an output bitcode file with --bc_out.";

  do {
    auto context = new llvm::LLVMContext;
    auto module = remill::LoadModuleFromFile(context, FLAGS_bc_in);
    auto optimizer = remill::Optimizer::Create(module);
    auto module_id = module->getModuleIdentifier();
    StripDebugInfo(module);
    RemoveISelVars(module);

//    if (FLAGS_lower_mem) {
//      LowerMemOps(module);
//    }

    optimizer->Optimize();

    RemoveDeadIntrinsics(module);
    if (false) {
      RemoveUnusedSemantics(module);
      StripDebugInfo(module);
    }
    remill::StoreModuleToFile(module, FLAGS_bc_out);
    delete module;
    delete context;
  } while (FLAGS_server);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();
  return EXIT_SUCCESS;
}
