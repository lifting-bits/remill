/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Metadata.h>

#include <llvm/Support/Path.h>

#include "remill/Arch/AssemblyWriter.h"
#include "remill/Arch/Instruction.h"

namespace remill {
//namespace {
//
//static llvm::DIFile *FileFromPath(llvm::LLVMContext *context,
//                                  const std::string &file_name) {
//  return llvm::DIFile::get(*context, file_name,
//                           llvm::sys::path::parent_path(file_name));
//}
//
//}  // namespace

AssemblyWriter::AssemblyWriter(llvm::Module *module,
                               const std::string &file_name_)
    : file_name(file_name_),
      output(file_name, std::ofstream::out | std::ofstream::trunc),
      dib(new llvm::DIBuilder(*module)),
      file_scope(nullptr),
      unit_scope(nullptr),
      block_scope(nullptr),
      line(0) {

  auto dir_name = llvm::sys::path::parent_path(file_name);

  file_scope = dib->createFile(file_name, dir_name);
  unit_scope = dib->createCompileUnit(
      0, file_name, dir_name, "remill-lift", false, "", 0);
}


void AssemblyWriter::WriteBlock(llvm::Function *func) {
  block_scope = dib->createFunction(
      unit_scope,
      func->getName(),  // Name
      "",  // LinkageName
      file_scope,
      line,  // Line
      llvm::DISubroutineType::get(func->getContext(), 0, 0, nullptr),  // Type
      true,  // IsLocalToUnit
      true,  // IsDefinition
      line);  // ScopeLine
}
//
//llvm::DISubprogram *AssemblyWriter::CreateBlockScope(llvm::Function *func) {
//  auto &context = func->getContext();
////  auto module = func->getParent();
//
//  auto func_name = func->getName();
////  auto block_name = llvm::MDString::get(context, func_name);
//
//  if (line) {
//    output << std::endl;
//    output.flush();
//
//    ++line;
//  }
//  output << func_name.str() << ":" << std::endl;
//  ++line;
//
////  return llvm::DISubprogram::get(
////      context,
////      file_scope,
////      func_name,  // Name
////      func_name,  // LinkageName
////      file_scope,
////      line,  // Line
////      llvm::DISubroutineType::get(context, 0, 0, nullptr),  // Type
////      true,  // IsLocalToUnit
////      true,  // IsDefinition
////      line,  // ScopeLine
////      nullptr,  // Containing type
////      0,  // Virtuality
////      0,  // VirtualIndex
////      0,  // ThisAdjustment
////      0,  // Flags
////      false,  // IsOptimized
////      unit_scope);
////
////  llvm::DIBuilder dib(*module);
////
//  return
//}

void AssemblyWriter::WriteInstruction(llvm::BasicBlock *block,
                                      const Instruction *instr) {
//  auto func = block->getParent();
  output << std::hex << instr->pc << ":  " << instr->disassembly << std::endl;
  ++line;

  auto asm_loc = llvm::DILocation::get(
      file_scope->getContext(), line, 0, block_scope);

  for (auto &I : *block) {
    I.setDebugLoc(asm_loc);
  }
}

}  // namespace remill
