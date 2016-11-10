/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/DIBuilder.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>

#include <llvm/Support/Path.h>

#include "remill/Arch/AssemblyWriter.h"
#include "remill/Arch/Instruction.h"

namespace remill {

AssemblyWriter::AssemblyWriter(llvm::Module *module,
                               const std::string &path_)
    : path(path_),
      output(path, std::ofstream::out | std::ofstream::trunc),
      dib(new llvm::DIBuilder(*module)),
      file_scope(nullptr),
      unit_scope(nullptr),
      block_scope(nullptr),
      line(0) {

  auto path_sep = llvm::sys::path::get_separator();
  auto dir_name = llvm::sys::path::parent_path(path).rtrim(path_sep).str() +
                  path_sep.str();
  auto file_name = llvm::sys::path::filename(path);

  file_scope = dib->createFile(file_name, dir_name);
  unit_scope = dib->createCompileUnit(
      llvm::dwarf::DW_LANG_C,  // Lang
      file_name,  // File
      dir_name,  // Dir
      "remill-lift",  // Producer
      false,  // isOptimized
      llvm::StringRef(),  // Flags (e.g. compiler flags)
      0);  // RuntimeVersion.
}

AssemblyWriter::~AssemblyWriter(void) {
  dib->finalize();
  delete dib;
}

void AssemblyWriter::WriteBlock(llvm::Function *func) {
  output << std::endl << func->getName().str() << ":" << std::endl;
  line += 2;

  block_scope = dib->createFunction(
      file_scope,
      func->getName(),  // Name
      func->getName(),  // LinkageName
      file_scope,
      line,  // Line
      dib->createSubroutineType(dib->getOrCreateTypeArray(llvm::None)),  // Type
      false,  // IsLocalToUnit
      true,  // IsDefinition
      line,  // ScopeLine
      llvm::DINode::FlagPrototyped,  // Flags
      false);  // IsOptimized

  block_scope->replaceUnit(unit_scope);
  func->setSubprogram(block_scope);

  auto loc = llvm::DebugLoc::get(line, 1, block_scope);
  for (auto &block : *func) {
    for (auto &inst : block) {
      inst.setDebugLoc(loc);
    }
  }
}

void AssemblyWriter::WriteInstruction(llvm::Function *func,
                                      const Instruction *instr) {
  output << std::hex << instr->pc << ":  " << instr->disassembly << std::endl;
  ++line;

  auto loc = llvm::DebugLoc::get(line, 1, block_scope);

  for (auto &block : *func) {
    for (auto &inst : block) {
      if (inst.getDebugLoc().get()) {
        break;  // Instructions in this block are already annotated.
      } else {
        inst.setDebugLoc(loc);
      }
    }
  }
}

void AssemblyWriter::Flush(void) {
  output.flush();
}

}  // namespace remill
