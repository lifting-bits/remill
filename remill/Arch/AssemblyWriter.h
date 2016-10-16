/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_ASSEMBLYWRITER_H_
#define REMILL_ARCH_ASSEMBLYWRITER_H_

#include <fstream>
#include <string>

namespace llvm {
class BasicBlock;
class DIBuilder;
class DIFile;
class DILocation;
class DISubprogram;
class Function;
class Module;
}  // namespace llvm

namespace remill {

class Instruction;

// Writes out disassembled instructions to a file, and associated those
// lines in the file with debug information that is attached to lifted
// code.
class AssemblyWriter {
 public:
  explicit AssemblyWriter(llvm::Module *module,
                          const std::string &file_name_);

  void WriteBlock(llvm::Function *func);
  void WriteInstruction(llvm::BasicBlock *block, const Instruction *instr);

 private:
  AssemblyWriter(void) = delete;
  AssemblyWriter(const AssemblyWriter &) = delete;

  const std::string file_name;
  std::ofstream output;
  llvm::DIBuilder * const dib;
  llvm::DIFile *file_scope;
  llvm::DICompileUnit *unit_scope;
  llvm::DISubprogram *block_scope;
  unsigned line;
};

}  // namespace remill

#endif  // REMILL_ARCH_ASSEMBLYWRITER_H_
