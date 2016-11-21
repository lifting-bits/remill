/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_EMULATOR_BYTECODE_COMPILER_H_
#define TOOLS_VMILL_EMULATOR_BYTECODE_COMPILER_H_

#include <cstdint>

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
namespace vmill {

struct Operation;
class ByteCodeIndex;
class ByteCodeCache;
class ByteCodeVM;
class ConstantPool;

// Compiles LLVM bitcode into the VMILL bytecode format. This format is
// useful for interpreting, JIT compiling, and symbolic execution.
class ByteCodeCompiler {
 public:
  virtual ~ByteCodeCompiler(void);

  // Create a new LLVM bitcode-to-bytecode compiler.
  static ByteCodeCompiler *Create(ByteCodeIndex *index_,
                                  ByteCodeCache *bytecode_cache_,
                                  ConstantPool *constant_pool_);

  // Return the bytecode for some program counter. If it doesn't exist,
  // then compile it on the spot..
  virtual void Compile(llvm::Module *module) = 0;

 protected:
  ByteCodeCompiler(ByteCodeIndex *index_,
                   ByteCodeCache *bytecode_cache_,
                   ConstantPool *constant_pool_);

  ByteCodeIndex *index;
  ByteCodeCache *cache;
  ConstantPool *constants;

 private:
  ByteCodeCompiler(void) = delete;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_EMULATOR_BYTECODE_COMPILER_H_
