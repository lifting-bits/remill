/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_BC_OPTIMIZER_H_
#define REMILL_BC_OPTIMIZER_H_

namespace llvm {
class Function;
class Module;

}  // namespace llvm
namespace remill {
class Optimizer {
 public:
  virtual ~Optimizer(void);

  static Optimizer *Create(llvm::Module *module_);

  virtual void Optimize(void) = 0;

 protected:
  explicit Optimizer(llvm::Module *module_);

  llvm::Module *module;

 private:
  Optimizer(void) = delete;

};
}  // namespace remill

#endif  // REMILL_BC_OPTIMIZER_H_
