///* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */
//
//#ifndef TOOLS_VMILL_ARCH_LIFTER_H_
//#define TOOLS_VMILL_ARCH_LIFTER_H_
//
//#include <string>
//#include <unistd.h>
//
//#include "tools/vmill/BC/Callback.h"
//
//namespace llvm {
//class LLVMContext;
//class Module;
//}  // namespace llvm
//namespace remill {
//namespace cfg {
//class Module;
//}  // namespace cfg
//namespace vmill {
//
//class Lifter {
// public:
//  static Lifter *Create(void);
//
//  llvm::Module *LiftIntoContext(
//
//      cfg::Module *cfg, llvm::LLVMContext *);
//
//  static void ForEachLiftedFunctionInModule(
//      llvm::Module *module,
//      LiftedFunctionCallback on_each_function);
//
//  ~Lifter(void);
// private:
//  Lifter(pid_t lift_pid_, pid_t opt_pid_);
//  Lifter(void) = delete;
//
//  pid_t lift_pid;
//  pid_t opt_pid;
//};
//
//
//}  // namespace vmill
//}  // namespace remill
//
//#endif  // TOOLS_VMILL_ARCH_LIFTER_H_
