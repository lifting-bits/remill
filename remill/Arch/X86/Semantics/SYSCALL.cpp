/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

DEF_SEM(DoSYSCALL) {
  HYPER_CALL = AsyncHyperCall::kX86SysCall;
  return memory;
}

DEF_SEM(DoSYSCALL_AMD) {
  HYPER_CALL = AsyncHyperCall::kX86SysCall;
  return memory;
}

DEF_SEM(DoSYSENTER) {
  HYPER_CALL = AsyncHyperCall::kX86SysEnter;
  return memory;
}

DEF_SEM(DoSYSEXIT) {
  HYPER_CALL = AsyncHyperCall::kX86SysExit;
  return memory;
}
}  // namespace

DEF_ISEL(SYSCALL) = DoSYSCALL;

DEF_ISEL(SYSCALL_AMD) = DoSYSCALL_AMD;

DEF_ISEL(SYSENTER) = DoSYSENTER;

DEF_ISEL(SYSEXIT) = DoSYSEXIT;
