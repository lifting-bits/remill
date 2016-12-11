/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

DEF_ISEL_SEM(SYSCALL) {
  HYPER_CALL = AsyncHyperCall::kX86SysCall;
}

DEF_ISEL_SEM(SYSCALL_AMD) {
  HYPER_CALL = AsyncHyperCall::kX86SysCall;
}

DEF_ISEL_SEM(SYSENTER) {
  HYPER_CALL = AsyncHyperCall::kX86SysEnter;
}

DEF_ISEL_SEM(SYSEXIT) {
  HYPER_CALL = AsyncHyperCall::kX86SysExit;
}

