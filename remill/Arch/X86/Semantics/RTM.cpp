/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */


namespace {
DEF_SEM(XBEGIN, R8W cond, PC taken, PC not_taken) {
  Write(cond, true);
  Write(REG_PC, Read(taken));
  WriteZExt(REG_XAX, static_cast<addr_t>(8));
  return memory;
}

DEF_SEM(DoXTEST) {
  Write(FLAG_ZF, true);
  return memory;
}
}  // namespace

DEF_ISEL(XBEGIN_RELBRz_16) = XBEGIN;
DEF_ISEL(XBEGIN_RELBRz_32) = XBEGIN;

DEF_ISEL(XTEST) = DoXTEST;
/*
522 XEND XEND COND_BR RTM RTM ATTRIBUTES:
 */
