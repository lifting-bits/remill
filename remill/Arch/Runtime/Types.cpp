/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_TYPES_CPP_
#define REMILL_ARCH_RUNTIME_TYPES_CPP_

#include "remill/Arch/Runtime/Intrinsics.h"

#if 0
float80_t::float80_t(void)
    : sign(0),
      exponent(0),
      integer(0),
      fraction(0) {}

float80_t::float80_t(float64_t new_val) {
  __remill_write_f80(new_val, *this);
}

float80_t::float80_t(float32_t new_val)
    : float80_t(float64_t(new_val)) {}

float80_t &float80_t::operator=(float64_t new_val) {
  __remill_write_f80(new_val, *this);
  return *this;
}

float80_t &float80_t::operator=(float32_t new_val_) {
  float64_t new_val = new_val_;
  __remill_write_f80(new_val, *this);
  return *this;
}
#endif

#endif  // REMILL_ARCH_RUNTIME_TYPES_CPP_
