/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Semantics/MACROS.h"
#include "mcsema/Arch/Semantics/TYPES.h"

vec128_t::vec128_t(void)
    : iwords{0} {}

vec128_t::vec128_t(const vec64_t &&sub_vec) {
  qwords[0] = sub_vec.qwords[0];
  qwords[1] = 0;
}
vec256_t::vec256_t(void)
    : iwords{0} {}

vec256_t::vec256_t(const vec64_t &&sub_vec) {
  qwords[0] = sub_vec.qwords[0];
  qwords[1] = 0;
  qwords[2] = 0;
  qwords[3] = 0;
}

vec256_t::vec256_t(const vec128_t &&sub_vec) {
  dqwords[0] = sub_vec.dqwords[0];
  dqwords[1] = 0;
}
vec512_t::vec512_t(void)
    : iwords{0} {}

vec512_t::vec512_t(const vec64_t &&sub_vec) {
  qwords[0] = sub_vec.qwords[0];
  qwords[1] = 0;
  qwords[2] = 0;
  qwords[3] = 0;
  qwords[4] = 0;
  qwords[5] = 0;
  qwords[6] = 0;
  qwords[7] = 0;
}

vec512_t::vec512_t(const vec128_t &&sub_vec) {
  dqwords[0] = sub_vec.dqwords[0];
  dqwords[1] = 0;
  dqwords[2] = 0;
  dqwords[3] = 0;
}

vec512_t::vec512_t(const vec256_t &&sub_vec) {
  dqwords[0] = sub_vec.dqwords[0];
  dqwords[1] = sub_vec.dqwords[1];
  dqwords[2] = 0;
  dqwords[3] = 0;
}
