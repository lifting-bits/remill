/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Runtime/Types.h"
#include "mcsema/Arch/Runtime/Util.h"

vec8_t::vec8_t(void)
    : iwords{0} {}

vec16_t::vec16_t(void)
    : iwords{0} {}

vec16_t::vec16_t(vec8_t sub_vec)
    : vec16_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec32_t::vec32_t(void)
    : iwords{0} {}

vec32_t::vec32_t(vec8_t sub_vec)
    : vec32_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec32_t::vec32_t(vec16_t sub_vec)
    : vec32_t() {
  words[0] = sub_vec.words[0];
}

vec64_t::vec64_t(void)
    : iwords{0} {}

vec64_t::vec64_t(vec8_t sub_vec)
    : vec64_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec64_t::vec64_t(vec16_t sub_vec)
    : vec64_t() {
  words[0] = sub_vec.words[0];
}

vec64_t::vec64_t(vec32_t sub_vec)
    : vec64_t() {
  dwords[0] = sub_vec.dwords[0];
}

vec128_t::vec128_t(void)
    : iwords{0} {}

vec128_t::vec128_t(vec8_t sub_vec)
    : vec128_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec128_t::vec128_t(vec16_t sub_vec)
    : vec128_t() {
  words[0] = sub_vec.words[0];
}

vec128_t::vec128_t(vec32_t sub_vec)
    : vec128_t() {
  dwords[0] = sub_vec.dwords[0];
}

vec128_t::vec128_t(vec64_t sub_vec)
    : vec128_t() {
  qwords[0] = sub_vec.qwords[0];
}

vec256_t::vec256_t(void)
    : iwords{0} {}

vec256_t::vec256_t(vec8_t sub_vec)
    : vec256_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec256_t::vec256_t(vec16_t sub_vec)
    : vec256_t() {
  words[0] = sub_vec.words[0];
}

vec256_t::vec256_t(vec32_t sub_vec)
    : vec256_t() {
  dwords[0] = sub_vec.dwords[0];
}

vec256_t::vec256_t(vec64_t sub_vec)
    : vec256_t() {
  qwords[0] = sub_vec.qwords[0];
}

vec256_t::vec256_t(vec128_t sub_vec)
    : vec256_t() {
  dqwords[0] = sub_vec.dqwords[0];
}

vec512_t::vec512_t(void)
    : iwords{0} {}

vec512_t::vec512_t(vec8_t sub_vec)
    : vec512_t() {
  bytes[0] = sub_vec.bytes[0];
}

vec512_t::vec512_t(vec16_t sub_vec)
    : vec512_t() {
  words[0] = sub_vec.words[0];
}

vec512_t::vec512_t(vec32_t sub_vec)
    : vec512_t() {
  dwords[0] = sub_vec.dwords[0];
}

vec512_t::vec512_t(vec64_t sub_vec)
    : vec512_t() {
  qwords[0] = sub_vec.qwords[0];
}

vec512_t::vec512_t(vec128_t sub_vec)
    : vec512_t() {
  dqwords[0] = sub_vec.dqwords[0];
}

vec512_t::vec512_t(vec256_t sub_vec)
    : vec512_t() {
  dqwords[0] = sub_vec.dqwords[0];
  dqwords[1] = sub_vec.dqwords[1];
}
