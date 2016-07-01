/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_TYPES_CPP_
#define REMILL_ARCH_RUNTIME_TYPES_CPP_

#include "remill/Arch/Runtime/Intrinsics.h"

#if 0
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

float32_t::float32_t(void) {
  *this = __remill_undefined_f32();
}

float32_t::float32_t(float val_)
    : val(val_) {}

float32_t &float32_t::operator=(float new_val) {
  val = new_val;
  return *this;
}

float32_t &float32_t::operator=(double new_val) {
  val = static_cast<float>(new_val);
  return *this;
}

float32_t &float32_t::operator=(const float64_t &new_val) {
  val = static_cast<float>(new_val.val);
  return *this;
}

float32_t &float32_t::operator=(int64_t new_val) {
  val = new_val;
  return *this;
}

float32_t &float32_t::operator=(int32_t new_val) {
  val = new_val;
  return *this;
}

float32_t &float32_t::operator=(int16_t new_val) {
  val = new_val;
  return *this;
}

float32_t &float32_t::operator=(int8_t new_val) {
  val = new_val;
  return *this;
}

float32_t::operator float(void) const {
  return val;
}

float64_t::float64_t(void) {
  *this = __remill_undefined_f64();
}

float64_t::float64_t(double val_)
    : val(val_) {}

float64_t::float64_t(float val_)
    : val(val_) {}

float64_t::float64_t(float32_t val_)
    : val(val_.val) {}

float64_t &float64_t::operator=(double new_val) {
  val = new_val;
  return *this;
}

float64_t &float64_t::operator=(float new_val) {
  val = new_val;
  return *this;
}

float64_t &float64_t::operator=(float32_t new_val) {
  val = new_val.val;
  return *this;
}

float64_t &float64_t::operator=(int64_t new_val) {
  val = new_val;
  return *this;
}

float64_t &float64_t::operator=(int32_t new_val) {
  val = new_val;
  return *this;
}

float64_t &float64_t::operator=(int16_t new_val) {
  val = new_val;
  return *this;
}

float64_t &float64_t::operator=(int8_t new_val) {
  val = new_val;
  return *this;
}

float64_t::operator double(void) const {
  return val;
}

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
