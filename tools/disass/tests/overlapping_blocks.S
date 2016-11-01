/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

  .file __FILE__
  .intel_syntax noprefix
  .text


/* This test should demonstrate two overlapping basic blocks. Binary Ninja
 * correctly handles this, though IDA Pro does not.
 */

  .globl _start
_start:
  .byte 0x77, 0x02, 0xc7, 0x07, 0xff, 0x07, 0x77, 0xfb
  ret
