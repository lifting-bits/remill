/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

  .file __FILE__
  .intel_syntax noprefix
  .text


/* This test should demonstrate the production of multiple discrete basic
 * blocks. Binary Ninja correctly handles this. IDA half-handles this. It
 * identifies each prefix into its own block. The problem with this is that
 * it treats prefixes as if they are their own instructions.
 */

  .globl _start
_start:
  jz .L01
  jc .L02
  jo .L03
  .byte 0x66
.L03:
  .byte 0x66
.L02:
  .byte 0xf0  /* Lock prefix */
.L01:
  .byte 0xff, 0x07  /* inc DWORD PTR [edi] */
  ret
