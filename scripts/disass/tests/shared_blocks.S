/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

  .file __FILE__
  .intel_syntax noprefix
  .text


/* This test demonstrates two functions sharing several basic blocks. */

  .globl _start
_start:
  nop
  jmp .Lfoo

.Lbar:
  nop
  ret

  .globl main
main:
  nop

.Lfoo:
  nop
  jmp .Lbar
