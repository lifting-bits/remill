/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

  .file __FILE__
  .intel_syntax noprefix
  .text


/* This test demonstrates two functions sharing several basic blocks. */

  .globl _start
_start:
  call foo
  call bar
  call baz
  ret

  .globl foo
foo:
  nop
  jmp baz

  .globl bar
bar:
  nop
  jmp baz

  .globl baz
baz:
  ret
