/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

  .file __FILE__
  .intel_syntax noprefix
  
  .text


/* This test demonstrates a jump table whose upper bound is checked within a
 * predecessor block. */

  .globl _start
_start:
  call neg_check
  call pos_check
  ret

  .globl target_table

  .globl neg_check
neg_check:
  cmp eax, 4
  jnb .Lbad
  jmp DWORD PTR [table + eax * 4]
.Lbad:
  ret

  .globl pos_check
pos_check:
  cmp eax, 4
  jb .Lgood
  ret
.Lgood:
  jmp DWORD PTR [table + eax * 4]
  
  ud2
  ud2

  .globl target_table
target_table:
.Ltarget0:
  ret
  ud2
.Ltarget1:
  ret
  ud2
.Ltarget2:
  ret
  ud2
.Ltarget3:
  ret
  ud2
.Ltarget4:
  ret  /* Should not be part of the jump table! */

  .data
table:
  .long .Ltarget0, .Ltarget1, .Ltarget2, .Ltarget3, .Ltarget4
