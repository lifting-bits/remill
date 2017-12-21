/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if ADDRESS_SIZE_BITS == 32

// (al & 0xf) > 9, al < 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_0, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  SET_CF
  SET_AF
  CLEAR_PFSFZF
  mov eax, 0x002e
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_SF
  mov ax, 0x0094 /* hard coded post-DAA value */
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al < 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_0_f, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  SET_CF
  SET_AF
  SET_PF
  SET_ZF
  SET_SF
  mov eax, 0x002e
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  CLEAR_PFSFZF
  SET_SF
  mov ax, 0x0094
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al < 0x99, af = 0, cf = 1
TEST_BEGIN(DAA_1, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  CLEAR_AF
  SET_CF
  mov eax, 0x002e
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_SF
  mov ax, 0x0094
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al < 0x99, af = 1, cf = 0
TEST_BEGIN(DAA_2, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  SET_AF
  CLEAR_CF
  mov eax, 0x002e
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  CLEAR_SF
  mov ax, 0x0034
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al < 0x99, af = 1, cf = 0
TEST_BEGIN(DAA_3, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_CF
  SET_AF
  mov eax, 0x0fae
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  CLEAR_PFSFZF
  SET_PF
  mov ax, 0x0f14
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al < 0x99, af = 0, cf = 0
TEST_BEGIN(DAA_4, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  CLEAR_CF
  CLEAR_AF
  mov eax, 0x002e
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_AF
  CLEAR_CF
  mov ax, 0x0034
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al > 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_5, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_CF
  SET_AF
  mov eax, 0x00aa
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  CLEAR_PFSFZF
  SET_CF
  SET_AF
  mov ax, 0x0010
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al > 0x99, af = 0, cf = 0
TEST_BEGIN(DAA_6, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  CLEAR_CF
  CLEAR_AF
  mov eax, 0x009a
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_PF
  SET_ZF
  CLEAR_SF
  mov ax, 0x0000
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al > 0x99, af = 0, cf = 1
TEST_BEGIN(DAA_7, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_ZF
  CLEAR_AF
  SET_CF
  mov eax, 0x009a
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_PF
  SET_ZF
  mov ax, 0x0000
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) > 9, al > 0x99, af = 1, cf = 0
TEST_BEGIN(DAA_8, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  SET_AF
  CLEAR_CF
  mov eax, 0x009a
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_PF
  SET_ZF
  CLEAR_SF
  mov ax, 0x0000
#endif /* IN_TEST_GENERATOR */
TEST_END


// (al & 0xf) <= 9, al > 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_9, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_CF
  SET_AF
  mov eax, 0x00a9
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_PF
  mov ax, 0x000f
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al > 0x99, af = 0, cf = 0
TEST_BEGIN(DAA_a, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  SET_SF
  SET_ZF
  CLEAR_PF
  CLEAR_CF
  CLEAR_AF
  mov eax, 0x00a9
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  CLEAR_PFSFZF
  SET_CF
  SET_PF
  mov ax, 0x0009
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al > 0x99, af = 0, cf = 1
TEST_BEGIN(DAA_b, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_ZF
  SET_SF
  CLEAR_AF
  SET_CF
  mov eax, 0x00a8
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  CLEAR_PFSFZF
  mov eax, 0x0008
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al > 0x99, af = 1, cf = 0
TEST_BEGIN(DAA_c, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  SET_AF
  CLEAR_CF
  mov eax, 0x0090
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_AF
  SET_PF
  SET_SF
  mov ax, 0x0096
#endif /* IN_TEST_GENERATOR */
TEST_END


// (al & 0xf) <= 9, al <= 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_d, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_SF
  SET_CF
  SET_AF
  mov eax, 0x0000
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  CLEAR_SF
  SET_PF
  mov ax, 0x0066
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al <= 0x99, af = 0, cf = 0
TEST_BEGIN(DAA_e, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  CLEAR_AF
  CLEAR_CF
  mov eax, 0x0009
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  CLEAR_PFSFZF
  SET_PF
  mov ax, 0x0009
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al <= 0x99, af = 1, cf = 1
TEST_BEGIN(DAA_f, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  SET_CF
  SET_AF
  mov eax, 0x0039
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_CF
  SET_AF
  SET_PF
  SET_SF
  mov ax, 0x009f
#endif /* IN_TEST_GENERATOR */
TEST_END

// (al & 0xf) <= 9, al <= 0x99, af = 1, cf = 0
TEST_BEGIN(DAA_10, 1)
TEST_IGNORE_FLAGS(OF)
TEST_INPUTS(0)
  CLEAR_PFSFZF
  CLEAR_CF
  SET_AF
  mov eax, 0x0039
#if IN_TEST_GENERATOR
  .byte 0x27  /* daa */
#else
  SET_PF
  mov ax, 0x003f /* hard coded post-DAA value */
#endif /* IN_TEST_GENERATOR */
TEST_END

#endif /* ADDRESS_SIZE_BITS == 32 */
