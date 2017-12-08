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

// al > 9, af = 1
TEST_BEGIN(AAS_alf_af1, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  // force af = 1 
  lahf
  bts ax, 0xc
  sahf
  mov eax, 0x0f0f
#if IN_TEST_GENERATOR
  .byte 0x3f  /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0x0e09 /* hard coded post-AAS value */
#endif /* IN_TEST_GENERATOR */
TEST_END

// al > 9, af = 1
TEST_BEGIN(AAS_alf_af1_extra, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  bts ax, 0xc
  sahf
  mov eax, 0x44440f0f
#if IN_TEST_GENERATOR
  .byte 0x3f  /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0x44440e09 /* hard coded post-AAS value */
#endif /* IN_TEST_GENERATOR */
TEST_END

// al > 9, af = 0 
TEST_BEGIN(AAS_alf_af0, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  and ax, 0xef
  sahf
  mov eax, 0x0f0f
#if IN_TEST_GENERATOR
  .byte 0x3f  /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0x0e09
#endif /* IN_TEST_GENERATOR */
TEST_END

// al < 9, af = 1
TEST_BEGIN(AAS_al8_af1, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  bts ax, 0xc
  sahf
  mov eax, 0x0f08
# if IN_TEST_GENERATOR
  .byte 0x3f /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0x0e02
#endif /* IN_TEST_GENERATOR */
TEST_END

// al = 9, af = 1
TEST_BEGIN(AAS_af9_al1, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  bts ax, 0xc
  sahf
  mov eax, 0x0f09
# if IN_TEST_GENERATOR
  .byte 0x3f /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0x0e03
#endif /* IN_TEST_GENERATOR */
TEST_END

// al = 9, af = 0
TEST_BEGIN(AAS_al9_af0, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  and ax, 0xef
  sahf
  mov eax, 0x0f09
# if IN_TEST_GENERATOR
  .byte 0x3f /* aas */
#else
  lahf
  and ax, 0xeeff
  sahf
  mov ax, 0x0f09
#endif /* IN_TEST_GENERATOR */
TEST_END

// al = 0, af = 1
TEST_BEGIN(AAS_al0_af1, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  bts ax, 0xc
  sahf
  mov eax, 0x0000
# if IN_TEST_GENERATOR
  .byte 0x3f /* aas */
#else
  lahf
  bts ax, 0xc
  bts ax, 0x8
  sahf
  mov ax, 0xfe0a
#endif /* IN_TEST_GENERATOR */
TEST_END

// al = 0, af = 0
TEST_BEGIN(AAS_al0_af0, 1)
TEST_IGNORE_FLAGS(OF ZF PF)
TEST_INPUTS(0)
  lahf
  and ax, 0xef
  sahf
  mov eax, 0x0f00
# if IN_TEST_GENERATOR
  .byte 0x3f /* aas */
#else
  lahf
  and ax, 0xeeff
  sahf
  mov ax, 0x0f00
#endif /* IN_TEST_GENERATOR */
TEST_END

#endif /* ADDRESS_SIZE_BITS == 32 */

