/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

/* Itanium ABI, used by Linux and Mac. */
#if 64 == ADDRESS_SIZE_BITS
# define ARG1_8 dil
# define ARG2_8 sil
# define ARG3_8 dl
#endif

#define ARG1_16 di
#define ARG2_16 si
#define ARG3_16 dx

#define ARG1_32 edi
#define ARG2_32 esi
#define ARG3_32 edx

#define ARG1_64 rdi
#define ARG2_64 rsi
#define ARG3_64 rdx

#define RET_32 eax
#define RET_64 rax
