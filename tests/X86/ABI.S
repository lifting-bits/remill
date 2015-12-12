/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

/* Windows 64-bit ABI */
#if defined(_WIN64) || defined(_WIN32)
# define ARG1_32 ecx
# define ARG2_32 edx
# define ARG3_32 r8d

# define ARG1_64 rcx
# define ARG2_64 rdx
# define ARG3_64 r8

/* Itanium ABI, used by Linux, Mac, Unices */
#else

# define ARG1_32 edi
# define ARG2_32 esi
# define ARG3_32 edx

# define ARG1_64 rdi
# define ARG2_64 rsi
# define ARG3_64 rdx

#endif

# define RET_32 eax
# define RET_64 rax
