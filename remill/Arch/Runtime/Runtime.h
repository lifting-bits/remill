/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_RUNTIME_RUNTIME_H_
#define REMILL_ARCH_RUNTIME_RUNTIME_H_

#ifndef ADDRESS_SIZE_BITS
# define ADDRESS_SIZE_BITS 64UL
#endif

#ifndef ADDRESS_SIZE_BYTES
# define ADDRESS_SIZE_BYTES (ADDRESS_SIZE_BITS / 8UL)
#endif

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"
#include "Definitions.h"

#endif  // REMILL_ARCH_RUNTIME_RUNTIME_H_
