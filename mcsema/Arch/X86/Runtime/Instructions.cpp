/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/X86/Runtime/State.h"
#include "mcsema/Arch/X86/Runtime/Types.h"

#include "mcsema/Arch/X86/Semantics/FLAGS.h"

#include "mcsema/Arch/X86/Semantics/BINARY.h"
#include "mcsema/Arch/X86/Semantics/BITBYTE.h"
#include "mcsema/Arch/X86/Semantics/CALL_RET.h"
#include "mcsema/Arch/X86/Semantics/CMOV.h"
#include "mcsema/Arch/X86/Semantics/COND_BR.h"
#include "mcsema/Arch/X86/Semantics/DATAXFER.h"
#include "mcsema/Arch/X86/Semantics/FMA.h"
#include "mcsema/Arch/X86/Semantics/LOGICAL.h"
#include "mcsema/Arch/X86/Semantics/MISC.h"
#include "mcsema/Arch/X86/Semantics/STACKPUSH.h"
#include "mcsema/Arch/X86/Semantics/STACKPOP.h"
#include "mcsema/Arch/X86/Semantics/UNCOND_BR.h"
#include "mcsema/Arch/X86/Semantics/XOP.h"
