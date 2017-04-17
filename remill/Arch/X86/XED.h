/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef REMILL_ARCH_X86_XED_H_
#define REMILL_ARCH_X86_XED_H_

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
extern "C" {
#define XED_DLL
#include <xed/xed-interface.h>
}  // extern C
#pragma clang diagnostic pop

#endif  // REMILL_ARCH_X86_XED_H_
