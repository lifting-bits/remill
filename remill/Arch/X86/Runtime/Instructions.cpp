/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

//#include "remill/Arch/Runtime/Types.cpp"

#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"

#include "remill/Arch/X86/Runtime/State.h"
#include "remill/Arch/X86/Runtime/Types.h"
#include "remill/Arch/X86/Runtime/Operators.h"


#define REG_EIP state.gpr.rip.dword
#define REG_RIP state.gpr.rip.qword

#define REG_ESP state.gpr.rsp.dword
#define REG_RSP state.gpr.rsp.qword

#define REG_EBP state.gpr.rbp.dword
#define REG_RBP state.gpr.rbp.qword

#define REG_AL state.gpr.rax.byte.low
#define REG_AH state.gpr.rax.byte.high
#define REG_AX state.gpr.rax.word
#define REG_EAX state.gpr.rax.dword
#define REG_RAX state.gpr.rax.qword

#define REG_BL state.gpr.rbx.byte.low
#define REG_BH state.gpr.rbx.byte.high
#define REG_BX state.gpr.rbx.word
#define REG_EBX state.gpr.rbx.dword
#define REG_RBX state.gpr.rbx.qword

#define REG_DL state.gpr.rdx.bytes.low
#define REG_DH state.gpr.rdx.bytes.high
#define REG_DX state.gpr.rdx.word
#define REG_EDX state.gpr.rdx.dword
#define REG_RDX state.gpr.rdx.qword

#define REG_CL state.gpr.rcx.byte.low
#define REG_CH state.gpr.rcx.byte.high
#define REG_CX state.gpr.rcx.word
#define REG_ECX state.gpr.rcx.dword
#define REG_RCX state.gpr.rcx.qword

#define REG_SIL state.gpr.rsi.bytes.low
#define REG_SI state.gpr.rsi.word
#define REG_ESI state.gpr.rsi.dword
#define REG_RSI state.gpr.rsi.qword

#define REG_DIL state.gpr.rdi.bytes.low
#define REG_DI state.gpr.rdi.word
#define REG_EDI state.gpr.rdi.dword
#define REG_RDI state.gpr.rdi.qword

#if 64 == ADDRESS_SIZE_BITS
# define REG_PC REG_RIP
# define REG_XIP REG_RIP
# define REG_XAX REG_RAX
# define REG_XDX REG_RDX
# define REG_XCX REG_RCX
# define REG_XSI REG_RSI
# define REG_XDI REG_RDI
# define REG_XSP REG_RSP
# define REG_XBP REG_RBP
# define REG_XBX REG_RBX
#else
# define REG_PC REG_EIP
# define REG_XIP REG_EIP
# define REG_XAX REG_EAX
# define REG_XDX REG_EDX
# define REG_XCX REG_ECX
# define REG_XSI REG_ESI
# define REG_XDI REG_EDI
# define REG_XSP REG_ESP
# define REG_XBP REG_EBP
# define REG_XBX REG_EBX
#endif  // 64 == ADDRESS_SIZE_BITS

#define FLAG_CF state.aflag.cf
#define FLAG_PF state.aflag.pf
#define FLAG_AF state.aflag.af
#define FLAG_ZF state.aflag.zf
#define FLAG_SF state.aflag.sf
#define FLAG_OF state.aflag.of
#define FLAG_DF state.aflag.df

#define BRANCH_TAKEN state.conditional_branch_taken
#define INTERRUPT_VECTOR state.interrupt_vector
#define INTERRUPT_TAKEN state.interrupt_taken

// Define the `PushValue` and `PopValue` helpers.
//#include "remill/Arch/X86/Semantics/POP.h"
//#include "remill/Arch/X86/Semantics/PUSH.h"
//
#include "remill/Arch/X86/Semantics/FLAGS.h"
#include "remill/Arch/X86/Semantics/BINARY.h"
#include "remill/Arch/X86/Semantics/BITBYTE.h"
#include "remill/Arch/X86/Semantics/CALL_RET.h"
#include "remill/Arch/X86/Semantics/CMOV.h"
#include "remill/Arch/X86/Semantics/COND_BR.h"
#include "remill/Arch/X86/Semantics/CONVERT.h"
#include "remill/Arch/X86/Semantics/DATAXFER.h"
#include "remill/Arch/X86/Semantics/INTERRUPT.h"
#include "remill/Arch/X86/Semantics/FMA.h"
#include "remill/Arch/X86/Semantics/LOGICAL.h"
#include "remill/Arch/X86/Semantics/MISC.h"
//#include "remill/Arch/X86/Semantics/ROTATE.h"
//#include "remill/Arch/X86/Semantics/SHIFT.h"
//#include "remill/Arch/X86/Semantics/SSE.h"
//#include "remill/Arch/X86/Semantics/STRINGOP.h"
#include "remill/Arch/X86/Semantics/UNCOND_BR.h"
//#include "remill/Arch/X86/Semantics/XOP.h"
//#include "remill/Arch/X86/Semantics/X87.h"
