#pragma once

// Windows doesn't have the following macros defined
#ifndef _SW_INEXACT
  #define _SW_INEXACT     0x00000001              // Inexact (precision)
  #define _SW_UNDERFLOW   0x00000002              // Underflow
  #define _SW_OVERFLOW    0x00000004              // Overflow
  #define _SW_ZERODIVIDE  0x00000008              // Divide by zero
  #define _SW_INVALID     0x00000010              // Invalid
  #define _SW_DENORMAL    0x00080000              // Denormal status bit
  #define _MCW_RC         0x00000300              // Rounding Control
  #define _RC_NEAR        0x00000000              //     near
  #define _RC_DOWN        0x00000100              //     down
  #define _RC_UP          0x00000200              //     up
  #define _RC_CHOP        0x00000300              //     chop
#endif
