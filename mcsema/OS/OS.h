/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MCSEMA_OS_OS_H_
#define MCSEMA_OS_OS_H_

#include <string>

namespace mcsema {

enum OSName {
  kOSInvalid,
  kOSMacOSX,
  kOSLinux
};

OSName GetOSName(std::string name_);

}  // namespace mcsema

#endif  // MCSEMA_OS_OS_H_
