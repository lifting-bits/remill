/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_RUNTIME_SYSTEMCALLABI_H_
#define TOOLS_VMILL_RUNTIME_SYSTEMCALLABI_H_

#include "remill/Arch/Runtime/Types.h"

struct Memory;
struct State;

// Generic wrapper around accessing arguments passed into a system call, and
// setting the return value from the system call.
class SystemCallABI {
 public:
  SystemCallABI(void) = default;

  virtual ~SystemCallABI(void) = default;

  // Find the return address of this system call.
  virtual addr_t GetReturnAddress(Memory *memory, addr_t ret_addr) const = 0;

  template <typename T1>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1) const {
    if (!CanReadArgs(memory, state, 1)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    return true;
  }

  template <typename T1, typename T2>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1, T2 *arg2) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1, T2 *arg2, T3 *arg3) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1, T2 *arg2, T3 *arg3, T4 *arg4) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4, typename T5>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1, T2 *arg2, T3 *arg3, T4 *arg4,
                         T5 *arg5) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    *arg5 = GetArg<T5, 4>(memory, state);
    return true;
  }

  template <typename T1, typename T2, typename T3, typename T4,
            typename T5, typename T6>
  inline bool TryGetArgs(Memory *memory, State *state,
                         T1 *arg1, T2 *arg2, T3 *arg3, T4 *arg4,
                         T5 *arg5, T6 *arg6) const {
    if (!CanReadArgs(memory, state, 2)) {
      return false;
    }
    *arg1 = GetArg<T1, 0>(memory, state);
    *arg2 = GetArg<T2, 1>(memory, state);
    *arg3 = GetArg<T3, 2>(memory, state);
    *arg4 = GetArg<T4, 3>(memory, state);
    *arg5 = GetArg<T5, 4>(memory, state);
    *arg6 = GetArg<T6, 5>(memory, state);
    return true;
  }

  virtual Memory *SetReturn(Memory *, State *, addr_t) const = 0;

  template <typename T>
  inline Memory *SetReturn(Memory *memory, State *state, T val) const {
    return this->SetReturn(
        memory, state, static_cast<addr_t>(static_cast<long>(val)));
  }

  virtual addr_t GetSystemCallNum(Memory *memory, State *state) const = 0;

 protected:
  template <typename T, int i>
  inline T GetArg(Memory *memory, State *state) const {
    return static_cast<T>(GetArg(memory, state, i));
  }

  virtual bool CanReadArgs(Memory *memory, State *state,
                           int num_args) const = 0;

  virtual addr_t GetArg(Memory *&memory, State *state, int i) const = 0;
};

#endif  // TOOLS_VMILL_RUNTIME_SYSTEMCALLABI_H_
