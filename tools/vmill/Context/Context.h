/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CONTEXT_CONTEXT_H_
#define TOOLS_VMILL_CONTEXT_CONTEXT_H_

#include <cstdint>
#include <unordered_map>

struct Memory;

namespace remill {
namespace vmill {

class AddressSpace;

// An execution context. An execution context can represent one or more
// logical threads/processes.
class Context {
 public:
  Context(void);

  // Create a clone of an existing `Context`.
  explicit Context(const Context &);

  ~Context(void);

  // Creates a new address space, and returns an opaque handle to it.
  Memory *CreateAddressSpace(void);

  // Clones an existing address space, and returns an opaque handle to the
  // clone.
  Memory *CloneAddressSpace(Memory *);

  // Destroys an address space. This doesn't actually free the underlying
  // address space. Instead it clears it out so that all futre operations
  // fail.
  void DestroyAddressSpace(Memory *);

  // Returns a pointer to the address space associated with a memory handle.
  AddressSpace *AddressSpaceOf(Memory *);

 private:
  Context(const Context &&) = delete;
  Context &operator=(Context &) = delete;
  Context &operator=(Context &&) = delete;

  // Maps opaque `Memory *` handles to address spaces.
  std::unordered_map<Memory *, uintptr_t> address_spaces;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CONTEXT_CONTEXT_H_
