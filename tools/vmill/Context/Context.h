/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef TOOLS_VMILL_CONTEXT_CONTEXT_H_
#define TOOLS_VMILL_CONTEXT_CONTEXT_H_

#include <cstdint>
#include <memory>
#include <unordered_map>

struct Memory;

namespace remill {
namespace vmill {

class AddressSpace;
class Context;

// A thin wrapper around a pointer to an `AddressSpace`. Address spaces managed
// by a given context must not be freed by outside code, so this pattern
// enforces this idea.
class AddressSpacePtr {
 public:
  AddressSpacePtr(const AddressSpacePtr &that) = default;
  AddressSpacePtr &operator=(const AddressSpacePtr &) = default;

  inline AddressSpace *operator->(void) const {
    return space;
  }

 private:
  friend class Context;

  AddressSpacePtr(void) = delete;

  explicit inline AddressSpacePtr(AddressSpace *space_)
      : space(space_) {}

  AddressSpace *space;
};

// An execution context. An execution context can contain the state of one or
// more emulated threads/processes.
class Context {
 public:
  static std::unique_ptr<Context> Create(void);
  static std::unique_ptr<Context> Clone(const std::unique_ptr<Context> &);

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
  AddressSpacePtr AddressSpaceOf(Memory *);

//  class InterceptorInitializer {
//   public:
//    InterceptorInitializer(const char *name, void **ptr_to_orig,
//                           void *interceptor);
//
//   private:
//    InterceptorInitializer(void) = delete;
//  };

 protected:
  static Context *&GetInterceptContext(void);

 private:
  Context(const Context &&) = delete;
  Context &operator=(Context &) = delete;
  Context &operator=(Context &&) = delete;

  Context(void);

  // Create a clone of an existing `Context`.
  explicit Context(const Context &);

  // Maps opaque `Memory *` handles to address spaces.
  std::unordered_map<Memory *, uintptr_t> address_spaces;
};

}  // namespace vmill
}  // namespace remill

#endif  // TOOLS_VMILL_CONTEXT_CONTEXT_H_
