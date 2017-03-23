/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include <cstdint>

#include "tools/vmill/Context/Context.h"
#include "tools/vmill/Context/AddressSpace.h"

namespace remill {
namespace vmill {
namespace {

static uintptr_t gNextMemoryHandle = 0;

// We will have one address space represent a "dead" address space. This is an
// address space that technically "works", but where all uses of it are mostly
// NO-OPs, and each use reports and error.
static AddressSpace *gDeadAddressSpace = nullptr;

// This is kind of a hack. We map opaque `Memory *` handles to address spaces,
// but not in the usual way. The mapping uses an `unordered_map`, and we don't
// want to hack to check for presence on every access, so instead we XOR in
// the `gDeadAddressSpaceAddr`. If the entry is not present, then it is default-
// initialized to `0`, so the XOR gets us `gDeadAddressSpace`. When we create
// new `AddressSpace`s, we store the address of the `AddressSpace`, XORed with
// `gDeadAddressSpaceAddr`.
static uintptr_t gDeadAddressSpaceAddr = 0;

inline static AddressSpace *ToAddressSpace(uintptr_t val) {
  return reinterpret_cast<AddressSpace *>(val ^ gDeadAddressSpaceAddr);
}

inline static uintptr_t ToAddress(AddressSpace *space) {
  return reinterpret_cast<uintptr_t>(space) ^ gDeadAddressSpaceAddr;
}

}  // namespace

std::unique_ptr<Context> Context::Create(void) {
  return std::unique_ptr<Context>(new Context);
}

std::unique_ptr<Context> Context::Clone(const std::unique_ptr<Context> &that) {
  return std::unique_ptr<Context>(new Context(*that));
}

Context::Context(void) {
  if (!gDeadAddressSpace) {
    gDeadAddressSpace = new AddressSpace;
    gDeadAddressSpace->Kill();
    gDeadAddressSpaceAddr = ToAddress(gDeadAddressSpace);
  }
}

Context::Context(const Context &parent) {
  for (auto space : parent.address_spaces) {
    if (!space.second) {
      continue;
    }

    CHECK(space.second != gDeadAddressSpaceAddr)
        << "Broken invariant!";

    auto parent_space = ToAddressSpace(space.second);
    address_spaces[space.first] = ToAddress(new AddressSpace(*parent_space));
  }
}

Context::~Context(void) {
  for (auto space : address_spaces) {
    auto addr_space = ToAddressSpace(space.second);
    if (addr_space != gDeadAddressSpace) {
      delete addr_space;
    }
  }
}

// Creates a new address space, and returns an opaque handle to it.
Memory *Context::CreateAddressSpace(void) {
  auto handle = reinterpret_cast<Memory *>(gNextMemoryHandle++);

  LOG_IF(ERROR, address_spaces.count(handle))
      << "Address space handle " << (gNextMemoryHandle - 1)
      << " has already (incorrectly) been used to reference an address space.";

  address_spaces[handle] = ToAddress(new AddressSpace);
  return handle;
}

// Clones an existing address space, and returns an opaque handle to the
// clone.
Memory *Context::CloneAddressSpace(Memory *handle) {
  auto new_handle = reinterpret_cast<Memory *>(gNextMemoryHandle++);
  auto parent = AddressSpaceOf(handle).space;
  if (parent == gDeadAddressSpace) {
    LOG(ERROR)
        << "Cloning a nonexistent or destroyed address space with handle "
        << reinterpret_cast<uintptr_t>(handle) << ".";
  } else {
    address_spaces[new_handle] = ToAddress(new AddressSpace(*parent));
  }

  return new_handle;
}

// Destroys an address space.
void Context::DestroyAddressSpace(Memory *handle) {
  auto space = AddressSpaceOf(handle).space;
  if (space == gDeadAddressSpace) {
    LOG(ERROR)
        << "Double destroy, or trying to destroy invalid address space "
        << reinterpret_cast<uintptr_t>(handle);
  } else {
    delete space;
    address_spaces[handle] = ToAddress(gDeadAddressSpace);
  }
}

AddressSpacePtr Context::AddressSpaceOf(Memory *handle) {
  return AddressSpacePtr(ToAddressSpace(address_spaces[handle]));
}

}  // namespace vmill
}  // namespace remill
