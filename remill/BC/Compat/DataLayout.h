#include <llvm/IR/DataLayout.h>

inline static uint64_t SizeInBits(llvm::DataLayout &datalayout, llvm::Type *type) {
  #if LLVM_VERSION_NUMBER < LLVM_VERSION(10, 0)
  return datalayout.getTypeSizeInBits(type);
  #else
  return datalayout.getTypeSizeInBits(type).getFixedSize();
  #endif
}

static inline uint64_t BitsToTypeSize(uint64_t size) {
  #if LLVM_VERSION_NUMBER < LLVM_VERSION(10, 0)
  return size;
  #else
  return llvm::TypeSize::Fixed(size);
  #endif
}
