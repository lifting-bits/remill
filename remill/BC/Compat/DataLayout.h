#include <llvm/IR/DataLayout.h>

inline static uint64_t SizeInBits(llvm::DataLayout &datalayout, llvm::Type *type) {
  IF_LLVM_LT_1000(return datalayout.getTypeSizeInBits(type);)
  IF_LLVM_GTE_1000(return datalayout.getTypeSizeInBits(type).getFixedSize();)
}

static inline uint64_t ToSize(uint64_t size) {
  IF_LLVM_LT_1000(return size;)
  IF_LLVM_GTE_1000(return llvm::TypeSize::Fixed(size);)
}
