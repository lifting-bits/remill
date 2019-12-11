#include <llvm/IR/DataLayout.h>

inline static uint64_t SizeInBits(llvm::DataLayout &datalayout, llvm::Type *type) {
	IF_LLVM_LT_1000(return datalayout.getTypeSizeInBits(type);)
	IF_LLVM_GTE_1000(return datalayout.getTypeSizeInBits(type).getFixedSize();)
}
