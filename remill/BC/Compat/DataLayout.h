#include <llvm/IR/DataLayout.h>

inline static uint64_t SizeInBits(llvm::DataLayout& DL, llvm::Type *Ty) {
	IF_LLVM_GTE_1000(return DL.getTypeSizeInBits(Ty);)
	IF_LLVM_LT_1000(return DL.getTypeSizeInBits(Ty).getFixedSize();)
}
