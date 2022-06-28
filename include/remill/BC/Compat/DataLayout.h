#include <llvm/IR/DataLayout.h>

namespace remill {

inline static uint64_t TypeSizeToBits(llvm::TypeSize type_type) {
  return type_type.getFixedSize();
}

inline static llvm::TypeSize BitsToTypeSize(uint64_t size) {
  return llvm::TypeSize::Fixed(size);
}

inline static uint64_t SizeOfTypeInBits(const llvm::DataLayout &data_layout,
                                        llvm::Type *type) {
  return TypeSizeToBits(data_layout.getTypeSizeInBits(type));
}

}  // namespace remill
