#include <llvm/IR/DataLayout.h>

namespace remill {

#if LLVM_VERSION_NUMBER < LLVM_VERSION(10, 0)
inline static uint64_t TypeSizeToBits(uint64_t bits) {
  return bits;
}
inline static uint64_t BitsToTypeSize(uint64_t size) {
  return size;
}
#else
inline static uint64_t TypeSizeToBits(llvm::TypeSize type_type) {
  return type_type.getFixedSize();
}
inline static llvm::TypeSize BitsToTypeSize(uint64_t size) {
  return llvm::TypeSize::Fixed(size);
}
#endif

inline static uint64_t SizeOfTypeInBits(
    const llvm::DataLayout &data_layout, llvm::Type *type) {
  return TypeSizeToBits(data_layout.getTypeSizeInBits(type));
}

}  // namespace remill
