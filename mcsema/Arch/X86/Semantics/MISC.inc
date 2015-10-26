
namespace {

template <typename D, typename S>
DEF_SEMANTICS(LEA, D dst, S src) {
  W(dst) = reinterpret_cast<uintptr_t>(src);
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8>;
DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8>;
