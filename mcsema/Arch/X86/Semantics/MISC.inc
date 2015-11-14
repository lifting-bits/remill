
namespace {

template <typename D, typename S>
DEF_SEM(LEA, D dst, S src) {
  W(dst) = src.addr;
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8>;
IF_64BIT( DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8>; )
