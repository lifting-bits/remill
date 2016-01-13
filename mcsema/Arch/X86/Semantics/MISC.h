
namespace {

template <typename D, typename S>
DEF_SEM(LEA, D dst, S src) {
  W(dst) = A(src);  // `src` will be a memory type.
}

DEF_SEM(LEAVE_16BIT) {
  const auto prev_bp = R(state.gpr.rbp);
  Mn<uint16_t> bp_addr = {prev_bp};

  state.gpr.rbp.word = R(bp_addr);
  W(state.gpr.rsp) = prev_bp + sizeof(uint16_t);
}

template <typename T>
DEF_SEM(LEAVE_FULL) {
  static_assert(sizeof(T) == sizeof(R(state.gpr.rbp)),
                "Invalid specialization of `LEAVE_FULL`.");
  const auto prev_bp = R(state.gpr.rbp);
  Mn<T> bp_addr = {prev_bp};

  W(state.gpr.rbp) = R(bp_addr);
  W(state.gpr.rsp) = prev_bp + sizeof(T);
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8>;
IF_64BIT( DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8>; )

DEF_ISEL(LEAVE_16) = LEAVE_16BIT;
DEF_ISEL_RI32or64(LEAVE, LEAVE_FULL);
