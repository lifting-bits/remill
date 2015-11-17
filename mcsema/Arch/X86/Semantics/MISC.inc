
namespace {

template <typename D, typename S>
DEF_SEM(LEA, D dst, S src) {
  W(dst) = src.addr;
}

DEF_SEM(LEAVE_16BIT) {
  state.gpr.rsp.word = state.gpr.rbp.word;
  auto addr = state.gpr.rsp.full;
  state.gpr.rbp.word = Mn<uint16_t>::Read(addr);
  state.gpr.rsp.full = addr + sizeof(uint16_t);
}

template <typename T>
DEF_SEM(LEAVE_FULL) {
  static_assert(sizeof(T) == sizeof(state.gpr.rbp.full),
                "Invalid specialization of `LEAVE_FULL`.");
  uintptr_t addr = state.gpr.rbp.full;
  state.gpr.rbp.full = Mn<T>::Read(addr);
  state.gpr.rsp.full = addr + sizeof(T);
}

}  // namespace

DEF_ISEL(LEA_GPRv_AGEN_32) = LEA<R32W, M8>;
IF_64BIT( DEF_ISEL(LEA_GPRv_AGEN_64) = LEA<R64W, M8>; )

DEF_ISEL(LEAVE_16) = LEAVE_16BIT;
DEF_ISEL_READONLY_32OR64(LEAVE, LEAVE_FULL);
