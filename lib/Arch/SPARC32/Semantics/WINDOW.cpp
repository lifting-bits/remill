/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 */

namespace {

template <typename S1, typename S2, typename D>
DEF_SEM(SAVE, S1 src1, S2 src2, D dst, RegisterWindow *window,
        RegisterWindow *&prev_window) {
  addr_t sp_base = Read(src1);
  addr_t sp_offset = Read(src2);
  addr_t new_sp = UAdd(sp_base, sp_offset);
  SAVE_WINDOW(memory, state, window, prev_window);
  WriteZExt(dst, new_sp);
  return memory;
}

template <typename S1, typename S2, typename D>
DEF_SEM(RESTORE, S1 src1, S2 src2, D dst, RegisterWindow *&prev_window) {
  auto rs1 = Read(src1);
  auto rs2 = Read(src2);
  auto sum = UAdd(rs1, rs2);
  RESTORE_WINDOW(memory, state, prev_window);
  WriteZExt(dst, sum);
  return memory;
}

}  // namespace

DEF_ISEL(SAVE) = SAVE<R32, I32, R32W>;
DEF_ISEL(RESTORE) = RESTORE<R32, I32, R32W>;
