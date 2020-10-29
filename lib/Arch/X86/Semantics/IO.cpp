/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace {

template <typename S>
DEF_SEM(IN8, R8W dst, S port) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  Write(dst, __remill_read_io_port_8(memory, Read(port)));
  return memory;
}

template <typename S>
DEF_SEM(IN16, R16W dst, S port) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  Write(dst, __remill_read_io_port_16(memory, Read(port)));
  return memory;
}

template <typename S>
DEF_SEM(IN32, R32W dst, S port) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  WriteZExt(dst, __remill_read_io_port_32(memory, Read(port)));
  return memory;
}

template <typename S>
DEF_SEM(OUT8, S port, R8 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_write_io_port_8(memory, Read(port), Read(src));
}

template <typename S>
DEF_SEM(OUT16, S port, R16 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_write_io_port_16(memory, Read(port), Read(src));
}

template <typename S>
DEF_SEM(OUT32, S port, R32 src) {
  memory =
      __remill_sync_hyper_call(state, memory, SyncHyperCall::kAssertPrivileged);
  return __remill_write_io_port_32(memory, Read(port), Read(src));
}

}  // namespace

DEF_ISEL(IN_AL_IMMb) = IN8<I8>;
DEF_ISEL(IN_AL_DX) = IN8<R16>;
DEF_ISEL(IN_OeAX_IMMb_16) = IN16<I8>;
DEF_ISEL(IN_OeAX_DX_16) = IN16<R16>;
DEF_ISEL(IN_OeAX_IMMb_32) = IN32<I8>;
DEF_ISEL(IN_OeAX_DX_32) = IN32<R16>;

DEF_ISEL(OUT_IMMb_AL) = OUT8<I8>;
DEF_ISEL(OUT_DX_AL) = OUT8<R16>;
DEF_ISEL(OUT_IMMb_OeAX_16) = OUT16<I8>;
DEF_ISEL(OUT_DX_OeAX_16) = OUT16<R16>;
DEF_ISEL(OUT_IMMb_OeAX_32) = OUT32<I8>;
DEF_ISEL(OUT_DX_OeAX_32) = OUT32<R16>;
