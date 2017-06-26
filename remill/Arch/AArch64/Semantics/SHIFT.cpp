/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

template <typename D, typename S>
DEF_SEM(ASR, D dst, S src, I8 count) {
  auto sval = Signed(Read(src));
  uint64_t scount = Read(count);
  Write(dst, Unsigned(SShr(sval, Signed(scount))));
  return memory;
}

}



DEF_ISEL(ASR_SBFM_64M_BITFIELD) = ASR<R64W, R64>;
