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

template <typename... Args>
DEF_SEM(PREFETCH, Args...) {
  return memory;
}

}  // namespace

DEF_ISEL(CLWB_MEMmprefetch) = PREFETCH<>;
DEF_ISEL(PREFETCH_RESERVED_0F0Dr4) = PREFETCH<M8>;
DEF_ISEL(PREFETCH_RESERVED_0F0Dr5) = PREFETCH<M8>;
DEF_ISEL(PREFETCH_RESERVED_0F0Dr6) = PREFETCH<M8>;
DEF_ISEL(PREFETCH_RESERVED_0F0Dr7) = PREFETCH<M8>;
DEF_ISEL(PREFETCHT2_MEMmprefetch) = PREFETCH<M8>;
DEF_ISEL(PREFETCHT1_MEMmprefetch) = PREFETCH<M8>;
DEF_ISEL(PREFETCHT0_MEMmprefetch) = PREFETCH<M8>;
DEF_ISEL(CLFLUSHOPT_MEMmprefetch) = PREFETCH<M8>;
DEF_ISEL(PREFETCH_EXCLUSIVE_MEMmprefetch) = PREFETCH<M8>;
IF_AVX512(DEF_ISEL(PREFETCHWT1_MEMu8) = PREFETCH<M8>;)
DEF_ISEL(PREFETCHW_0F0Dr1) = PREFETCH<M8>;
DEF_ISEL(PREFETCHW_0F0Dr3) = PREFETCH<M8>;
DEF_ISEL(PREFETCHNTA_MEMmprefetch) = PREFETCH<M8>;
