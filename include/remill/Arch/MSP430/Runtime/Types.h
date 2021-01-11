/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#pragma once

typedef RnW<uint16_t> R16W;

typedef Rn<uint16_t> R16;

typedef Mn<uint8_t> M8;
typedef Mn<uint16_t> M16;

typedef MnW<uint8_t> M8W;
typedef MnW<uint16_t> M16W;

typedef In<uint8_t> I8;
typedef In<uint16_t> I16;

typedef In<addr_t> PC;
typedef In<addr_t> IMM;
