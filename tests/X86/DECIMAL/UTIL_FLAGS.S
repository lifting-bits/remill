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

#define CLEAR_PFSFZF  lahf; and ax, 0x3bff; sahf;
#define SET_PF        lahf; bts ax, 0xa; sahf;
#define CLEAR_PF      lahf; and ax, 0xfbff; sahf;
#define SET_ZF        lahf; bts ax, 0xe; sahf;
#define CLEAR_ZF      lahf; and ax, 0xbfff; sahf;
#define SET_SF        lahf; bts ax, 0xf; sahf;
#define CLEAR_SF      lahf; and ax, 0x7fff; sahf;
#define SET_CF        lahf; bts ax, 0x8; sahf;
#define SET_AF        lahf; bts ax, 0xc; sahf;
#define CLEAR_AF      lahf; and ax, 0xefff; sahf;
#define CLEAR_CF      lahf; and ax, 0xfeff; sahf;
