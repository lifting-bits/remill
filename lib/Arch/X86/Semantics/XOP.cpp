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

#pragma once

/*
 * See https://en.wikipedia.org/wiki/XOP_instruction_set

1990 VPCMOV VPCMOV_XMMdq_XMMdq_MEMdq_XMMdq XOP XOP XOP ATTRIBUTES:
1991 VPCMOV VPCMOV_XMMdq_XMMdq_XMMdq_XMMdq XOP XOP XOP ATTRIBUTES:
1992 VPCMOV VPCMOV_XMMdq_XMMdq_XMMdq_MEMdq XOP XOP XOP ATTRIBUTES:
1993 VPCMOV VPCMOV_XMMdq_XMMdq_XMMdq_XMMdq XOP XOP XOP ATTRIBUTES:
1994 VPCMOV VPCMOV_YMMqq_YMMqq_MEMqq_YMMqq XOP XOP XOP ATTRIBUTES:
1995 VPCMOV VPCMOV_YMMqq_YMMqq_YMMqq_YMMqq XOP XOP XOP ATTRIBUTES:
1996 VPCMOV VPCMOV_YMMqq_YMMqq_YMMqq_MEMqq XOP XOP XOP ATTRIBUTES:
1997 VPCMOV VPCMOV_YMMqq_YMMqq_YMMqq_YMMqq XOP XOP XOP ATTRIBUTES:
 */
