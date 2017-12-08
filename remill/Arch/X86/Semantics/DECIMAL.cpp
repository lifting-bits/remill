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

#ifndef REMILL_ARCH_X86_SEMANTICS_DECIMAL_H_
#define REMILL_ARCH_X86_SEMANTICS_DECIMAL_H_

namespace {

DEF_SEM(AAS) {
	auto &rax = state.gpr.rax;
	auto af = Read(FLAG_AF);
	auto cf = Read(FLAG_CF);

	// al > 9 or af == 1
	if (UCmpGt(UAnd16(rax.byte.low, 0xf), 9) || UCmpEq(af, 1)) {
		rax.word = USub16(rax.word, 6);
		rax.byte.high = USub8(rax.byte.high, 1);
		cf = 1;
		af = 1;	

	} else {
		cf = 0;
		af = 0;
	}

	// in both cases
	rax.byte.low = UAnd8(rax.byte.low, 0xf);

	Write(FLAG_AF, af);
	Write(FLAG_CF, cf);

	FLAG_OF = __remill_undefined_8();
	FLAG_ZF = __remill_undefined_8();
	FLAG_PF = __remill_undefined_8();

  return memory;
}

} // namespace

IF_32BIT(DEF_ISEL(AAS) = AAS;)


#endif  // REMILL_ARCH_X86_SEMANTICS_LOGICAL_H_
