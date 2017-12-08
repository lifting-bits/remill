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
/* 
 901 AAS AAS DECIMAL BASE I86 ATTRIBUTES: 
 3 
	0 REG0 SUPPRESSED RW REG INVALID AL 
	1 REG1 SUPPRESSED RW REG INVALID AH 
	2 REG2 SUPPRESSED RW NT_LOOKUP_FN INVALID RFLAGS */

DEF_SEM(AAS) {
 	uint8_t al = Read(REG_AL);
	uint8_t ah = Read(REG_AH);
	auto af = Read(FLAG_AF);
	auto cf = Read(FLAG_CF);
	
	if (UCmpGt(al, 9) || UCmpEq(af, 1)) {
		ah = USub8(ah, 1);
		al = USub8(al, 6);
		cf = 1;
		af = 1;	
	} else {
		cf = 0;
		af = 0;
	}
	
	auto masked_al = UAnd8(al, 0xf);

	Write(REG_AH, ah);
	Write(REG_AL, masked_al); 
	Write(FLAG_AF, af);
	Write(FLAG_CF, cf);

  return memory;
}

} // namespace

IF_32BIT(DEF_ISEL(AAS) = AAS;)


#endif  // REMILL_ARCH_X86_SEMANTICS_LOGICAL_H_
