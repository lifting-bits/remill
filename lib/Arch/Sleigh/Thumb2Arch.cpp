/*
 * Copyright (c) 2021-present Trail of Bits, Inc.
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

#include <glog/logging.h>
#include <remill/Arch/AArch32/AArch32Base.h>
#include <remill/Arch/AArch32/Runtime/State.h>
#include <remill/Arch/Name.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include "Arch.h"

namespace remill {
namespace sleighthumb2 {

//ARM7_le.sla"
class SleighThumb2Decoder final : public remill::sleigh::SleighDecoder {
 public:
  SleighThumb2Decoder(const remill::Arch &arch)
      : SleighDecoder(arch, "ARM7_le.sla", "ARMtTHUMB.pspec") {}


  void InitializeSleighContext(
      remill::sleigh::SingleInstructionSleighContext &ctxt) const final {
    ctxt.GetContext().setVariableDefault("TMode", 1);
  }
};
}  // namespace sleighthumb2
//     this->sleigh_ctx.GetEngine().setContextDefault("TMode", 1);

}  // namespace remill
