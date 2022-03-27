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


#include "SleighArch.h"

#include <glog/logging.h>

namespace remill::sleigh {

SleighArch::SleighArch(llvm::LLVMContext *context_, OSName os_name_,
                       ArchName arch_name_, std::string sla_name)
    : Arch(context_, os_name_, arch_name_),
      engine(&image, &ctx) {
  DocumentStorage storage;
  const std::optional<std::filesystem::path> sla_path =
      ::sleigh::FindSpecFile(sla_name.c_str());
  if (!sla_path) {
    LOG(FATAL) << "Couldn't find required spec file: " << sla_name << '\n';
  }
  Element *root = storage.openDocument(sla_path->string())->getRoot();
  storage.registerTag(root);
  engine.initialize(storage);

  // This needs to happen after engine initialization
  cur_addr = Address(engine.getDefaultCodeSpace(), 0x0);
}


CustomLoadImage::CustomLoadImage(void) : LoadImage("nofile") {}

void CustomLoadImage::AppendInstruction(std::string_view instr_bytes) {
  image_buffer.append(instr_bytes);
}

void CustomLoadImage::loadFill(unsigned char *ptr, int size,
                               const Address &addr) {
  uint8_t start = addr.getOffset();
  for (int i = 0; i < size; ++i) {
    uint64_t offset = start + i;
    ptr[i] = offset < image_buffer.size() ? image_buffer[i] : 0;
  }
}

std::string CustomLoadImage::getArchType(void) const {
  return "custom";
}

void CustomLoadImage::adjustVma(long) {}


}  // namespace remill::sleigh