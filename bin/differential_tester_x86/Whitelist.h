/*
 * Copyright (c) 2022 Trail of Bits, Inc.
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

#include <llvm/Support/JSON.h>
#include <remill/Arch/X86/Runtime/State.h>

class Accessor {

  std::string section;
  std::string target_name;

 public:
  void ApplyOverride(X86State *state) const;

  bool fromJSON(const llvm::json::Value &E, llvm::json::Path P);
};


class WhiteListInstruction {
 private:
  std::string target_isel_prefix;
  Accessor target_state_portion;


 public:
  bool fromJSON(const llvm::json::Value &E, llvm::json::Path P);

  void ApplyToInsn(std::string_view isel_name, X86State *state) const;
};

namespace llvm::json {
bool fromJSON(const Value &E, Accessor &Out, Path P);
bool fromJSON(const Value &E, WhiteListInstruction &Out, Path P);
}  // namespace llvm::json