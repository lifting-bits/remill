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

#pragma once

#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <test_runner/TestRunner.h>

#include <any>
#include <string>
#include <unordered_map>
#include <vector>

namespace test_runner {

using MemoryModifier = std::function<void(MemoryHandler &)>;

struct RegisterPrecondition {
  std::string register_name;
  std::variant<uint64_t, uint8_t> enforced_value;
};

struct MemoryPostcondition {
  uint64_t addr;
  std::vector<uint8_t> bytes;
};


template <typename State, typename = typename std::enable_if_t<
                              std::is_base_of<ArchState, State>::value>>
class TestOutputSpec {
 public:
  uint64_t addr;
  std::string target_bytes;

 private:
  remill::Instruction::Category expected_category;
  std::vector<RegisterPrecondition> register_preconditions;
  std::vector<RegisterPrecondition> register_postconditions;
  std::vector<MemoryModifier> initial_memory_conditions;
  std::vector<MemoryModifier> expected_memory_conditions;
  std::unordered_map<std::string, std::function<std::any(State &)>>
      reg_to_accessor;

  template <typename T>
  void ApplyCondition(State &state, std::string reg, T value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      std::any_cast<std::reference_wrapper<T>>(accessor->second(state)).get() =
          value;
    }
  }

  template <typename T>
  void CheckCondition(State &state, std::string reg, T value) const {
    auto accessor = reg_to_accessor.find(reg);
    if (accessor != reg_to_accessor.end()) {
      auto actual =
          std::any_cast<std::reference_wrapper<T>>(accessor->second(state));
      LOG(INFO) << "Reg: " << reg << " Actual: " << std::hex
                << static_cast<uint64_t>(actual.get())
                << " Expected: " << std::hex << static_cast<uint64_t>(value);
      CHECK_EQ(actual, value);
    }
  }

 public:
  template <typename T>
  void AddPrecWrite(uint64_t addr, T value) {
    this->initial_memory_conditions.push_back(
        [addr, value](MemoryHandler &mem_hand) {
          mem_hand.WriteMemory(addr, value);
        });
  }

  template <typename T>
  void AddPostRead(uint64_t addr, T value) {
    this->expected_memory_conditions.push_back(
        [addr, value](MemoryHandler &mem_hand) {
          LOG(INFO) << "Mem: " << std::hex << addr << " Actual: " << std::hex
                    << mem_hand.ReadMemory<T>(addr) << " Expected: " << std::hex
                    << value;
          CHECK_EQ(mem_hand.ReadMemory<T>(addr), value);
        });
  }

  const std::vector<MemoryModifier> &GetMemoryPrecs() const {
    return this->initial_memory_conditions;
  }

  const std::vector<MemoryModifier> &GetMemoryPosts() const {
    return this->expected_memory_conditions;
  }

  TestOutputSpec(
      uint64_t disas_addr, std::string target_bytes,
      remill::Instruction::Category expected_category,
      std::vector<RegisterPrecondition> register_preconditions,
      std::vector<RegisterPrecondition> register_postconditions,
      std::unordered_map<std::string, std::function<std::any(State &)>>
          reg_to_accessor)
      : addr(disas_addr),
        target_bytes(target_bytes),
        expected_category(expected_category),
        register_preconditions(std::move(register_preconditions)),
        register_postconditions(std::move(register_postconditions)),
        reg_to_accessor(reg_to_accessor) {}


  void SetupTestPreconditions(State &state) const {
    for (auto prec : this->register_preconditions) {
      std::visit(
          [this, &state, prec](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            this->ApplyCondition<T>(state, prec.register_name, arg);
          },
          prec.enforced_value);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) const {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(State &state) const {
    for (auto post : this->register_postconditions) {
      std::visit(
          [this, &state, post](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            this->CheckCondition<T>(state, post.register_name, arg);
          },
          post.enforced_value);
    }
  }

  void CheckResultingMemory(MemoryHandler &mem_hand) const {
    for (const auto &post : this->GetMemoryPosts()) {
      post(mem_hand);
    }
  }
};
}  // namespace test_runner
