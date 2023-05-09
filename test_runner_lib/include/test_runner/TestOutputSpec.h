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
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>


namespace test_runner {

using MemoryModifier = std::function<void(MemoryHandler &)>;
using RegisterValue = std::variant<uint64_t, uint32_t, uint8_t>;
using RegisterValueRef = std::variant<uint64_t *,
                                      uint32_t *,
                                      uint8_t *>;

struct RegisterCondition {
  std::string register_name;
  RegisterValue enforced_value;
};

template <typename T>
concept State = std::is_base_of_v<ArchState, T>;

template <State S>
class TestOutputSpec {
 public:
  uint64_t addr;
  std::string target_bytes;

 private:
  using RegisterAccessorMap =
      std::unordered_map<std::string, std::function<RegisterValueRef(S &)>>;
  using RegisterConditionList = std::vector<RegisterCondition>;
  using MemoryConditionList = std::vector<MemoryModifier>;

  remill::Instruction::Category expected_category;
  RegisterConditionList register_preconditions;
  RegisterConditionList register_postconditions;
  MemoryConditionList initial_memory_conditions;
  MemoryConditionList expected_memory_conditions;
  RegisterAccessorMap reg_to_accessor;

  template <typename T>
  T *GetRegister(S &state, const std::string &reg_name) const {
    auto accessor = reg_to_accessor.find(reg_name);
    if (accessor == reg_to_accessor.end()) {
      throw std::runtime_error(std::string("Unknown reg: ") + reg_name);
    }
    auto wrapper = accessor->second(state);
    if (auto underlying = std::get_if<T *>(&wrapper)) {
      return *underlying;
    }
    throw std::runtime_error(
        std::string("Reg value " + reg_name + " has incorrect type"));
  }

  template <typename T>
  void ApplyCondition(S &state, const std::string &reg_name, T value) const {
    auto *reg = this->GetRegister<T>(state, reg_name);
    *reg = value;
  }

  template <typename T>
  void CheckCondition(S &state, const std::string &reg_name, T value) const {
    auto actual = *(this->GetRegister<T>(state, reg_name));
    LOG(INFO) << "Reg: " << reg_name << " Actual: " << std::hex
              << static_cast<uint64_t>(actual) << " Expected: " << std::hex
              << static_cast<uint64_t>(value);
    CHECK_EQ(actual, value);
  }

 public:
  template <typename T>
  void AddPrecWrite(uint64_t addr, T value) {
    this->initial_memory_conditions.push_back(
        [=](MemoryHandler &mem_hand) { mem_hand.WriteMemory(addr, value); });
  }

  template <typename T>
  void AddPostRead(uint64_t addr, T value) {
    this->expected_memory_conditions.push_back([=](MemoryHandler &mem_hand) {
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

  TestOutputSpec(uint64_t disas_addr, std::string target_bytes,
                 remill::Instruction::Category expected_category,
                 RegisterConditionList register_preconditions,
                 RegisterConditionList register_postconditions,
                 RegisterAccessorMap reg_to_accessor)
      : addr(disas_addr),
        target_bytes(std::move(target_bytes)),
        expected_category(expected_category),
        register_preconditions(std::move(register_preconditions)),
        register_postconditions(std::move(register_postconditions)),
        reg_to_accessor(std::move(reg_to_accessor)) {}


  void SetupTestPreconditions(S &state) const {
    for (auto &prec : this->register_preconditions) {
      std::visit(
          [&](auto &arg) {
            this->ApplyCondition(state, prec.register_name, arg);
          },
          prec.enforced_value);
    }
  }

  void CheckLiftedInstruction(const remill::Instruction &lifted) const {
    CHECK_EQ(lifted.category, this->expected_category);
  }

  void CheckResultingState(S &state) const {
    for (auto &post : this->register_postconditions) {
      std::visit(
          [&](auto &arg) {
            this->CheckCondition(state, post.register_name, arg);
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
