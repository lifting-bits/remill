/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

namespace remill {

struct _colored {
  std::string _str;

  _colored(std::string str, std::string color) : _str(std::move(color) + std::move(str)) {}

  std::string operator()() {
    _str += "\033[0m";
    return std::move(_str);
  }
};

struct green : _colored {
  green(std::string str) : _colored(std::move(str), "\033[92m") {}
};

struct red : _colored {
  red(std::string str) : _colored(std::move(str), "\033[91m") {}
};

} // namespace remill
