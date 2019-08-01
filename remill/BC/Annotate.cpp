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

#include "Annotate.h"

namespace remill {

const std::string BaseFunction::metadata_value = "base";

const std::string BaseFunction::metadata_kind = "remill.function.type";

const std::string LiftedFunction::metadata_value = BaseFunction::metadata_value + "." + "lifted";

const std::string EntrypointFunction::metadata_value = BaseFunction::metadata_value + "." +
                                                       "entrypoint";

const std::string ExternalFunction::metadata_value = BaseFunction::metadata_value + "." +
                                                     "external";


const std::string Helper::metadata_value = BaseFunction::metadata_value + "." + "helper";


const std::string RemillHelper::metadata_value = Helper::metadata_value + "." +
                                                  "remill";

const std::string McSemaHelper::metadata_value = Helper::metadata_value + "." +
                                                 "mcsema";
} // namespace remill
