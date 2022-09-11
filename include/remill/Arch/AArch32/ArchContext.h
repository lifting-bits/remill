#pragma once

#include <remill/Arch/Context.h>

#include <string>

namespace remill {

extern const std::string_view kThumbModeRegName;

extern const remill::DecodingContext kThumbContext;
extern const remill::DecodingContext kARMContext;
}  // namespace remill