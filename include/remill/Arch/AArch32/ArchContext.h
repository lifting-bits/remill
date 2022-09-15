#pragma once

#include <remill/Arch/Context.h>

#include <string>

namespace remill {
inline const std::string_view kThumbModeRegName = "TMReg";

inline const remill::DecodingContext kThumbContext =
    remill::DecodingContext({{std::string(remill::kThumbModeRegName), 1}});
inline const remill::DecodingContext kARMContext =
    remill::DecodingContext({{std::string(remill::kThumbModeRegName), 0}});

}  // namespace remill