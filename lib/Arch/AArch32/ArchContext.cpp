#include <remill/Arch/AArch32/ArchContext.h>

namespace remill {
const std::string_view kThumbModeRegName = "TMReg";

const remill::DecodingContext kThumbContext =
    remill::DecodingContext({{std::string(remill::kThumbModeRegName), 1}});
const remill::DecodingContext kARMContext =
    remill::DecodingContext({{std::string(remill::kThumbModeRegName), 0}});
}  // namespace remill