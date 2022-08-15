
#include <glog/logging.h>
#include <remill/Arch/Context.h>

namespace remill {

DecodingContext::DecodingContext(
    std::unordered_map<std::string, uint64_t> context_value)
    : context_value(std::move(context_value)) {}


uint64_t
DecodingContext::GetContextValue(const std::string &context_reg) const {

  if (auto res = this->context_value.find(context_reg);
      res != this->context_value.end()) {
    return res->second;
  }

  LOG(FATAL) << "No context value for " << context_reg
             << " but it is required for decoding";
}
DecodingContext DecodingContext::PutContextReg(std::string creg,
                                               uint64_t value) const {
  std::unordered_map<std::string, uint64_t> new_value(this->context_value);
  new_value.emplace(creg, value);
  return DecodingContext(std::move(new_value));
}
}  // namespace remill