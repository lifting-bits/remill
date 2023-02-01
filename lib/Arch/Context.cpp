
#include <glog/logging.h>
#include <remill/Arch/Context.h>

namespace remill {


bool DecodingContext::operator==(remill::DecodingContext const &rhs) const {
  return this->context_value == rhs.context_value;
}

DecodingContext::DecodingContext(ContextValues context_value)
    : context_value(std::move(context_value)) {}


uint64_t
DecodingContext::GetContextValue(const std::string &context_reg) const {
  if (auto res = this->context_value.find(context_reg);
      res != this->context_value.end()) {
    return res->second;
  }

  LOG(FATAL) << "Required context reg value for: " << context_reg;
}

DecodingContext DecodingContext::PutContextReg(std::string creg,
                                               uint64_t value) const {
  auto new_value = context_value;
  new_value.emplace(creg, value);
  return DecodingContext(std::move(new_value));
}

void DecodingContext::UpdateContextReg(std::string creg, uint64_t value) {
  this->context_value[creg] = value;
}

void DecodingContext::DropReg(const std::string &creg) {
  this->context_value.erase(creg);
}

bool DecodingContext::HasValueForReg(const std::string &creg) const {
  return this->context_value.find(creg) != this->context_value.end();
}


DecodingContext
DecodingContext::ContextWithoutRegister(const std::string &creg) const {
  DecodingContext cpy = *this;
  cpy.DropReg(creg);
  return cpy;
}

const ContextValues &DecodingContext::GetContextValues() const {
  return this->context_value;
}

}  // namespace remill
