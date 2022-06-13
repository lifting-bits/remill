
#include "Whitelist.h"

#include <glog/logging.h>
#include <llvm/Support/JSON.h>

#include <string>
#include <string_view>
#include <unordered_map>

namespace {
const static std::unordered_map<
    std::string, std::function<void(X86State *, std::string_view)>>
    accessors = {{"gpr",
                  [](X86State *state, std::string_view target) {
                    uint32_t *target_ptr = nullptr;
                    if (target == "rip") {
                      target_ptr = &state->gpr.rip.dword;
                    }

                    if (target == "rax") {
                      target_ptr = &state->gpr.rax.dword;
                    }

                    if (target_ptr) {
                      *target_ptr = 0;
                      return;
                    }
                    std::string s(target);
                    throw std::runtime_error(std::string("Unknown reg: ") + s);
                  }},
                 {"aflags",
                  [](X86State *state, std::string_view target) {
                    uint8_t *target_ptr = nullptr;
                    if (target == "af") {
                      target_ptr = &state->aflag.af;
                    }

                    if (target == "zf") {
                      target_ptr = &state->aflag.zf;
                    }

                    if (target_ptr) {
                      *target_ptr = 0;
                      return;
                    }
                    std::string s(target);
                    throw std::runtime_error(std::string("Unknown reg: ") + s);
                  }

                 }

};
}


void Accessor::ApplyOverride(X86State *state) const {
  if (accessors.find(this->section) != accessors.end()) {
    accessors.find(this->section)->second(state, this->target_name);
  } else {
    throw std::runtime_error(std::string("Couldnt find section ") +
                             std::string(this->section));
  }
}

bool Accessor::fromJSON(const llvm::json::Value &E, llvm::json::Path P) {


  std::vector<std::string> section_names;

  if (!llvm::json::fromJSON(E, section_names, P.field("state_target"))) {
    return false;
  }

  if (section_names.size() != 2) {
    P.field("state_target")
        .report(
            "Currently only supports access paths of the form [section, target_var]");
    return false;
  }

  this->section = section_names[0];
  LOG(INFO) << "Section is: " << this->section;
  this->target_name = section_names[1];
  return true;
}


bool WhiteListInstruction::fromJSON(const llvm::json::Value &E,
                                    llvm::json::Path P) {
  auto maybe_obj = E.getAsObject();
  if (!maybe_obj) {
    P.report("Should be an object");
    return false;
  }

  auto maybe_isel_name = maybe_obj->find("isel_name");
  if (maybe_isel_name == maybe_obj->end()) {
    P.report("Should have isel_name object");
    return false;
  }

  std::string isel_name = "";
  if (!llvm::json::fromJSON(maybe_isel_name->second, isel_name,
                            P.field("isel_name"))) {
    return false;
  }


  auto maybe_state_target = maybe_obj->find("state_target");
  if (maybe_state_target == maybe_obj->end()) {
    P.report("Should have state target path");
    return false;
  }

  if (!llvm::json::fromJSON(maybe_state_target->second,
                            this->target_state_portion,
                            P.field("state_target"))) {
    return false;
  }

  this->target_isel_prefix = isel_name;

  return true;
}

void WhiteListInstruction::ApplyToInsn(std::string_view isel_name,
                                       X86State *state) const {
  if (isel_name.rfind(target_isel_prefix, 0) == 0) {
    this->target_state_portion.ApplyOverride(state);
  }
}


namespace llvm::json {
bool fromJSON(const Value &E, Accessor &Out, Path P) {
  return Out.fromJSON(E, P);
}
bool fromJSON(const Value &E, WhiteListInstruction &Out, Path P) {
  return Out.fromJSON(E, P);
}
}  // namespace llvm::json