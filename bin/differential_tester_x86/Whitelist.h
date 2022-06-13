#include <llvm/Support/JSON.h>
#include <remill/Arch/X86/Runtime/State.h>

class Accessor {

  std::string section;
  std::string target_name;

 public:
  void ApplyOverride(X86State *state) const;

  bool fromJSON(const llvm::json::Value &E, llvm::json::Path P);
};


class WhiteListInstruction {
 private:
  std::string target_isel_prefix;
  Accessor target_state_portion;


 public:
  bool fromJSON(const llvm::json::Value &E, llvm::json::Path P);

  void ApplyToInsn(std::string_view isel_name, X86State *state) const;
};

namespace llvm::json {
bool fromJSON(const Value &E, Accessor &Out, Path P);
bool fromJSON(const Value &E, WhiteListInstruction &Out, Path P);
}  // namespace llvm::json