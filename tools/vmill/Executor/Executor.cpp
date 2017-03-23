/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <glog/logging.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Util.h"

#include "tools/vmill/BC/Translator.h"
#include "tools/vmill/CFG/Decoder.h"
#include "tools/vmill/Executor/Executor.h"
#include "tools/vmill/OS/System.h"

namespace remill {
namespace vmill {

Executor::Executor(const Runtime *runtime_, const Arch * const arch_)
    : runtime(runtime_),
      arch(arch_),
      decoder(new Decoder(arch)),
      translator(Translator::Create(arch)) {
  UpdateFunctionIndex();
}

Executor::~Executor(void) {
  delete translator;
  delete decoder;
  delete arch;
}

// Compiles or recompiles the bitcode in order to satisfy a new execution
// request for code that we don't yet have lifted.
void Executor::LiftCodeAtProgramCounter(Process *process) {

  auto memory = process->MachineMemory();
  auto curr_pc = process->NextProgramCounter();

  DLOG(INFO)
      << "Lifting code for " << std::hex << curr_pc;

  CFGCallback lift_cfg = [=] (const cfg::Module *cfg) {
    translator->LiftCFG(cfg);
  };

  ByteReaderCallback byte_reader = [=] (uint64_t addr, uint8_t *byte) {
    AddressRange info = {};
    if (memory->QueryMemory(addr, &info) && info.can_read && info.can_exec) {
      return memory->TryRead(addr, byte);
    } else {
      return false;
    }
  };

  auto cfg = decoder->DecodeToCFG(curr_pc, byte_reader);
  decoder->DecodeToCFG(curr_pc, byte_reader, lift_cfg);
  UpdateFunctionIndex();

  CHECK(pc_to_func.count(curr_pc))
      << "Failed to lift code associated with PC " << std::hex << curr_pc;
}

Executor::Status Executor::Execute(Process *process) {
  while (auto thread = process->ScheduleNextThread()) {
    auto pc = thread->NextProgramCounter();
    auto func_it = pc_to_func.find(pc);

    // If we don't have the lifted code, then go lift it!
    if (func_it == pc_to_func.end()) {
      LiftCodeAtProgramCounter(process);
      func_it = pc_to_func.find(pc);

      CHECK(func_it != pc_to_func.end())
          << "Unable to find code associated with PC " << std::hex << pc;
    }

    const auto exec_flow = Execute(process, thread, func_it->second);

    switch (exec_flow) {
      case kFlowAsyncHyperCall:
        return Executor::kStatusStoppedAtAsyncHyperCall;

      case kFlowError:
        return Executor::kStatusStoppedAtError;

      case kFlowFunctionCall:
      case kFlowFunctionReturn:
      case kFlowJump:
        break;
    }
  }

  CHECK(false)
      << "Fell off end of executor!";

  return Executor::kStatusStoppedAtError;
}

// Updates `func_index` with whatever is in the lifted module.
void Executor::UpdateFunctionIndex(void) {
  translator->VisitModule([=] (llvm::Module *module) {
                            ForEachIndirectBlock(
                                module,
                                [=] (uint64_t pc, llvm::Function *func) {
                                  pc_to_func[pc] = func;
                                  func_to_pc[func] = pc;
                                });
                          });
}

}  // namespace vmill
}  // namespace remill
