/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "../Native/Compiler.h"

#include <glog/logging.h>

#include <memory>
#include <system_error>
#include <utility>

#include <llvm/Analysis/TargetLibraryInfo.h>

#include <llvm/CodeGen/AsmPrinter.h>
#include <llvm/CodeGen/MachineFunctionPass.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/CodeGen/Passes.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>

#include <llvm/MC/MCAsmBackend.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/SubtargetFeature.h>

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/ToolOutputFile.h>

#include <llvm/Target/TargetLoweringObjectFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetSubtargetInfo.h>

namespace remill {
namespace vmill {
namespace {

// Emulates `-mtune=native`. We want the compiled code to run as well as it
// can on the current machine.
static std::string GetNativeFeatureString(void) {
  llvm::SubtargetFeatures target_features;
  llvm::StringMap<bool> host_features;
  if (llvm::sys::getHostCPUFeatures(host_features)) {
    for (auto &feature : host_features) {
      target_features.AddFeature(feature.first(), feature.second);
    }
  }
  return target_features.getString();
}

// Stream for saving output machine code.
static llvm::tool_output_file *CreateOutputFile(const std::string &dest_path) {
  // Open the file.
  std::error_code error;

  auto os = new llvm::tool_output_file(dest_path, error, llvm::sys::fs::F_None);
  CHECK(!error)
      << "Error opening " << dest_path << " for writing: " << error.message();

  return os;
}

static llvm::PassRegistry *GetRegistry(void) {
  auto registry = llvm::PassRegistry::getPassRegistry();
  llvm::initializeCore(*registry);
  llvm::initializeCodeGen(*registry);
  llvm::initializeTarget(*registry);
  return registry;
}

static const llvm::Target *GetTarget(llvm::Triple target_triple) {
  std::string error;
  auto target = llvm::TargetRegistry::lookupTarget("", target_triple, error);
  CHECK(nullptr != target)
      << "Unable to find target for triple " << target_triple.getTriple()
      << ": " << error;
  return target;
}

static llvm::TargetOptions GetTargetOptions(void) {
  llvm::TargetOptions target_options;
  target_options.GuaranteedTailCallOpt = true;
  return target_options;
}

class CC final : public Compiler {
 public:
  CC(void);
  virtual ~CC(void);

  // Compile an LLVM module into a shared library.
  void CompileToSharedObject(
      llvm::Module *module, const std::string &dest_path) override;

  llvm::PassRegistry * const registry;
  llvm::Triple target_triple;
  llvm::TargetLibraryInfoImpl tli;
  const llvm::Target * const target;
  llvm::TargetOptions target_options;
  std::string feature_str;
  llvm::TargetMachine *target_machine;
};

CC::~CC(void) {}

CC::CC(void)
    : Compiler(),
      registry(GetRegistry()),
      target_triple(
          llvm::Triple::getArchTypeName(llvm::Triple::x86_64),
          llvm::Triple::getVendorTypeName(llvm::Triple::PC),
          llvm::Triple::getOSTypeName(llvm::Triple::Linux),
          llvm::Triple::getEnvironmentTypeName(llvm::Triple::GNU)),
      tli(target_triple),
      target(GetTarget(target_triple)),
      target_options(GetTargetOptions()),
      feature_str(GetNativeFeatureString()),
      target_machine(target->createTargetMachine(
          target_triple.getTriple(),
          llvm::sys::getHostCPUName(),
          feature_str,
          target_options,
          llvm::Reloc::PIC_,
          llvm::CodeModel::Large,
          llvm::CodeGenOpt::Default)) {

  CHECK(nullptr != target_machine)
      << "Unable to create target machine for target triple "
      << target_triple.getTriple() << " using CPU "
      << llvm::sys::getHostCPUName().str() << " and feature set "
      << feature_str;
}

// Compile an LLVM module into a shared library.
void CC::CompileToSharedObject(
    llvm::Module *module, const std::string &dest_path) {


//  llvm::MCContext mc_context(
//      target_machine->getMCAsmInfo(), target_machine->getMCRegisterInfo(),
//      target_machine->getObjFileLowering(), nullptr, false);

//  auto machine_code_emitter = target->createMCCodeEmitter(
//      *target_machine->getMCInstrInfo(),
//      *target_machine->getMCRegisterInfo(),
//      mc_context);
//
//  CHECK(nullptr != machine_code_emitter)
//      << "Unable to create machine code emitter.";
//
//  auto asm_backend = target->createMCAsmBackend(
//      *target_machine->getMCRegisterInfo(),
//      target_triple.getTriple(),
//      llvm::sys::getHostCPUName());
//
//  CHECK(nullptr != asm_backend)
//      << "Unable to create an ASM backend.";

  auto output_file = CreateOutputFile(dest_path);
  auto output_file_stream = &output_file->os();
//  llvm::SmallVector<char, 0> byte_buffer;
//  llvm::raw_svector_ostream byte_buffer_stream(byte_buffer);
//  std::unique_ptr<llvm::MCStreamer> asm_streamer(
//      target->createMCObjectStreamer(
//          target_triple, mc_context, *asm_backend, *output_file_stream,
//          machine_code_emitter, *target_machine->getMCSubtargetInfo(),
//          true /* RelaxAll */, true /* IncrementalLinkerCompatible */,
//          false  /* DWARFMustBeAtTheEnd */));
//
//
////  llvm::TargetRegistry::RegisterAsmPrinter(*target);
//  auto printer = target->createAsmPrinter(
//      *target_machine, std::move(asm_streamer));
//
//  CHECK(nullptr != printer)
//        << "Unable to create assembly printer pass for target triple "
//        << target_triple.getTriple() << " using CPU "
//        << llvm::sys::getHostCPUName().str() << " and feature set "
//        << feature_str;

  llvm::legacy::PassManager pm;
//  llvm::MCContext *mc_context = nullptr;
  target_machine->addPassesToEmitFile(
      pm, *output_file_stream, llvm::TargetMachine::CGFT_ObjectFile);
  //, mc_context, output_file_stream);
//  pm.add(new llvm::TargetLibraryInfoWrapperPass(tli));
//  pm.add(printer);
//  pm.add(llvm::createFreeMachineFunctionPass());

  // Compile it?
  module->setTargetTriple(target_triple.getTriple());
  module->setDataLayout(target_machine->createDataLayout());
  pm.run(*module);

//  auto &llvmtm = static_cast<llvm::LLVMTargetMachine &>(*target_machine);
//  auto &target_pass_config = *llvmtm.createPassConfig(pm);


  //delete machine_code_emitter;
//  delete output_file;
//  delete target_machine;

}
}  // namespace

Compiler *Compiler::Create(void) {
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmPrinter();
  return new CC;
}

Compiler::~Compiler(void) {}
Compiler::Compiler(void) {}



}  // namespace vmill
}  // namespace remill
