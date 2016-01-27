#!/usr/bin/env python
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

if "__main__" != __name__:
  exit(0)

from buildsystem import *

if OS not in ("mac", "linux"):
  print "Unsupported platform: {}".format(OS)
  exit(1)

# Find all source code.
source_paths = []
source_paths.append(
  os.path.join(MCSEMA_SRC_DIR, "Translate.cpp"))
source_paths.extend(list(
  glob.glob(os.path.join(MCSEMA_SRC_DIR, "Arch", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(MCSEMA_SRC_DIR, "Arch", "X86", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(MCSEMA_SRC_DIR, "CFG", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(MCSEMA_SRC_DIR, "BC", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(MCSEMA_SRC_DIR, "OS", "*.cpp"))))

# Find the pre-existing static libraries to link in.
object_files = [
  StaticLibrary("xed"),
  StaticLibrary("protobuf"),
  StaticLibrary("gflags"),
  StaticLibrary("glog")]

# System libraries.
system_libraries = [
  LinkerLibrary("dl"),
  LinkerLibrary("pthread"),
  LinkerLibrary("curses"),
  LinkerLibrary("c++", os="mac"),
  LinkerLibrary("c++abi", os="mac")]

# Find the LLVM libraries to link in.
libraries = [ConfigLibraries(
  os.path.join(MCSEMA_BIN_DIR, "llvm-config"), "--libs")]
libraries.extend(system_libraries)

# Create a program that lifts a CFG protobuf file into 
cfg_to_bc = TargetExecutable(
  os.path.join(MCSEMA_BUILD_DIR, "cfg_to_bc"),
  source_files=[SourceFile(f) for f in source_paths],
  object_files=object_files,
  libraries=libraries)

# Create an LLVM plugin for optimizing lifted bitcode files.
libOptimize = TargetLibrary(
  os.path.join(MCSEMA_BUILD_DIR, "libOptimize.{}".format(SHARED_LIB_EXT)),
  source_files=[
    SourceFile(os.path.join(MCSEMA_DIR, "mcsema", "Optimize.cpp"))])

# Build the test cases for a particular arch.
def BuildTests(arch, bits, suffix, has_avx, has_avx512):
  target_args = [
    "-mavx",
    "-mavx512f",
    "-mavx512pf",
    "-mavx512er",
    "-mavx512cd"]

  macro_args = [
    "-DADDRESS_SIZE_BITS={}".format(bits),
    "-DHAS_FEATURE_AVX={}".format(has_avx),
    "-DHAS_FEATURE_AVX512={}".format(has_avx512)]

  # Create an executable that will create a CFG file describing all of
  # the testcases for this arch/config.
  gen_cfg = TargetExecutable(
    os.path.join(MCSEMA_BUILD_DIR, "gen_cfg_{}{}".format(arch, suffix)),
    source_files=[
      SourceFile(
        os.path.join(MCSEMA_TEST_DIR, "X86", "Generate.cpp"),
        extra_args=macro_args),

      # The `Tests.S` file needs to be compiled with extra arguments
      # that enable Clang to assemble code with extra features.
      SourceFile(
        os.path.join(MCSEMA_TEST_DIR, "X86", "Tests.S"),
        extra_args=macro_args+target_args+["-DIN_TEST_GENERATOR"]),
      
      SourceFile(os.path.join(MCSEMA_SRC_DIR, "CFG", "CFG.cpp"))],
    object_files=object_files,
    libraries=libraries)

  # CFG protobuf that will describe the test cases.
  cfg_file = os.path.join(
    MCSEMA_GEN_DIR, "tests", "cfg_{}{}".format(arch, suffix))

  # Lifted bitcode of the test cases.
  bc_file = os.path.join(
    MCSEMA_GEN_DIR, "tests", "bc_{}{}".format(arch, suffix))

  sem_file = os.path.join(
    MCSEMA_GEN_DIR, "sem_{}{}.bc".format(arch, suffix))

  MakeDirsForFile(cfg_file)

  # Generate a CFG protobuf for the test cases for this specific arch/config.
  gen_cfg.Execute("--cfg_out={}".format(cfg_file))
  
  # Lift the testcases to a bitcode file.
  cfg_to_bc.Execute(
    "--cfg={}".format(cfg_file),
    "--os_in={}".format(OS),
    "--os_out={}".format(OS),
    "--arch_in={}".format(arch),
    "--arch_out=amd64",
    "--bc_in={}".format(sem_file),
    "--bc_out={}.bc".format(bc_file))

  # Build the test runner.
  run_tests = TargetExecutable(
    os.path.join(MCSEMA_BUILD_DIR, "run_tests_{}{}".format(arch, suffix)),
    source_files=[
      SourceFile(
        "{}.bc".format(bc_file),
        extra_args=["-O3", "-mno-avx", "-mno-sse"]),
      SourceFile(
        os.path.join(MCSEMA_TEST_DIR, "X86", "Tests.S"),
        extra_args=macro_args+target_args),
      SourceFile(
        os.path.join(MCSEMA_TEST_DIR, "X86", "Run.cpp"),
        extra_args=macro_args)],
    object_files=[
      StaticLibrary("gflags"),
      StaticLibrary("glog"),
      StaticLibrary("gtest")],
    libraries=system_libraries)

# Iterate over various target settings to produce test case files
# that will let us exercise different features of the bitcode lifter
# for X86 code.
for target in [("x86", 32), ("amd64", 64)]:
  for avx in [("", 0, 0), ("_avx", 1, 0)]: #, ("_avx512", 1, 1)]:
    arch, bits = target
    suffix, has_avx, has_avx512 = avx
    Task(BuildTests, arch, bits, suffix, has_avx, has_avx512)

# Wait for all executors to finish.
FinishAllTasks()
