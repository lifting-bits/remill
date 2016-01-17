#!/usr/bin/env python

import concurrent.futures
import glob
import hashlib
import os
import subprocess
import sys

MCSEMA_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

CC = os.path.join(MCSEMA_DIR, "third_party", "bin", "clang")
CXX = os.path.join(MCSEMA_DIR, "third_party", "bin", "clang++")

OS = {
  "darwin": "mac",
  "linux": "linux",
  "linux2": "linux",
  "win32": "win",
}[sys.platform]

SHARED_LIB_EXT = {
  "linux": "so",
  "mac": "dylib",
  "win": "dll",
}[OS]

SRC_DIR = os.path.join(MCSEMA_DIR, "mcsema")
BUILD_DIR = os.path.join(MCSEMA_DIR, "build")
TEST_DIR = os.path.join(MCSEMA_DIR, "tests")
GEN_DIR = os.path.join(MCSEMA_DIR, "generated")
INCLUDE_DIR = os.path.join(MCSEMA_DIR, "third_party", "include")
BIN_DIR = os.path.join(MCSEMA_DIR, "third_party", "bin")
LIB_DIR = os.path.join(MCSEMA_DIR, "third_party", "lib")

POOL = concurrent.futures.ThreadPoolExecutor(max_workers=32)

CXX_FLAGS = [
  # Enable warnings.
  "-Wall",
  "-Werror",
  "-pedantic",

  # Disable specific warnings.
  "-Wno-nested-anon-types",
  "-Wno-extended-offsetof",
  "-Wno-gnu-anonymous-struct",
  "-Wno-variadic-macros",
  "-Wno-gnu-zero-variadic-macro-arguments",
  "-Wno-error=unused-command-line-argument",
  "-Wno-override-module",
  
  # Features.
  "-fno-rtti",
  "-fno-exceptions",
  "-std=gnu++11",

  # Macros.
  '-DMCSEMA_DIR="{}"'.format(MCSEMA_DIR),
  '-DMCSEMA_OS="{}"'.format(OS),
  "-D__STDC_LIMIT_MACROS",
  "-D__STDC_CONSTANT_MACROS",
  "-DGOOGLE_PROTOBUF_NO_RTTI",

  # Includes.
  "-isystem", INCLUDE_DIR,
  "-I{}".format(MCSEMA_DIR),

  # Output info.
  "-fPIC",
  "-fpie",
  "-g3",
  "-m64",
]

# Dictionary for memoizing the compilation of source files.
SOURCE_FILES = {}
TASKS = []


# Execute a command.
def Command(*args):
  args = [str(a) for a in args]
  try:
    return subprocess.check_output(args)
  except:
    print " ".join(args)


# Run some task asynchronously.
def Task(func, *args, **kargs):
  future = POOL.submit(func, *args, **kargs)
  TASKS.append(future)
  return future


# Wait until all pending tasks are done.
def FinishAllTasks():
  for task in TASKS:
    task.result()
  POOL.shutdown()


# Recursively make directors.
def MakeDirsForFile(file_name):
  dir_name = os.path.dirname(file_name)
  while not os.path.exists(dir_name):
    try:
      os.makedirs(dir_name)
    except:
      pass


class FileName(object):
  """File name wrapper. A file name is either a string or a
  Future returning a string."""
  def __init__(self, path):
    self.path = path

  def __str__(self):
    if isinstance(self.path, str) or isinstance(self.path, unicode):
      return os.path.abspath(self.path)
    assert isinstance(self.path, concurrent.futures.Future)
    return os.path.abspath(str(self.path.result()))


class _File(object):
  """Generic file abstraction with a method of extracting the
  file location."""
  def __init__(self, path):
    self.path = path

  def Paths(self):
    return [self.path]

  def __str__(self):
    return str(self.path)


class _SourceFile(_File):
  """Source file that will be compiled."""
  def __init__(self, source_path, target_path, extra_args):
    super(_SourceFile, self).__init__(FileName(Task(
      self._Build,
      source_path,
      target_path,
      extra_args)))

  def _Build(self, source_path, target_path, extra_args):
    MakeDirsForFile(target_path)
    args = [CXX]
    args.extend(CXX_FLAGS)
    args.extend(extra_args)
    args.extend([
      "-c", source_path,
      "-o", target_path])
    Command(*args)
    return target_path


# Memoized source file compiler. Names compiled object files
# in terms of the extra args and the path to the source file.
def SourceFile(path, extra_args=[]):
  path = os.path.abspath(str(path))
  key = hashlib.md5("{}{}".format(path, "".join(extra_args))).hexdigest()
  target_path = os.path.join(BUILD_DIR, "{}.o".format(key))
  if target_path not in SOURCE_FILES:
    SOURCE_FILES[target_path] = _SourceFile(
      path, target_path, extra_args)
  return SOURCE_FILES[target_path]


class StaticLibrary(_File):
  """Pre-compiled library within the source/library dirs."""
  def __init__(self, name):
    abs_path = os.path.abspath(name)
    if not os.path.exists(abs_path):
      for where in (LIB_DIR, BUILD_DIR):
        for ext in ("o", "a", "so", "dylib", "bc"):
          for prefix in ("lib", ""):
            path = os.path.join(where, "{}{}.{}".format(prefix, name, ext))
            if os.path.exists(path):
              abs_path = path
              break
      if not os.path.exists(abs_path):
        print "Warning: cannot find object file: {}".format(name)
        abs_path = name
    super(StaticLibrary, self).__init__(abs_path)


class ConfigLibraries(object):
  """Set of libraries returned from a configuration command."""
  def __init__(self, *args):
    self.paths = subprocess.check_output(args).strip().split(" ")

  def Paths(self):
    return self.paths


class LinkerLibrary(object):
  """A library that the linker will figure out how to find."""
  def __init__(self, name, os=None):
    global OS
    self._name = name
    self._include = True
    if os and OS != os:
      self._include = False

  def Paths(self):
    paths = []
    if self._include:
      paths.append("-l{}".format(self._name))
    return paths


class _Target(_File):
  """Generic target that must be compiled."""
  def __init__(self, path, source_files=[], object_files=[], libraries=[]):
    global POOL
    path = os.path.abspath(path)
    MakeDirsForFile(path)
    super(_Target, self).__init__(FileName(Task(
      self._Build,
      path,
      source_files,
      object_files,
      libraries)))

  def _Build(self, path, source_files, object_files, libraries):
    args = [CXX]
    args.extend(CXX_FLAGS)
    args.extend(self.extra_args)

    for src in source_files:
      args.extend(src.Paths())

    args.extend([
      "-o",
      path,
      "-L{}".format(LIB_DIR)])

    if "linux" == OS:
      args.extend([
        "-Wl,-z,now",
        "-Wl,-rpath={}".format(LIB_DIR),
        "-Wl,-gc-sections"])

    elif "mac" == OS:
      args.extend([
        "-Xlinker", "-rpath", "-Xlinker", LIB_DIR,
        "-Wl,-dead_strip"])

    for obj in object_files:
      args.extend(obj.Paths())

    for lib in libraries:
      args.extend(lib.Paths())

    Command(*args)
    return path

  def Wait(self):
    [str(p) for p in self.Paths()]


class TargetExecutable(_Target):
  """Represents an individual binary executable file."""
  def __init__(self, *args, **kargs):
    self.extra_args = []
    super(TargetExecutable, self).__init__(*args, **kargs)

  def Execute(self, *args):
    Command(self.path, *args)


class TargetLibrary(_Target):
  """Shared library that must be compiled by the system."""
  def __init__(self, *args, **kargs):
    if "linux" == OS:
      self.extra_args = ["-shared"]
    elif "mac" == OS:
      self.extra_args = ["-dynamiclib"]
    super(TargetLibrary, self).__init__(*args, **kargs)


if "__main__" != __name__:
  exit(0)

if OS not in ("mac", "linux"):
  print "Unsupported platform: {}".format(OS)
  exit(1)

# Find all source code.
source_paths = [os.path.join(SRC_DIR, "Translate.cpp")]
source_paths.extend(list(
  glob.glob(os.path.join(SRC_DIR, "Arch", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(SRC_DIR, "Arch", "X86", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(SRC_DIR, "CFG", "*.cpp"))))
source_paths.extend(list(
  glob.glob(os.path.join(SRC_DIR, "BC", "*.cpp"))))

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
  LinkerLibrary("unwind", os="linux")]

# Find the LLVM libraries to link in.
libraries = [ConfigLibraries(
  os.path.join(BIN_DIR, "llvm-config"), "--libs")]
libraries.extend(system_libraries)

# Create a program that lifts a CFG protobuf file into 
cfg_to_bc = TargetExecutable(
  os.path.join(BUILD_DIR, "cfg_to_bc"),
  source_files=[SourceFile(f) for f in source_paths],
  object_files=object_files,
  libraries=libraries)

# Create an LLVM plugin for optimizing lifted bitcode files.
libOptimize = TargetLibrary(
  os.path.join(BUILD_DIR, "libOptimize.{}".format(SHARED_LIB_EXT)),
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
    os.path.join(BUILD_DIR, "gen_cfg_{}{}".format(arch, suffix)),
    source_files=[
      SourceFile(
        os.path.join(TEST_DIR, "X86", "Generate.cpp"),
        extra_args=macro_args),

      # The `Tests.S` file needs to be compiled with extra arguments
      # that enable Clang to assemble code with extra features.
      SourceFile(
        os.path.join(TEST_DIR, "X86", "Tests.S"),
        extra_args=macro_args+target_args+["-DIN_TEST_GENERATOR"]),
      
      SourceFile(os.path.join(SRC_DIR, "CFG", "CFG.cpp"))],
    object_files=object_files,
    libraries=libraries)

  # CFG protobuf that will describe the test cases.
  cfg_file = os.path.join(
    GEN_DIR, "tests", "cfg_{}{}".format(arch, suffix))

  # Lifted bitcode of the test cases.
  bc_file = os.path.join(
    GEN_DIR, "tests", "bc_{}{}".format(arch, suffix))

  MakeDirsForFile(cfg_file)

  # Generate a CFG protobuf for the test cases for this specific arch/config.
  gen_cfg.Execute("--cfg_out={}".format(cfg_file))
  
  # Lift the testcases to a bitcode file.
  cfg_to_bc.Execute(
    "--source_arch={}".format(arch),
    "--target_arch=amd64",
    "--cfg={}".format(cfg_file),
    "--bc_out={}.bc".format(bc_file))

  # Enable more bitcode optimizations.
  Command(
    os.path.join(BIN_DIR, "opt"),
    "-load", libOptimize,
    "-deferred_inliner",
    "-o={}.opt.bc".format(bc_file),
    "{}.bc".format(bc_file))

  # Build the test runner.
  run_tests = TargetExecutable(
    os.path.join(BUILD_DIR, "run_tests_{}{}".format(arch, suffix)),
    source_files=[
      SourceFile(
        "{}.opt.bc".format(bc_file),
        extra_args=["-O3"]),
      SourceFile(
        os.path.join(TEST_DIR, "X86", "Tests.S"),
        extra_args=macro_args+target_args),
      SourceFile(
        os.path.join(TEST_DIR, "X86", "Run.cpp"),
        extra_args=macro_args),
      SourceFile(
        os.path.join(SRC_DIR, "Arch", "Runtime", "Types.cpp"),
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
