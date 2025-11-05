# Remill Dependency Management

## Overview

Remill uses a CMake superbuild pattern for dependency management instead of traditional package managers like vcpkg or Conan. The superbuild system is located in the `dependencies/` directory.

## Why Superbuild?

The superbuild approach was chosen for several key reasons:

1. **Simplicity**: Automating dependency compilation is easier for users
2. **Reproducibility**: Pinned dependency versions ensure consistent builds across all environments
3. **Cross-Platform Consistency**: Same build process works on Linux, macOS, and Windows

## How It Works

The superbuild uses CMake's `ExternalProject` module to:

1. Download dependencies from source
2. Build them in the correct order (respecting inter-dependencies)
3. Install everything to a common prefix: `dependencies/install/` as proper CMake packages
4. The main project then uses this prefix via `CMAKE_PREFIX_PATH`

## Configuration Options

### Using External LLVM

The superbuild can use an externally-provided LLVM instead of building its own:

```bash
cmake -S dependencies -B dependencies/build -DUSE_EXTERNAL_LLVM=ON
```

This is particularly useful for:
- macOS users with Homebrew LLVM
- Linux distributions with packaged LLVM
- CI/CD systems with pre-installed LLVM

### Customizing Versions

To modify dependency versions, edit the corresponding `.cmake` file in `dependencies/`:
- `dependencies/llvm.cmake` - LLVM version and configuration
- `dependencies/xed.cmake` - Intel XED configuration
- Individual `simple_git()` calls for Google libraries
