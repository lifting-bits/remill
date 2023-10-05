{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    sleigh.url = "github:lifting-bits/sleigh/will/nixify";
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    treefmt-nix,
    sleigh,
  }:
    {
      overlays.default = final: prev: {
        ghidra = with final;
          applyPatches {
            src = fetchFromGitHub {
              owner = "trail-of-forks";
              repo = "ghidra";
              rev = "6eb9ff14c2fea37986026cd4995984dba97f3952";
              sha256 = "sha256-pJrcr+F2rjeRDDyL/NDkb2zNp5S6Pa4cadKtvcXzgbM=";
            };
            patches = [
              (fetchpatch {
                url = "https://raw.githubusercontent.com/lifting-bits/sleigh/e1562dd87f27e9a7b8edb57082c910ed9c53f0cd/src/patches/HEAD/0001-Fix-UBSAN-errors-in-decompiler.patch";
                sha256 = "sha256-IowkVhcHw/F+pdve5tei7DMHO+UrV3c4nkS/F1lE4HU=";
              })
              (fetchpatch {
                url = "https://raw.githubusercontent.com/lifting-bits/sleigh/e1562dd87f27e9a7b8edb57082c910ed9c53f0cd/src/patches/HEAD/0002-Use-stroull-instead-of-stroul-to-parse-address-offse.patch";
                sha256 = "sha256-+rQ/a9VK0evnGGidFPLL/NnXoHn8AgTVHszeN1f8VGI=";
              })
            ];
          };

        remill = with final;
          pkgs.llvmPackages_16.stdenv.mkDerivation {
            name = "remill";
            src = ./.;
            nativeBuildInputs = [
              cmake
              ninja
              git
            ];
            buildInputs = [
              glibc_multi
              llvm_16
              llvmPackages_16.libclang
              llvmPackages_16.libcxx
              llvmPackages_16.libcxxClang
              llvmPackages_16.libcxxabi
              libxml2
              xed
              ghidra
              glog
              gflags
              gtest
              sleigh.packages.${system}.default
              z3
            ];
            cmakeFlags = [
              # https://github.com/NixOS/nixpkgs/pull/216273
              "-DFETCHCONTENT_SOURCE_DIR_GHIDRA-FORK=${ghidra}"
              #"-Dsleigh_RELEASE_TYPE=HEAD"
              #"-DFETCHCONTENT_SOURCE_DIR_SLEIGH=${sleigh}"
              # temporary workaround for a nix bug where it forgets to include the c++ libs
              "-DCMAKE_CXX_FLAGS='-I${lib.getDev pkgs.llvmPackages_16.libcxxabi}/include/c++/v1'"
              "-DCMAKE_BC_COMPILER=${pkgs.llvmPackages_16.clang}/bin/clang++"
              "-DREMILL_BUILD_SPARC32_RUNTIME=OFF"
              "-DGIT_FAIL_IF_NONZERO_EXIT=OFF"
            ];
          };
      };
    }
    // flake-utils.lib.eachDefaultSystem (
      system: let
        nixpkgs-patched = (import nixpkgs {inherit system;}).applyPatches {
          name = "nixpkgs-patched";
          src = nixpkgs;
          patches = [];
        };
        pkgs = import nixpkgs-patched {
          inherit system;
          overlays = [self.overlays.default];
        };
      in {
        packages.default = pkgs.remill;
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cmake
            ninja
            git
            clang-tools
          ];
          inputsFrom = with pkgs; [
            remill
          ];
        };
        formatter = treefmt-nix.lib.mkWrapper pkgs {
          projectRootFile = ".git/config";
          programs = {
            alejandra.enable = true;
            clang-format.enable = true;
          };
        };
      }
    );
}
