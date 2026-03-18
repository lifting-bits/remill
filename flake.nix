{
  description = "Remill - Static binary translator that lifts machine code to LLVM bitcode";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      forSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      llvmVersions = [ 15 16 17 18 19 20 21 ];
      defaultLLVM = 17;
    in
    {
      packages = forSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          xed = ver:
            let llvmPkgs = pkgs.${"llvmPackages_${toString ver}"};
            in llvmPkgs.stdenv.mkDerivation {
              pname = "xed";
              version = "2025.06.08";

              src = pkgs.fetchFromGitHub {
                owner = "intelxed";
                repo = "xed";
                rev = "v2025.06.08";
                hash = "sha256-FXVWCq7ykuSsVx8iB7WkFD7DDq6o/4bgsS0YJQWE+XM=";
              };

              mbuild = pkgs.fetchFromGitHub {
                owner = "intelxed";
                repo = "mbuild";
                rev = "v2024.11.04";
                hash = "sha256-iQVykBG3tEPxI1HmqBkvO1q+K8vi64qBfVC63/rcTOk=";
              };

              nativeBuildInputs = [ pkgs.python3 ];

              dontConfigure = true;

              postUnpack = "cp -r $mbuild mbuild";

              buildPhase = ''
                runHook preBuild
                patchShebangs .
                python3 mfile.py install \
                  --install-dir=$out \
                  --cc=$CC --cxx=$CXX \
                  --ar=$AR \
                  --compiler=clang \
                  --static \
                  --extra-ccflags=-fPIC \
                  --extra-cxxflags=-fPIC
                runHook postBuild
              '';

              installPhase = ''
                runHook preInstall
                mkdir -p $out/lib/cmake/XED
                cp ${./dependencies/XEDConfig.cmake.in} \
                  $out/lib/cmake/XED/XEDConfig.cmake
                runHook postInstall
              '';
            };

          sleighSrc = pkgs.fetchFromGitHub {
            owner = "lifting-bits";
            repo = "sleigh";
            rev = "7c6b742";
            hash = "sha256-Di/maGPXHPSM/EUVTgNRsu7nJ0Of+tVRu+B4wr9OoBE=";
          };

          ghidraSource = pkgs.applyPatches {
            src = pkgs.fetchFromGitHub {
              owner = "NationalSecurityAgency";
              repo = "ghidra";
              rev = "80ccdadeba79cd42fb0b85796b55952e0f79f323";
              hash = "sha256-7Iv1awZP5lU1LpGqC0nyiMxy0+3WOmM2NTdDYIzKmmk=";
            };
            patches =
              let dir = ./patches/sleigh;
              in map (f: dir + "/${f}")
                (builtins.filter (f: lib.hasSuffix ".patch" f)
                  (builtins.sort builtins.lessThan
                    (builtins.attrNames (builtins.readDir dir))));
          };

          mkRemill = ver:
            let
              llvmPkgs = pkgs.${"llvmPackages_${toString ver}"};
              majorStr = toString ver;
              # LLVM 16+ uses major-only version in resource dir (D125860)
              clangVersion =
                if lib.versionOlder llvmPkgs.release_version "16"
                then llvmPkgs.release_version
                else majorStr;
            in llvmPkgs.stdenv.mkDerivation {
              pname = "remill";
              version =
                "0-unstable-${self.shortRev or self.dirtyShortRev or "unknown"}";

              src = self;

              nativeBuildInputs = [
                pkgs.cmake
                pkgs.ninja
                pkgs.git
                pkgs.python3
                pkgs.python3Packages.tqdm
              ];

              buildInputs = [
                llvmPkgs.llvm.dev
                llvmPkgs.llvm.lib
                (xed ver)
                pkgs.glog
                pkgs.gflags
                pkgs.gtest
              ];

              cmakeFlags = [
                "-DFETCHCONTENT_SOURCE_DIR_SLEIGH=${sleighSrc}"
                "-DFETCHCONTENT_SOURCE_DIR_GHIDRASOURCE=${ghidraSource}"
                "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
                "-DCLANG_PATH:FILEPATH=${pkgs.writeShellScript "bc-clang" ''
                  exec ${llvmPkgs.clang-unwrapped}/bin/clang++ \
                    -resource-dir ${llvmPkgs.clang-unwrapped.lib}/lib/clang/${clangVersion} \
                    "$@"
                ''}"
                "-DGIT_FAIL_IF_NONZERO_EXIT=FALSE"
              ];

              doCheck = true;

              checkPhase = ''
                runHook preCheck
                ninja test_dependencies
                ctest --output-on-failure
                runHook postCheck
              '';
            };

          remillPackages = lib.listToAttrs (map (ver: {
            name = "remill-llvm${toString ver}";
            value = mkRemill ver;
          }) llvmVersions);
        in
        remillPackages // {
          default = remillPackages."remill-llvm${toString defaultLLVM}";
          xed = xed defaultLLVM;
        }
      );

      devShells = forSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          mkDevShell = ver:
            let
              llvmPkgs = pkgs.${"llvmPackages_${toString ver}"};
              majorStr = toString ver;
            in pkgs.mkShell {
              packages = [
                self.packages.${system}."remill-llvm${majorStr}"
                llvmPkgs.clang
                llvmPkgs.llvm
                pkgs.xxd
                pkgs.cmake
                pkgs.ninja
                pkgs.glog
                pkgs.gflags
                pkgs.gtest
                pkgs.python3
                pkgs.python3Packages.tqdm
              ];

              shellHook = ''
                echo "Remill development environment (LLVM ${majorStr})"
                echo "Available: remill-lift-${majorStr}, clang, llvm-*, xxd"
              '';
            };

          shells = lib.listToAttrs (map (ver: {
            name = "llvm${toString ver}";
            value = mkDevShell ver;
          }) llvmVersions);
        in
        shells // {
          default = shells."llvm${toString defaultLLVM}";
        }
      );
    };
}
