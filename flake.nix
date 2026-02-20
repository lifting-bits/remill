{
  description = "Remill - Static binary translator that lifts machine code to LLVM bitcode";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      forSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    in
    {
      packages = forSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          llvmPkgs = pkgs.llvmPackages_17;

          xed = llvmPkgs.stdenv.mkDerivation {
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
              cp ${./dependencies/XEDConfig.cmake.in} $out/lib/cmake/XED/XEDConfig.cmake
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
                (builtins.filter (f: nixpkgs.lib.hasSuffix ".patch" f)
                  (builtins.sort builtins.lessThan
                    (builtins.attrNames (builtins.readDir dir))));
          };

          remill = llvmPkgs.stdenv.mkDerivation {
            pname = "remill";
            version = "0-unstable-${self.shortRev or self.dirtyShortRev or "unknown"}";

            src = self;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.git
              pkgs.python3
            ];

            buildInputs = [
              llvmPkgs.llvm.dev
              llvmPkgs.llvm.lib
              xed
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
                  -resource-dir ${llvmPkgs.clang-unwrapped.lib}/lib/clang/17 \
                  "$@"
              ''}"
              #"-DREMILL_ENABLE_TESTING=OFF"
              "-DGIT_FAIL_IF_NONZERO_EXIT=FALSE"
            ];
          };
        in
        {
          default = remill;
          inherit xed remill;
        }
      );
    };
}
