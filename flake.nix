{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = inputs: inputs.flake-parts.lib.mkFlake { inherit inputs; } {
    systems = import inputs.systems;
    perSystem = { config, self', inputs', pkgs, system, ... }: let
      overlays = [ (import inputs.rust-overlay) ];
      pkgs = import inputs.nixpkgs {
        inherit system overlays;
      };
      rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
    in {
      _module.args.pkgs = import inputs.nixpkgs {
        config.allowUnfree = true;
      };
      devShells.default = pkgs.mkShell rec {
        buildInputs = [
          rustToolchain
          pkgs.pkgsCross.aarch64-multiplatform.buildPackages.binutils
          (pkgs.writeShellScriptBin "aarch64-linux-gnu-as" "aarch64-unknown-linux-gnu-as")
          (pkgs.writeShellScriptBin "aarch64-linux-gnu-ld" "aarch64-unknown-linux-gnu-ld")
          pkgs.ncurses5
          pkgs.ncurses6
        ];
        LD_LIBRARY_PATH = "${pkgs.lib.makeLibraryPath buildInputs}";
      };
    };
  };
}
