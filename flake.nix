{
  description = "dnsseedrs - A DNS seed implementation in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, treefmt-nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            rustfmt.enable = true;
            nixpkgs-fmt.enable = true;
          };
        };

        buildInputs = with pkgs; [
          sqlite
          pkg-config
          openssl
        ] ++ lib.optionals stdenv.isDarwin [
          darwin.apple_sdk.frameworks.Security
          darwin.apple_sdk.frameworks.SystemConfiguration
        ];

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];

      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "dnsseedrs";
          version = "0.2.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          inherit buildInputs nativeBuildInputs;

          meta = with pkgs.lib; {
            description = "A DNS seed implementation in Rust";
            homepage = "https://github.com/achow101/dnsseedrs";
            license = licenses.mit;
            maintainers = [ "achow101" ];
          };
        };

        devShells.default = pkgs.mkShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs ++ (with pkgs; [
            cargo-watch
            cargo-edit
            cargo-audit
            rust-analyzer
          ]);

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };

        formatter = treefmtEval.config.build.wrapper;

        checks = {
          formatting = treefmtEval.config.build.check self;
        };
      });
}
