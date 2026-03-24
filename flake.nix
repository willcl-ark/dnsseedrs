{
  description = "dnsseedrs - Bitcoin DNS seeder";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        dnsseedrs = pkgs.callPackage ./default.nix { };
      in
      {
        packages.default = dnsseedrs;
        devShells.default = pkgs.mkShell {
          inputsFrom = [ dnsseedrs ];
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.rust-analyzer (pkgs.python313.withPackages (ps: [ ps.plotly ])) ];
        };
      }
    )
    // {
      nixosModules.default = import ./nixos/module.nix;
      overlays.default = final: _prev: {
        dnsseedrs = final.callPackage ./default.nix { };
      };
    };
}
