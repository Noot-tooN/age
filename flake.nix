{
  description = "Local age-keygen with BIP39 paper recovery for native PQ identities";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = import nixpkgs { inherit system; };
      keygen = pkgs.callPackage ./nix/package.nix {};
    in {
      age-keygen-mnemonic = keygen;
      default = keygen;
    });

    checks = forAllSystems (system: {
      recovery = self.packages.${system}.age-keygen-mnemonic;
    });
  };
}
