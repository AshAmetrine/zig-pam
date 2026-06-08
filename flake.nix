{
  description = "zig-pam flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    zig-overlay = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    zls-flake = {
      url = "github:zigtools/zls/0.16.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      zig-overlay,
      zls-flake,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs (builtins.attrNames zig-overlay.packages);
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };

          zig = zig-overlay.packages.${system}."0.16.0";
          zls = zls-flake.packages.${system}.zls;
        in
        {
          default = pkgs.mkShell {
            name = "zig-pam-devshell";
            packages = [
              zig
              zls
              pkgs.linux-pam
            ];
          };
        }
      );
    };
}
