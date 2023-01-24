{
  description = "wharfix-web";

  inputs = {
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
  };

  outputs = { self, crane, nixpkgs }:
  let
    pname = "wharfix-web";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay crane-overlay ];
    };
    lib = nixpkgs.lib;
    crane-overlay = final: prev: {
      # crane's lib is not exposed as an overlay in its flake (should be added
      # upstream ideally) so this interface might be brittle, but avoids
      # accidentally passing a detached nixpkgs from its flake (or its follows)
      # on to consumers.
      craneLib = crane.mkLib prev;
    };

    outputPackages = {
      "${pname}" = [];
    };
  in {
    packages.${system} = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage.${system} = pkgs.${pname};

    overlay = final: prev:
    let
      cratePackage = name: features:
        (final.craneLib.buildPackage {
          src = with final; lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
            let
              templates = lib.hasInfix "/templates/" path;
              webroot = lib.hasInfix "/webroot/" path;
            in
              (craneLib.filterCargoSources path type) || webroot || templates;
          };
          nativeBuildInputs = with final; [
            pkg-config
          ];
          buildInputs = with final; [
            openssl
          ];
          cargoExtraArgs = final.lib.concatMapStringsSep " " (f: "--features=${f}") features;
        });
    in
      lib.mapAttrs cratePackage outputPackages;

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        nix
        openssl.dev
        pkgconfig
        rustc
        rustfmt
        zlib.dev
      ];
    };
  };
}
