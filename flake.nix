{
  description = "wharfix-web";

  inputs = {
    cargo2nix.url = "github:cargo2nix/cargo2nix";
    cargo2nix.inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
  };

  outputs = { self, cargo2nix, nixpkgs }:
  let
    pname = "wharfix-web";
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ self.overlay cargo2nix.overlays.default ];
    };
    lib = nixpkgs.lib;

    outputPackages = {
      "${pname}" = ["default"];
    };

    askama.workspacePatch = pks: name: pks.rustBuilder.rustLib.makeOverride {
      inherit name;
      overrideAttrs = oa: {
        postPatch = (oa.postPatch or "") + ''
          substituteInPlace ${name}/Cargo.toml --replace 'workspace = ".."' ""
        '';
      };
    };
  in {
    packages.${system} = lib.mapAttrs (n: _: pkgs.${n}) outputPackages;
    defaultPackage.${system} = pkgs.${pname};

    overlay = final: prev:
    let
      cratePackage = name: features:
        (final.rustBuilder.makePackageSet {
          rustVersion = final.rustc.version;
          packageFun = import ./Cargo.nix;
          rootFeatures = map (f: "${pname}/${f}") features;
          packageOverrides = pks: (let pf = askama.workspacePatch pks; in pks.rustBuilder.overrides.all ++ (map pf [
            "askama"
            "askama_actix"
            "askama_derive"
            "askama_escape"
          ]));
        }).workspace.${pname} {};
    in
      lib.mapAttrs cratePackage outputPackages;

    devShell.${system} = with pkgs; mkShell {
      buildInputs = [
        cargo
        cargo2nix.packages.${system}.cargo2nix
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
