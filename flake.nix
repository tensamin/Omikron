{
  description = "Omikron packages and development shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    type-maps = {
      url = "git+file:mtp-type-maps";
      flake = false;
    };
    tau-src = {
      url = "git+file:../tau";
      flake = false;
    };
    mtp-src = {
      url = "git+file:../mtp";
      flake = false;
    };
    iota-src = {
      url = "git+file:../iota";
      flake = false;
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      type-maps,
      tau-src,
      mtp-src,
      iota-src,
      ...
    }:
    let
      systems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      rustFor =
        pkgs:
        pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
          ];
        };
    in
    {
      lib.mkPackage =
        {
          rustPlatform,
          pkgs,
          source,
          cargoDeps,
          typeMaps,
        }:
        rustPlatform.buildRustPackage {
          pname = "omikron";
          version = "0.1.0";
          src = source;
          inherit cargoDeps;
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.perl
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.openssl
            pkgs.sqlite
          ];
          dontUseCmakeConfigure = true;
          MTP_TYPE_MAPS = "${typeMaps}/type-maps.yaml";
          doCheck = false;
          meta = {
            platforms = [
              "x86_64-linux"
              "aarch64-linux"
            ];
            mainProgram = "omikron";
          };
        };
      lib.mkContainer =
        {
          pkgs,
          package,
          revision,
        }:
        pkgs.dockerTools.buildLayeredImage {
          name = "tensamin/omikron";
          tag = revision;
          contents = [
            package
            pkgs.cacert
            pkgs.dockerTools.binSh
          ];
          config = {
            Entrypoint = [ "${package}/bin/omikron" ];
            WorkingDir = "/var/lib/omikron";
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
      packages = systems (
        system:
        let
          pkgs = pkgsFor system;
          rust = rustFor pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          source = pkgs.runCommand "omikron-source" { } ''
            cp -r ${self} "$out"
            chmod -R u+w "$out"
            rm -rf "$out/mtp-type-maps"
            cp -r ${type-maps} "$out/mtp-type-maps"
            substituteInPlace "$out/Cargo.toml" \
              --replace-fail 'path = "../tau"' 'path = "${tau-src}"' \
              --replace-fail 'path = "../iota/iota-opaque"' 'path = "${iota-src}/iota-opaque"' \
              --replace-fail 'path = "../mtp"' 'path = "${mtp-src}"' \
              --replace-fail 'path = "../mtp/bindings/native"' 'path = "${mtp-src}/bindings/native"' \
              --replace-fail 'path = "../mtp/type-map"' 'path = "${mtp-src}/type-map"' \
              --replace-fail 'path = "../mtp/crypto"' 'path = "${mtp-src}/crypto"'
          '';
        in
        {
          default = self.lib.mkPackage {
            inherit pkgs rustPlatform source;
            typeMaps = type-maps;
            cargoDeps = rustPlatform.fetchCargoVendor {
              pname = "omikron";
              version = "0.1.0";
              src = source;
              hash = "sha256-pEauls+utqsmPx27ENGTXs33iYEi8oOIKh5MAgDtlJA=";
            };
          };
          container = self.lib.mkContainer {
            inherit pkgs;
            package = self.packages.${system}.default;
            revision = self.shortRev or "local";
          };
        }
      );
      checks = systems (system: {
        inherit (self.packages.${system}) default;
      });
      devShells = systems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (rustFor pkgs)
              pkgs.git
              pkgs.cmake
              pkgs.perl
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.openssl
              pkgs.sqlite
            ];
            MTP_TYPE_MAPS = "${type-maps}/type-maps.yaml";
          };
        }
      );
    };
}
