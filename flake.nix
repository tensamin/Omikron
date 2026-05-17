{
  description = "Omikron";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    ttp = {
      url = "git+https://git.methanium.net/Tensamin/TTP.git?rev=7e5d1953df8592a1feba0f390d205d0ef61a3119";
      flake = false;
    };
  };

  outputs = inputs@{ self, nixpkgs, flake-parts, rust-overlay, ttp, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = { self', pkgs, system, ... }:
        let
          rustPkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = rustPkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          };
        in
        {
          packages = {
            default = self'.packages.omikron;
            omikron = pkgs.rustPlatform.buildRustPackage {
              pname = "omikron";
              version = "0.1.0";
              src = ./.;
              cargoLock = {
                lockFile = ./Cargo.lock;
                allowBuiltinFetchGit = true;
              };
              nativeBuildInputs = with pkgs; [ cmake perl pkg-config ];
              buildInputs = with pkgs; [ openssl ];
              dontUseCmakeConfigure = true;
              preConfigure = ''
                if [ -d ../cargo-vendor-dir/ttp-core-0.1.0 ]; then
                  cp ${ttp}/ttp-codec.json ../cargo-vendor-dir/ttp-codec.json
                fi
              '';
            };
          };

          devShells.default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rustToolchain git cmake perl pkg-config ];
            buildInputs = with pkgs; [ openssl ];
          };
        };

      flake = {
        nixosModules.default = { config, pkgs, lib, ... }:
          let
            cfg = config.services.omikron;
            defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default or (throw "omikron: no pre-built package for system ${pkgs.stdenv.hostPlatform.system}");
          in
          {
            options.services.omikron = {
              enable = lib.mkEnableOption "Enabled the Omikron";

              dataDir = lib.mkOption {
                type = lib.types.str;
                default = "/var/lib/omikron";
                description = "Directory where the Omikron stores its data and reads certificates from.";
              };

              certFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to the SSL certificate file (cert.pem). Required if acmeCertDir is not set.";
              };

              keyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to the SSL private key file (key.pem). Required if acmeCertDir is not set.";
              };

              acmeCertDir = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Directory containing ACME certificates (fullchain.pem and key.pem). When set, the service will automatically convert the EC key to PKCS8 and copy both files into the dataDir/certs directory on startup.";
              };

              environmentFiles = lib.mkOption {
                type = lib.types.listOf lib.types.path;
                default = [ ];
                description = "Environment files to load for the Omikron service.";
              };

              openFirewall = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Whether to open the firewall for ports used by the Omikron.";
              };

              rhoPort = lib.mkOption {
                type = lib.types.port;
                default = 959;
                description = "Port the Omikron server listens on for incoming QUIC connections.";
              };

              ttpBind = lib.mkOption {
                type = lib.types.str;
                default = "0.0.0.0";
                description = "IP address to bind the TTP/QUIC server to.";
              };

              omegaHost = lib.mkOption {
                type = lib.types.str;
                default = "tensamin.net";
                description = "Hostname of the upstream Omega server.";
              };

              omegaPort = lib.mkOption {
                type = lib.types.port;
                default = 9187;
                description = "Port of the upstream Omega server.";
              };

              package = lib.mkOption {
                type = lib.types.package;
                default = defaultPackage;
                description = "The Omikron package to use.";
              };
            };

            config = lib.mkIf cfg.enable {
              assertions = [
                {
                  assertion = cfg.acmeCertDir != null || (cfg.certFile != null && cfg.keyFile != null);
                  message = "services.omikron: either acmeCertDir must be set, or both certFile and keyFile must be provided.";
                }
              ];

              users.users.omikron = {
                isSystemUser = true;
                group = "omikron";
                home = cfg.dataDir;
                createHome = true;
                description = "Omikron service user";
              };

              users.groups.omikron = { };

              systemd.services.omikron = {
                description = "Tensamin Omikron";
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                environment = {
                  RHO_PORT = toString cfg.rhoPort;
                  TTP_BIND = cfg.ttpBind;
                  OMEGA_HOST = cfg.omegaHost;
                  OMEGA_PORT = toString cfg.omegaPort;
                };

                serviceConfig = {
                  Type = "simple";
                  User = "omikron";
                  Group = "omikron";
                  WorkingDirectory = cfg.dataDir;
                  ExecStart = "${cfg.package}/bin/omikron";
                  Restart = "always";
                  RestartSec = "5s";

                  EnvironmentFile = cfg.environmentFiles;

                  AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
                  CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

                  ExecStartPre = [
                    ("+" + pkgs.writeShellScript "omikron-setup-certs" (if cfg.acmeCertDir != null then ''
                      mkdir -p ${cfg.dataDir}/certs
                      cp ${cfg.acmeCertDir}/fullchain.pem ${cfg.dataDir}/certs/cert.pem
                      ${pkgs.openssl}/bin/openssl pkcs8 -topk8 -nocrypt \
                        -in ${cfg.acmeCertDir}/key.pem \
                        -out ${cfg.dataDir}/certs/key.pem
                      chown -R omikron:omikron ${cfg.dataDir}
                    '' else ''
                      mkdir -p ${cfg.dataDir}/certs
                      ln -sf ${cfg.certFile} ${cfg.dataDir}/certs/cert.pem
                      ln -sf ${cfg.keyFile} ${cfg.dataDir}/certs/key.pem
                      chown -R omikron:omikron ${cfg.dataDir}
                    ''))
                  ];

                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  NoNewPrivileges = true;
                  ReadWritePaths = cfg.dataDir;
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                };
              };

              networking.firewall = lib.mkIf cfg.openFirewall {
                allowedTCPPorts = [ cfg.rhoPort ];
                allowedUDPPorts = [ cfg.rhoPort ];
              };
            };
          };
      };
    };
}
