{
  description = "Omikron development and verification";

  inputs.prod-pins.url = "git+ssh://git@methanium.net/tensamin/prod-pins?ref=main";

  outputs = { self, prod-pins, ... }:
    let
      forSystems = prod-pins.inputs.nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      project = system: prod-pins.lib.mkPackages {
        inherit system;
        sources.omikron = self;
      };
    in {
      checks = forSystems (system: { inherit ((project system).packages) omikron; });
      devShells = forSystems (system: {
        default = (project system).devShells.omikron.overrideAttrs (old: {
          TENSAMIN_SOURCE = (project system).packages.omikron.transformedSource;
          shellHook = (old.shellHook or "") + ''
            # Stage authoritative dependencies without changing the checkout.
            export TENSAMIN_CHECKOUT="$PWD"
            workRoot="/tmp/tensamin-dev-$UID/$(basename "$TENSAMIN_SOURCE")"
            if [ ! -d "$workRoot" ]; then
              mkdir -p "$(dirname "$workRoot")"
              stage="$(mktemp -d "$workRoot.XXXXXX")"
              cp -R "$TENSAMIN_SOURCE/." "$stage/" &&
                chmod -R u+w "$stage" &&
                mv -T "$stage" "$workRoot" || exit 1
            fi
            cd "$workRoot"
          '';
        });
      });
    };
}
