#!/usr/bin/env bash
set -euo pipefail

workspace=$(dirname "$(dirname "$(realpath "$0")")")

# Include untracked source files without capturing runtime data or build output.
snapshot() {
  SOURCE="$1" nix eval --impure --raw --expr '
    let source = builtins.getEnv "SOURCE";
    in builtins.path {
      path = builtins.toPath source;
      filter = path: type:
        let name = builtins.baseNameOf path;
        in if builtins.dirOf path == source then
          builtins.elem name [
            "Cargo.toml" "Cargo.lock" "build.rs" ".cargo" "src" "tests"
            "examples" "benches" "flake.nix" "flake.lock" "mtp-type-maps"
            "type-maps.yaml" "app_protection.rs" "LICENSE" "README.md"
          ]
        else !(builtins.elem name [ ".git" "target" ".direnv" "result" ]);
    }
  '
}

omikron_source=$(snapshot "$workspace/omikron")
maps_source=$(snapshot "$workspace/mtp-type-maps")

nix build "path:$omikron_source#default" \
  --override-input type-maps "path:$maps_source" \
  --no-write-lock-file "$@"
