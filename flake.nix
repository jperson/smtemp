{
  description = "Rust v1.100.0 dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; config.allowUnfree = true; overlays = [ (import rust-overlay) ]; };
      in
      {
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.rust-bin.stable.latest.default
            pkgs.rust-analyzer
            pkgs.cargo-fuzz
            pkgs.jq
            pkgs.pi-coding-agent
            pkgs.claude-code
            pkgs.python3
            pkgs.openssl
          ];
          env = {
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1;
        };
      };
    });
}

