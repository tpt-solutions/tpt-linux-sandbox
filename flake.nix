{
  # Untested on Nix so far: build with `nix build` and report any problems.
  description = "tpt-sandbox: run a command in a Linux sandbox (Landlock, seccomp, namespaces, cgroups)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "tpt-sandbox";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          cargoBuildFlags = [ "--package" "tpt-l-sandbox-cli" ];

          # The sandbox tests need unprivileged user namespaces, which the Nix
          # build sandbox does not provide. Run them with cargo test instead.
          doCheck = false;

          meta = {
            description = "Run a command inside a Linux sandbox (Landlock, seccomp, namespaces, cgroups)";
            homepage = "https://github.com/TPT-Solutions/tpt-linux-sandbox";
            license = with pkgs.lib.licenses; [ mit asl20 ];
            mainProgram = "tpt-sandbox";
            platforms = pkgs.lib.platforms.linux;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt pkgs.strace ];
        };
      });
}
