{
  description = "Combine keys from multiple SSH agents into a single agent socket";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "ssh-agent-mux";
            version = "0.2.0-resilient";

            src = self;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            # Fix SkEcdsaSha2NistP256 signature encoding in ssh-key 0.6.7.
            # The Encode impl only handles SkEd25519 SK trailer (flags + counter)
            # separately from the signature data, but SkEcdsaSha2NistP256 falls
            # through to the generic path which wraps everything in one string,
            # corrupting the signature.
            postConfigure = ''
              chmod -R +w /build/cargo-vendor-dir/ssh-key-0.6.7/
              substituteInPlace /build/cargo-vendor-dir/ssh-key-0.6.7/src/signature.rs \
                --replace-fail \
                  'if self.algorithm == Algorithm::SkEd25519 {' \
                  'if self.algorithm == Algorithm::SkEd25519 || self.algorithm == Algorithm::SkEcdsaSha2NistP256 {'
            '';

            nativeCheckInputs = [ pkgs.openssh ];

            meta = with pkgs.lib; {
              description = "Combine keys from multiple SSH agents into a single agent socket";
              homepage = "https://github.com/jemilsson/ssh-agent-mux";
              license = with licenses; [ asl20 bsd3 ];
              mainProgram = "ssh-agent-mux";
            };
          };
        }
      );
    };
}
