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

            # Patch ssh-key 0.6.7 to:
            #   1. Encode SkEcdsaSha2NistP256 signatures with the SK trailer
            #      (flags + counter) separated from the signature data, like
            #      SkEd25519. The generic path wraps the whole lot in one
            #      length-prefixed string, corrupting the signature.
            #   2. Accept legacy ssh-rsa signatures (Algorithm::Rsa
            #      { hash: None }) during decode. gpg-agent emits these when
            #      the sign request has flags=0, e.g. from pam_ssh_agent_auth.
            #      Upstream deliberately rejects them as a length error,
            #      breaking sudo -> YubiKey via the mux.
            postConfigure = ''
              chmod -R +w /build/cargo-vendor-dir/ssh-key-0.6.7/
              substituteInPlace /build/cargo-vendor-dir/ssh-key-0.6.7/src/signature.rs \
                --replace-fail \
                  'if self.algorithm == Algorithm::SkEd25519 {' \
                  'if self.algorithm == Algorithm::SkEd25519 || self.algorithm == Algorithm::SkEcdsaSha2NistP256 {'
              substituteInPlace /build/cargo-vendor-dir/ssh-key-0.6.7/src/signature.rs \
                --replace-fail \
                  'Algorithm::Rsa { hash: Some(_) } => (),' \
                  'Algorithm::Rsa { .. } => (),'
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
