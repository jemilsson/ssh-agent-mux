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
