{
  description = "Sentinel - Intrusion Detection System";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustup
            cargo
            rust-analyzer
            
            go
            gopls
            
            python311
            
            gcc
            pkg-config
            libpcap
            
            git
            
            cmake
            gnumake
          ];
          
          shellHook = ''
            echo "Sentinel Development Environment"
            echo "Rust: $(rustc --version)"
            echo "Go: $(go version)"
            echo "Python: $(python3 --version)"
            echo ""
            echo "Tools:"
            echo " - Rust: cargo, rustc, rust-analyzer"
            echo " - Go: go, gopls"
            echo " - Python: python3"
          '';
        };
      }
    );
}

