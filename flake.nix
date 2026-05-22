{
  description = "Automated bootstrapping and configuration tool for deploying Talos Linux clusters";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    devenv.url = "github:cachix/devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
    go-overlay.url = "github:purpleclay/go-overlay";
    go-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-trusted-public-keys = ["devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw="];
    extra-substituters = ["https://devenv.cachix.org"];
  };

  outputs = {
    nixpkgs,
    devenv,
    systems,
    go-overlay,
    ...
  } @ inputs: let
    forEachSystem = nixpkgs.lib.genAttrs (import systems);
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [go-overlay.overlays.default];
      };
    perSystem = system: let
      pkgs = pkgsFor system;
      fs = pkgs.lib.fileset;
      # Pin Go to the version declared in go.mod.
      go = pkgs.go-bin.fromGoMod ./go.mod;
      src = fs.toSource {
        root = ./.;
        fileset = fs.unions [
          ./go.mod
          ./go.sum
          (fs.fileFilter (f: f.hasExt "go") ./cmd)
          (fs.fileFilter (f: f.hasExt "go") ./internal)
        ];
      };
      # When go.mod/go.sum change, `nix build` will fail with the expected
      # vendorHash in the error — copy that into the value below.
      bootstrap = (pkgs.buildGoModule.override {inherit go;}) {
        name = "talos-bootstrap";
        inherit src;

        vendorHash = "sha256-+01Bv6ZGUwxaeR0XFiKc6bta0DKNeHLZn5DkUsm+Qlo=";

        subPackages = ["cmd/bootstrap"];

        env.CGO_ENABLED = 0;
        ldflags = ["-s" "-w"];

        meta = {
          description = "Bootstrap tool for Talos Linux clusters";
          mainProgram = "bootstrap";
          license = pkgs.lib.licenses.mit;
        };
      };
    in {
      inherit pkgs go bootstrap;
    };
  in {
    packages = forEachSystem (system: {
      default = (perSystem system).bootstrap;
    });

    checks = forEachSystem (system: let
      s = perSystem system;
    in {
      # `nix flake check` runs the Go test suite by reusing the package's
      # source closure and adding the test dependencies. Linting is left to
      # `make lint` in the devshell because golangci-lint cannot run
      # hermetically without an extra dependency-vendoring step.
      test = s.bootstrap.overrideAttrs (_: {
        name = "talos-bootstrap-test";
        doCheck = true;
        subPackages = ["./..."];
      });
    });

    devShells = forEachSystem (system: let
      s = perSystem system;
    in {
      default = devenv.lib.mkShell {
        inherit inputs;
        pkgs = s.pkgs;
        modules = [
          {
            # https://devenv.sh/reference/options/
            # languages.go.enable also pulls in gopls (lsp.enable=true) and
            # delve (delve.enable=true), so we do not list them here.
            languages.go = {
              enable = true;
              package = s.go;
            };
            packages = with s.pkgs; [
              golangci-lint
              talosctl
            ];
            scripts.dev-bootstrap.exec = ''exec go run ./cmd/bootstrap "$@"'';
          }
        ];
      };
    });

    formatter = forEachSystem (system: (pkgsFor system).alejandra);
  };
}
