{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    gitignore = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:hercules-ci/gitignore.nix";
    };
  };

  outputs = { nixpkgs, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      perSystem = {config, self', inputs', pkgs, system, ...}:
        with rec {
          inherit (pkgs) lib;
          clean-source = src: inputs.gitignore.lib.gitignoreSource (lib.cleanSource src);
        }; {
          packages = {
            default = pkgs.stdenv.mkDerivation (self: {
              name = "trojan";
              src = clean-source ./.;
              nativeBuildInputs = [
                pkgs.cmake
                # tests:
                pkgs.curl
                pkgs.netcat
                pkgs.python3
              ];
              env = lib.optionalAttrs self.enableMysql {
                NIX_CFLAGS_COMPILE = "-L${pkgs.libmysqlclient}/lib/mariadb";
              };
              buildInputs = with pkgs; [ boost openssl ] ++
                                       lib.optionals self.enableMysql [ libmysqlclient ];
              enableMysql = true;
              cmakeFlags = [
                "-DDEFAULT_CONFIG=config.json"
                "-DENABLE_MYSQL=${if self.enableMysql then "ON" else "OFF"}"
                # Options that I found in their CI config but didn’t care to enable just yet
                # "-DBoost_USE_STATIC_LIBS=ON"
                # -DFORCE_TCP_FASTOPEN=ON
              ] ++ lib.optionals self.enableMysql [
                "-DMYSQL_INCLUDE_DIR=${lib.getDev pkgs.libmysqlclient}/include/mariadb"
              ];
              doCheck = true;
            });
            nomysql = self'.packages.default.overrideAttrs (_: {
              enableMysql = false;
            });
          };
        };
      systems = [ "x86_64-linux" "aarch64-linux" ];
    };
}
