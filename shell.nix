with import <nixpkgs> {};

clangStdenv.mkDerivation rec {
  name = "quickrun";
  buildInputs = [ unicorn pkg-config ];
}
