{ lib, buildGoModule }:
buildGoModule {
  pname = "age-keygen-mnemonic";
  version = "0.1.0-local";

  src = lib.cleanSource ../.;
  vendorHash = "sha256-cNh9U7OjoxewskX/+Ezln+U7p44g2h+Zx1dVKAaK6Ww=";
  subPackages = [ "cmd/age-keygen" ];

  # Run the codec and CLI recovery tests, not just compilation.
  checkPhase = ''
    runHook preCheck
    go test ./internal/bip39 ./cmd/age-keygen
    runHook postCheck
  '';

  ldflags = [ "-s" "-w" "-X main.Version=0.1.0-local-mnemonic" ];
  postInstall = ''
    mv "$out/bin/age-keygen" "$out/bin/age-keygen-mnemonic"
  '';

  meta = {
    description = "Local age PQ key generator with 24-word paper recovery";
    license = with lib.licenses; [ bsd3 mit ];
    mainProgram = "age-keygen-mnemonic";
    platforms = lib.platforms.unix;
  };
}
