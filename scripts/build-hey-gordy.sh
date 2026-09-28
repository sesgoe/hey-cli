#!/usr/bin/env bash
# Build the restricted hey-gordy binary for a Linux host (see internal/cmd/restricted.go),
# and the full hey CLI beside it, which is only ever used to sign in on that host.
#
#   scripts/build-hey-gordy.sh            # linux/amd64 -> bin/hey-gordy-linux-amd64, bin/hey-linux-amd64
#   GOARCH=arm64 scripts/build-hey-gordy.sh
set -euo pipefail

cd "$(dirname "$0")/.."

goarch="${GOARCH:-amd64}"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo none)"

go test ./internal/cmd -run 'Restricted|SplitCommandLine' -count=1

mkdir -p bin
build() {
  local package="$1" out="$2"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w \
      -X github.com/basecamp/hey-cli/internal/version.Version=gordy-${commit} \
      -X github.com/basecamp/hey-cli/internal/version.Commit=${commit} \
      -X github.com/basecamp/hey-cli/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o "$out" "$package"
  (cd bin && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
  echo "built $out"
}

build ./cmd/hey-gordy "bin/hey-gordy-linux-${goarch}"
build ./cmd/hey "bin/hey-linux-${goarch}"
cat bin/*-linux-"${goarch}".sha256
