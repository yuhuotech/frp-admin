#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$script_dir/lib.sh"

[[ $# == 1 && -d "$1" ]] || die "usage: verify-release.sh RELEASE_DIRECTORY"
release_dir=$1
[[ -f "$release_dir/SHA256SUMS" && ! -L "$release_dir/SHA256SUMS" ]] || die "SHA256SUMS is missing"
while read -r expected name extra; do
  [[ -z ${extra:-} && "$expected" =~ ^[0-9a-f]{64}$ && "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || die "invalid SHA256SUMS entry"
  [[ -f "$release_dir/$name" && ! -L "$release_dir/$name" ]] || die "release file is missing or unsafe: $name"
  [[ $(sha256_file "$release_dir/$name") == "$expected" ]] || die "checksum mismatch: $name"
done <"$release_dir/SHA256SUMS"
log "release checksums verified"
