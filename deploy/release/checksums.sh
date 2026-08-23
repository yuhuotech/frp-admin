#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 && -d "$1" ]] || {
  echo "usage: checksums.sh RELEASE_DIRECTORY" >&2
  exit 2
}

release_dir=$(cd "$1" && pwd)
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../ops/lib.sh
source "$script_dir/../ops/lib.sh"

tmp=$(mktemp "$release_dir/.SHA256SUMS.XXXXXX")
trap 'rm -f "$tmp"' EXIT
(
  cd "$release_dir"
  find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '.SHA256SUMS.*' -print \
    | sed 's#^./##' | LC_ALL=C sort \
    | while IFS= read -r name; do
        [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || die "unsupported release filename: $name"
        printf '%s  %s\n' "$(sha256_file "$name")" "$name"
      done
) >"$tmp"
mv "$tmp" "$release_dir/SHA256SUMS"
trap - EXIT
log "release checksums created: $release_dir/SHA256SUMS"
