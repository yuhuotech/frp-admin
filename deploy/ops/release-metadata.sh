#!/usr/bin/env bash
set -euo pipefail
umask 022

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$script_dir/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: release-metadata.sh --output-dir DIR ARTIFACT [ARTIFACT ...]

Generates SHA256SUMS and an SPDX JSON SBOM per artifact. Requires Syft. Artifact
basenames must be unique because release bundles are expected to have a flat layout.
EOF
  exit 2
}

output_dir=''
if [[ ${1:-} == --output-dir && -n ${2:-} ]]; then output_dir=$2; shift 2; else usage; fi
(($# > 0)) || usage
require_command openssl
require_command syft
[[ ! -e "$output_dir" ]] || die "output directory already exists"
install -d -m 0755 "$output_dir"

declare -A seen=()
for artifact in "$@"; do
  [[ -f "$artifact" && ! -L "$artifact" ]] || die "artifact is missing or unsafe: $artifact"
  name=$(basename "$artifact")
  [[ "$name" =~ ^[A-Za-z0-9._+-]+$ ]] || die "unsupported artifact basename: $name"
  [[ -z ${seen[$name]:-} ]] || die "duplicate artifact basename: $name"
  seen[$name]=1
  install -m 0644 "$artifact" "$output_dir/$name"
  syft scan "file:$artifact" -o "spdx-json=$output_dir/$name.spdx.json"
done
(
  cd "$output_dir"
  for name in *; do
    [[ -f "$name" ]] || continue
    printf '%s  %s\n' "$(sha256_file "$name")" "$name"
  done >SHA256SUMS
)
log "release metadata created: $output_dir/SHA256SUMS"
