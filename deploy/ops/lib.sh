#!/usr/bin/env bash

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '%s\n' "$*" >&2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

sha256_file() {
  openssl dgst -sha256 -r "$1" | awk '{print $1}'
}

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

require_private_file() {
  local path=$1 label=$2 mode
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file"
  mode=$(file_mode "$path")
  (( (8#$mode & 8#077) == 0 )) || die "$label permissions must not grant group or other access (found $mode)"
}

require_secure_parent() {
  local target=$1 label=$2 parent mode
  parent=$(dirname "$target")
  [[ -d "$parent" && ! -L "$parent" ]] || die "$label parent must be an existing non-symlink directory"
  mode=$(file_mode "$parent")
  (( (8#$mode & 8#022) == 0 )) || die "$label parent must not be group or other writable (found $mode)"
}

require_master_key() {
  require_private_file "$1" "$2"
  [[ $(wc -c <"$1" | tr -d ' ') == 32 ]] || die "$2 must contain exactly 32 bytes"
}

validate_key_version() {
  [[ "$1" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "invalid master key version: $1"
}

install_private() {
  local source=$1 target=$2
  install -d -m 0700 "$(dirname "$target")"
  install -m 0600 "$source" "$target"
}

verify_pki() {
  local dir=$1 cert_pub key_pub server_cert_pub server_key_pub
  require_command openssl
  [[ -d "$dir" && ! -L "$dir" ]] || die "PKI directory must be a directory and not a symlink"
  require_private_file "$dir/ca.key" "CA private key"
  require_private_file "$dir/server.key" "server private key"
  [[ -f "$dir/ca.crt" && ! -L "$dir/ca.crt" ]] || die "CA certificate is missing or unsafe"
  [[ -f "$dir/server.crt" && ! -L "$dir/server.crt" ]] || die "server certificate is missing or unsafe"

  cert_pub=$(openssl x509 -in "$dir/ca.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print $1}')
  key_pub=$(openssl pkey -in "$dir/ca.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || die "CA certificate and private key do not match"

  server_cert_pub=$(openssl x509 -in "$dir/server.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print $1}')
  server_key_pub=$(openssl pkey -in "$dir/server.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print $1}')
  [[ -n "$server_cert_pub" && "$server_cert_pub" == "$server_key_pub" ]] || die "server certificate and private key do not match"
  openssl verify -CAfile "$dir/ca.crt" "$dir/server.crt" >/dev/null || die "server certificate is not signed by the packaged CA"
}

verify_manifest() {
  local root=$1 manifest=$1/manifest.sha256 expected path actual
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "backup manifest is missing"
  while IFS=$'\t' read -r expected path; do
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "invalid checksum in manifest"
    [[ ( "$path" == metadata.env || "$path" =~ ^payload/[A-Za-z0-9._/-]+$ ) && "$path" != *'..'* ]] || die "unsafe path in manifest"
    [[ -f "$root/$path" && ! -L "$root/$path" ]] || die "manifest entry is missing or unsafe: $path"
    actual=$(sha256_file "$root/$path")
    [[ "$actual" == "$expected" ]] || die "checksum mismatch: $path"
  done <"$manifest"
}
