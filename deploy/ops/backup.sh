#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$script_dir/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: backup.sh --driver sqlite|mysql|postgres --output FILE --master-key FILE --pki-dir DIR [database options]

Database options:
  sqlite:   --sqlite-path FILE
  mysql:    --database NAME --mysql-defaults-file FILE
  postgres: --database NAME (uses PGHOST/PGPORT/PGUSER/PGPASSFILE/PGSSLMODE)

Repeat --key-version VERSION=FILE for every historical key required to decrypt Secrets.
The output contains private keys and must be encrypted before off-host storage.
EOF
  exit 2
}

driver=''
output=''
master_key=''
pki_dir=''
sqlite_path=''
database=''
mysql_defaults=''
declare -a key_versions=()
while (($#)); do
  case "$1" in
    --driver) driver=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    --master-key) master_key=${2:-}; shift 2 ;;
    --pki-dir) pki_dir=${2:-}; shift 2 ;;
    --sqlite-path) sqlite_path=${2:-}; shift 2 ;;
    --database) database=${2:-}; shift 2 ;;
    --mysql-defaults-file) mysql_defaults=${2:-}; shift 2 ;;
    --key-version) key_versions+=("${2:-}"); shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ "$driver" =~ ^(sqlite|mysql|postgres)$ ]] || usage
[[ -n "$output" && -n "$master_key" && -n "$pki_dir" ]] || usage
[[ ! -e "$output" && ! -L "$output" && ! -e "$output.sha256" && ! -L "$output.sha256" ]] || die "output already exists or is a symlink"
require_secure_parent "$output" "backup output"
require_command openssl
require_command tar
require_master_key "$master_key" "master key"
verify_pki "$pki_dir"

work=$(mktemp -d "${TMPDIR:-/tmp}/frp-admin-backup.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
install -d -m 0700 "$work/payload/database" "$work/payload/master-keys" "$work/payload/pki"
install_private "$master_key" "$work/payload/master-keys/master.key"

if ((${#key_versions[@]})); then
  for entry in "${key_versions[@]}"; do
    [[ "$entry" == *=* ]] || die "--key-version must be VERSION=FILE"
    version=${entry%%=*}
    key_path=${entry#*=}
    validate_key_version "$version"
    require_master_key "$key_path" "master key version $version"
    install_private "$key_path" "$work/payload/master-keys/$version.key"
  done
fi

for name in ca.crt ca.key server.crt server.key; do
  install_private "$pki_dir/$name" "$work/payload/pki/$name"
done

case "$driver" in
  sqlite)
    [[ -n "$sqlite_path" && -f "$sqlite_path" && ! -L "$sqlite_path" ]] || die "--sqlite-path must be a regular non-symlink database file"
    require_command sqlite3
    sqlite3 "$sqlite_path" '.timeout 10000' 'PRAGMA wal_checkpoint(PASSIVE);' >/dev/null
    sqlite3 "$sqlite_path" '.timeout 10000' ".backup '$work/payload/database/sqlite.db'"
    [[ $(sqlite3 "$work/payload/database/sqlite.db" 'PRAGMA integrity_check;') == ok ]] || die "SQLite backup failed integrity_check"
    [[ $(sqlite3 "$work/payload/database/sqlite.db" 'PRAGMA foreign_key_check;' | wc -l | tr -d ' ') == 0 ]] || die "SQLite backup failed foreign_key_check"
    ;;
  mysql)
    [[ -n "$database" && "$database" =~ ^[A-Za-z0-9_$-]+$ ]] || die "--database contains unsupported characters"
    [[ -n "$mysql_defaults" ]] || die "--mysql-defaults-file is required"
    require_private_file "$mysql_defaults" "MySQL defaults file"
    require_command mysqldump
    mysqldump --defaults-extra-file="$mysql_defaults" --single-transaction --quick --routines --events --triggers --hex-blob --no-tablespaces --set-gtid-purged=OFF "$database" >"$work/payload/database/mysql.sql"
    ;;
  postgres)
    [[ -n "$database" ]] || die "--database is required"
    if [[ -n "${PGPASSFILE:-}" ]]; then require_private_file "$PGPASSFILE" "PostgreSQL password file"; fi
    require_command pg_dump
    pg_dump --format=custom --compress=6 --no-owner --no-acl --dbname="$database" --file="$work/payload/database/postgres.dump"
    ;;
esac

# Key material is copied before the database snapshot. Reject the backup if any
# source key changes while the database is being captured.
[[ $(sha256_file "$master_key") == "$(sha256_file "$work/payload/master-keys/master.key")" ]] || die "master key changed during backup"
for name in ca.crt ca.key server.crt server.key; do
  [[ $(sha256_file "$pki_dir/$name") == "$(sha256_file "$work/payload/pki/$name")" ]] || die "PKI changed during backup: $name"
done
if ((${#key_versions[@]})); then
  for entry in "${key_versions[@]}"; do
    version=${entry%%=*}
    key_path=${entry#*=}
    [[ $(sha256_file "$key_path") == "$(sha256_file "$work/payload/master-keys/$version.key")" ]] || die "master key version changed during backup: $version"
  done
fi

created=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
cat >"$work/metadata.env" <<EOF
FRP_ADMIN_BACKUP_FORMAT=1
FRP_ADMIN_BACKUP_DRIVER=$driver
FRP_ADMIN_BACKUP_CREATED_AT=$created
EOF
(
  cd "$work"
  { printf '%s\n' metadata.env; find payload -type f -print; } | LC_ALL=C sort | while IFS= read -r path; do
    printf '%s\t%s\n' "$(sha256_file "$path")" "$path"
  done >manifest.sha256
)
tar -C "$work" -cf "$output" metadata.env manifest.sha256 payload
chmod 0600 "$output"
sha256_file "$output" >"$output.sha256"
chmod 0600 "$output.sha256"
log "backup created: $output"
log "encrypt the archive before copying it off-host; the archive contains private key material"
