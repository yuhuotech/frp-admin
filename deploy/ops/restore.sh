#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$script_dir/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: restore.sh --archive FILE --master-key-target FILE --pki-target DIR [database options]

Database options:
  sqlite:   --sqlite-target FILE
  mysql:    --database NAME --mysql-defaults-file FILE
  postgres: --database NAME (uses PGHOST/PGPORT/PGUSER/PGPASSFILE/PGSSLMODE)

Optional: --keyring-target DIR. Targets and target databases must be empty.
EOF
  exit 2
}

archive=''
master_target=''
pki_target=''
keyring_target=''
sqlite_target=''
database=''
mysql_defaults=''
while (($#)); do
  case "$1" in
    --archive) archive=${2:-}; shift 2 ;;
    --master-key-target) master_target=${2:-}; shift 2 ;;
    --pki-target) pki_target=${2:-}; shift 2 ;;
    --keyring-target) keyring_target=${2:-}; shift 2 ;;
    --sqlite-target) sqlite_target=${2:-}; shift 2 ;;
    --database) database=${2:-}; shift 2 ;;
    --mysql-defaults-file) mysql_defaults=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ -f "$archive" && ! -L "$archive" && -n "$master_target" && -n "$pki_target" ]] || usage
[[ ! -e "$master_target" && ! -L "$master_target" ]] || die "master key target already exists or is a symlink"
[[ ! -e "$pki_target" && ! -L "$pki_target" ]] || die "PKI target already exists or is a symlink"
require_secure_parent "$master_target" "master key target"
require_secure_parent "$pki_target" "PKI target"
if [[ -n "$keyring_target" ]]; then
  [[ ! -e "$keyring_target" && ! -L "$keyring_target" ]] || die "keyring target already exists or is a symlink"
  require_secure_parent "$keyring_target" "keyring target"
fi
require_command openssl
require_command tar

[[ -f "$archive.sha256" && ! -L "$archive.sha256" ]] || die "archive sidecar checksum is required: $archive.sha256"
expected=$(tr -d '[:space:]' <"$archive.sha256")
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "invalid archive sidecar checksum"
[[ $(sha256_file "$archive") == "$expected" ]] || die "archive checksum mismatch"

work=$(mktemp -d "${TMPDIR:-/tmp}/frp-admin-restore.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
while IFS= read -r entry; do
  [[ "$entry" != /* && "$entry" != *'..'* ]] || die "archive contains an unsafe path"
done < <(tar -tf "$archive")
if tar -tvf "$archive" | awk 'substr($1,1,1) !~ /^[-d]$/ { unsafe=1 } END { exit !unsafe }'; then
  die "archive contains links, devices, or another unsupported entry type"
fi
tar -C "$work" -xf "$archive"
[[ -f "$work/metadata.env" && ! -L "$work/metadata.env" ]] || die "backup metadata is missing"
# metadata.env is parsed as data, never sourced.
format=$(awk -F= '$1=="FRP_ADMIN_BACKUP_FORMAT" {print $2}' "$work/metadata.env")
driver=$(awk -F= '$1=="FRP_ADMIN_BACKUP_DRIVER" {print $2}' "$work/metadata.env")
[[ "$format" == 1 && "$driver" =~ ^(sqlite|mysql|postgres)$ ]] || die "unsupported backup metadata"
verify_manifest "$work"
require_master_key "$work/payload/master-keys/master.key" "packaged master key"
verify_pki "$work/payload/pki"

case "$driver" in
  sqlite)
    [[ -n "$sqlite_target" && ! -e "$sqlite_target" && ! -L "$sqlite_target" ]] || die "--sqlite-target must point to a new non-symlink file"
    require_secure_parent "$sqlite_target" "SQLite target"
    require_command sqlite3
    sqlite3 "$work/payload/database/sqlite.db" ".backup '$sqlite_target'"
    chmod 0600 "$sqlite_target"
    [[ $(sqlite3 "$sqlite_target" 'PRAGMA integrity_check;') == ok ]] || die "restored SQLite database failed integrity_check"
    [[ $(sqlite3 "$sqlite_target" 'PRAGMA foreign_key_check;' | wc -l | tr -d ' ') == 0 ]] || die "restored SQLite database failed foreign_key_check"
    ;;
  mysql)
    [[ -n "$database" && "$database" =~ ^[A-Za-z0-9_$-]+$ ]] || die "--database contains unsupported characters"
    [[ -n "$mysql_defaults" ]] || die "--mysql-defaults-file is required"
    require_private_file "$mysql_defaults" "MySQL defaults file"
    require_command mysql
    [[ -z $(mysql --defaults-extra-file="$mysql_defaults" --batch --skip-column-names "$database" -e 'SHOW TABLES') ]] || die "MySQL target database is not empty"
    mysql --defaults-extra-file="$mysql_defaults" "$database" <"$work/payload/database/mysql.sql"
    ;;
  postgres)
    [[ -n "$database" ]] || die "--database is required"
    if [[ -n "${PGPASSFILE:-}" ]]; then require_private_file "$PGPASSFILE" "PostgreSQL password file"; fi
    require_command psql
    require_command pg_restore
    [[ $(psql --no-psqlrc --tuples-only --no-align --dbname="$database" -c "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')") == 0 ]] || die "PostgreSQL target database is not empty"
    pg_restore --exit-on-error --single-transaction --no-owner --no-acl --dbname="$database" "$work/payload/database/postgres.dump"
    ;;
esac

install_private "$work/payload/master-keys/master.key" "$master_target"
install -d -m 0700 "$pki_target"
for name in ca.crt ca.key server.crt server.key; do install_private "$work/payload/pki/$name" "$pki_target/$name"; done
if [[ -n "$keyring_target" ]]; then
  install -d -m 0700 "$keyring_target"
  while IFS= read -r key; do install_private "$key" "$keyring_target/$(basename "$key")"; done < <(find "$work/payload/master-keys" -type f ! -name master.key -print)
fi
log "restore completed; start the server with the restored database, master key, and PKI, then run smoke.sh"
