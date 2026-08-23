#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

for command in openssl sqlite3 tar; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing test dependency: %s\n' "$command" >&2; exit 1; }
done

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/frp-admin-ops-test.XXXXXXXX")
cleanup() { rm -rf -- "$test_dir"; }
trap cleanup EXIT INT TERM
install -d -m 0700 "$test_dir/source/pki" "$test_dir/restore" "$test_dir/links"
openssl rand -out "$test_dir/source/master.key" 32
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$test_dir/source/pki/ca.key" >/dev/null 2>&1
openssl req -x509 -new -key "$test_dir/source/pki/ca.key" -sha256 -days 2 \
  -subj '/CN=frp-admin ops test CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature' -out "$test_dir/source/pki/ca.crt" >/dev/null 2>&1
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$test_dir/source/pki/server.key" >/dev/null 2>&1
openssl req -new -key "$test_dir/source/pki/server.key" -subj '/CN=frp-admin-server' -out "$test_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:localhost' >"$test_dir/server.ext"
openssl x509 -req -in "$test_dir/server.csr" -CA "$test_dir/source/pki/ca.crt" \
  -CAkey "$test_dir/source/pki/ca.key" -CAcreateserial -days 2 -sha256 \
  -extfile "$test_dir/server.ext" -out "$test_dir/source/pki/server.crt" >/dev/null 2>&1
chmod 0600 "$test_dir/source/master.key" "$test_dir/source/pki/"*
sqlite3 "$test_dir/source/control.db" \
  'PRAGMA journal_mode=WAL; CREATE TABLE probe(id INTEGER PRIMARY KEY, marker TEXT NOT NULL); INSERT INTO probe(marker) VALUES ("restorable");' >/dev/null
chmod 0600 "$test_dir/source/control.db"

ln -s missing-target "$test_dir/links/dangling-backup.tar"
if "$script_dir/backup.sh" --driver sqlite --sqlite-path "$test_dir/source/control.db" \
  --master-key "$test_dir/source/master.key" --pki-dir "$test_dir/source/pki" \
  --output "$test_dir/links/dangling-backup.tar" >/dev/null 2>&1; then
  printf 'backup accepted a dangling output symlink\n' >&2
  exit 1
fi

ln -s missing-target "$test_dir/links/dangling-sidecar.tar.sha256"
if "$script_dir/backup.sh" --driver sqlite --sqlite-path "$test_dir/source/control.db" \
  --master-key "$test_dir/source/master.key" --pki-dir "$test_dir/source/pki" \
  --output "$test_dir/links/dangling-sidecar.tar" >/dev/null 2>&1; then
  printf 'backup accepted a dangling checksum sidecar symlink\n' >&2
  exit 1
fi

"$script_dir/backup.sh" --driver sqlite --sqlite-path "$test_dir/source/control.db" \
  --master-key "$test_dir/source/master.key" --pki-dir "$test_dir/source/pki" \
  --output "$test_dir/backup.tar" >/dev/null

ln -s missing-target "$test_dir/links/dangling-master.key"
if "$script_dir/restore.sh" --archive "$test_dir/backup.tar" \
  --sqlite-target "$test_dir/links/rejected.db" --master-key-target "$test_dir/links/dangling-master.key" \
  --pki-target "$test_dir/links/rejected-pki" >/dev/null 2>&1; then
  printf 'restore accepted a dangling master key symlink\n' >&2
  exit 1
fi

ln -s missing-target "$test_dir/links/dangling-pki"
if "$script_dir/restore.sh" --archive "$test_dir/backup.tar" \
  --sqlite-target "$test_dir/links/rejected.db" --master-key-target "$test_dir/links/rejected.key" \
  --pki-target "$test_dir/links/dangling-pki" >/dev/null 2>&1; then
  printf 'restore accepted a dangling PKI symlink\n' >&2
  exit 1
fi

ln -s missing-target "$test_dir/links/dangling-keyring"
if "$script_dir/restore.sh" --archive "$test_dir/backup.tar" \
  --sqlite-target "$test_dir/links/rejected.db" --master-key-target "$test_dir/links/rejected.key" \
  --pki-target "$test_dir/links/rejected-pki" --keyring-target "$test_dir/links/dangling-keyring" >/dev/null 2>&1; then
  printf 'restore accepted a dangling keyring symlink\n' >&2
  exit 1
fi

ln -s missing-target "$test_dir/links/dangling.db"
if "$script_dir/restore.sh" --archive "$test_dir/backup.tar" \
  --sqlite-target "$test_dir/links/dangling.db" --master-key-target "$test_dir/links/rejected.key" \
  --pki-target "$test_dir/links/rejected-pki" >/dev/null 2>&1; then
  printf 'restore accepted a dangling SQLite symlink\n' >&2
  exit 1
fi

"$script_dir/restore.sh" --archive "$test_dir/backup.tar" \
  --sqlite-target "$test_dir/restore/control.db" --master-key-target "$test_dir/restore/master.key" \
  --pki-target "$test_dir/restore/pki" >/dev/null
[[ $(sqlite3 "$test_dir/restore/control.db" 'PRAGMA integrity_check;') == ok ]]
[[ $(sqlite3 "$test_dir/restore/control.db" 'SELECT marker FROM probe;') == restorable ]]
[[ $(openssl dgst -sha256 -r "$test_dir/source/master.key" | awk '{print $1}') == \
   "$(openssl dgst -sha256 -r "$test_dir/restore/master.key" | awk '{print $1}')" ]]
repo_root=$(cd "$script_dir/../.." && pwd)
(
  cd "$repo_root/server"
  FRP_ADMIN_RESTORE_E2E=1 go test ./internal/app -run '^TestKeyRingBackupRestoreMaterialization$' -count=1
)
printf 'ops backup/restore tests passed\n'
