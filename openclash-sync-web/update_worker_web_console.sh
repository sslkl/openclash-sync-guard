#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

converter_runtime_ok(){
  # Immutable dependencies are published separately, before the app transaction.
  # Read literal pins only: never execute source as root during preflight.
  python3 -I -B - "$1" "$2" <<'PY_CONVERTER_RUNTIME'
import ast, hashlib, os, pathlib, re, stat, sys
assert sys.version_info >= (3, 11)
def literal(path, key):
    values = [node.value for node in ast.parse(pathlib.Path(path).read_bytes()).body
              if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == key for t in node.targets)]
    assert len(values) == 1 and isinstance(values[0], ast.Constant) and isinstance(values[0].value, str)
    value = values[0].value
    assert re.fullmatch(r'[0-9a-f]{64}', value)
    return value
expected = literal(sys.argv[1], 'CONVERTER_RUNTIME_ID')
assert literal(sys.argv[2], 'CONVERTER_RUNTIME_ID') == expected
sandbox_sha = literal(sys.argv[2], 'CONVERTER_SANDBOX_SHA256')
root = pathlib.Path('/opt/openclash-sync-converter') / expected
current = root
while True:
    info = current.lstat()
    assert stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0) and not info.st_mode & 0o022
    assert info.st_mode & 0o001, "converter runtime is not service-user traversable"
    if current.parent == current: break
    current = current.parent
files = {'subscription_converter.py', 'converter_apply.py', 'converter_engine.py', 'converter_fetch.py',
         'converter_formats.py', 'converter_mellow.py', 'converter_services.py', 'converter_sandbox.py', 'converter_surge.py',
         'static/converter.js', 'static/converter_apply.js', 'static/converter_services.js'}
seen = set()
for directory, dirs, names in os.walk(root, followlinks=False):
    path = pathlib.Path(directory); info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0) and stat.S_IMODE(info.st_mode) == 0o555
    assert all((path / name).relative_to(root).as_posix() == 'static' for name in dirs)
    seen.update((path / name).relative_to(root).as_posix() for name in names)
assert seen == files | {'SHA256SUMS'}
manifest = []
for name in sorted(files) + ['SHA256SUMS']:
    path = root / name; info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0) and info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) == 0o444 and 1 <= info.st_size <= 2 * 1024 * 1024
    body = path.read_bytes(); digest = hashlib.sha256(body).hexdigest()
    if name == 'SHA256SUMS':
        assert body == ''.join(manifest).encode() and digest == expected
    else:
        manifest.append(f'{digest}  {name}\n')
        if name.endswith('.py'): ast.parse(body, filename=name)
        if name == 'converter_sandbox.py': assert digest == sandbox_sha
PY_CONVERTER_RUNTIME
}

failure_reason=UNSPECIFIED
hold(){ failure_reason=$1; printf 'WORKER_WEB_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
valid_digest(){
  case "$1" in *[!0-9a-f]*|'') return 1;; esac
  [ "${#1}" -eq 64 ]
}
sha(){
  sha_output=$(sha256sum "$1") || return 1
  sha_digest=${sha_output%% *}
  valid_digest "$sha_digest" || return 1
  printf '%s' "$sha_digest"
}
fsync_file(){
  python3 -I -B -c 'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)' "$1"
}
fsync_directory(){
  python3 -I -B -c 'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)' "$1"
}
fsync_path(){ fsync_file "$1" && fsync_directory "${1%/*}"; }
directory_chain_ok(){
  chain=$1
  while :; do
    [ -d "$chain" ] && [ ! -L "$chain" ] || return 1
    [ "$(stat -c '%u:%g' "$chain" 2>/dev/null)" = '0:0' ] || return 1
    if find "$chain" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q .; then
      find "$chain" -maxdepth 0 -perm -1000 | grep -q . || return 1
    fi
    [ "$chain" = / ] && return 0
    parent=${chain%/*}; [ -n "$parent" ] || parent=/; chain=$parent
  done
}
trusted_directory(){
  [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%g' "$1" 2>/dev/null)" = '0:0' ] || return 1
  find "$1" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && return 1
  directory_chain_ok "$1"
}
installed_file_ok(){
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c '%a:%u:%g:%h' "$1" 2>/dev/null)" = "$2:$3:$4:1" ] || return 1
  directory_chain_ok "${1%/*}"
}
shared_vendor_ok(){
  vendor_files='LICENSE SOURCE.json yaml/__init__.py yaml/composer.py yaml/constructor.py yaml/cyaml.py yaml/dumper.py yaml/emitter.py yaml/error.py yaml/events.py yaml/loader.py yaml/nodes.py yaml/parser.py yaml/reader.py yaml/representer.py yaml/resolver.py yaml/scanner.py yaml/serializer.py yaml/tokens.py'
  [ -d "$shared_vendor" ] && [ ! -L "$shared_vendor" ] && [ -d "$shared_vendor/yaml" ] && [ ! -L "$shared_vendor/yaml" ] || return 1
  [ "$(find "$shared_vendor" -type f | wc -l | tr -d ' ')" -eq 19 ] &&
    [ "$(find "$shared_vendor" -type d | wc -l | tr -d ' ')" -eq 2 ] &&
    [ "$(find "$shared_vendor" -type l | wc -l | tr -d ' ')" -eq 0 ] &&
    [ "$(find "$shared_vendor" ! -type f ! -type d | wc -l | tr -d ' ')" -eq 0 ] || return 1
  for directory in "$shared_vendor" "$shared_vendor/yaml"; do
    [ "$(stat -c '%a:%u:%g' "$directory" 2>/dev/null)" = '555:0:0' ] && directory_chain_ok "$directory" || return 1
  done
  for file in $vendor_files; do installed_file_ok "$shared_vendor/$file" 444 0 0 || return 1; done
  python3 -I -B - "$shared_vendor" <<'PY_SHARED_VENDOR'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve(strict=True)
metadata = json.loads((root / "SOURCE.json").read_text(encoding="utf-8"))
assert metadata.get("version") == "6.0.2"
assert metadata.get("source_sha256") == "d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e"
sys.path.insert(0, str(root))
import yaml
assert yaml.__version__ == "6.0.2"
assert root in pathlib.Path(yaml.__file__).resolve(strict=True).parents
PY_SHARED_VENDOR
}
service_listen_address(){
  listen_host=$(sed -n 's/^Environment=OPENCLASH_WEB_HOST=//p' "$service") || return 1
  listen_port=$(sed -n 's/^Environment=OPENCLASH_WEB_PORT=//p' "$service") || return 1
  [ "$(printf '%s\n' "$listen_host" | wc -l | tr -d ' ')" -eq 1 ] &&
    [ "$(printf '%s\n' "$listen_port" | wc -l | tr -d ' ')" -eq 1 ] || return 1
  listen_address=$listen_host:$listen_port
  case "$listen_address" in 127.0.0.1:8088|192.0.2.20:8088) printf '%s' "$listen_address";; *) return 1;; esac
}
health_ok(){
  health_address=$(service_listen_address) || return 1
  systemctl is-enabled --quiet openclash-sync-web.service &&
  systemctl is-active --quiet openclash-sync-web.service &&
  python3 -I -B - "$health_address" <<'PY_HEALTH' 2>/dev/null
import json, sys
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(f"http://{sys.argv[1]}/healthz", timeout=3) as response:
    assert response.status == 200 and json.load(response) == {"ok": True}
PY_HEALTH
}
service_listen_ok(){
  expected_listen=$(service_listen_address) || return 1
  ss -ltn | awk 'NR>1 {print $4}' | grep -qx "$expected_listen"
}
acquire_lifecycle_lock(){
  lifecycle_lock=/run/lock/openclash-sync-web.lifecycle.lock
  command -v flock >/dev/null 2>&1 || return 1
  python3 -I -B - "$lifecycle_lock" <<'PY_LOCK'
import os, stat, sys
path = sys.argv[1]
for directory in ("/run", "/run/lock"):
    info = os.lstat(directory)
    writable = info.st_mode & 0o022
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or \
            (writable and not info.st_mode & stat.S_ISVTX):
        raise OSError("untrusted lifecycle lock directory")
dirfd = os.open("/run/lock", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
created = False
try:
    try:
        fd = os.open(os.path.basename(path), os.O_RDWR | os.O_NOFOLLOW, dir_fd=dirfd)
    except FileNotFoundError:
        try:
            fd = os.open(os.path.basename(path), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
            created = True
        except FileExistsError:
            fd = os.open(os.path.basename(path), os.O_RDWR | os.O_NOFOLLOW, dir_fd=dirfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError("untrusted lifecycle lock file")
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        os.fsync(dirfd)
finally:
    os.close(dirfd)
PY_LOCK
  lock_identity=$(stat -Lc '%d:%i:%a:%u:%g' "$lifecycle_lock") || return 1
  exec 9<>"$lifecycle_lock"
  [ "$(stat -Lc '%d:%i:%a:%u:%g' "/proc/$$/fd/9" 2>/dev/null)" = "$lock_identity" ] || return 1
  flock -n 9
}
ensure_lifecycle_root(){
  lifecycle_root=/opt/openclash-sync-web-lifecycle
  if [ ! -e "$lifecycle_root" ] && [ ! -L "$lifecycle_root" ]; then
    install -d -m 0700 -o root -g root "$lifecycle_root" || return 1
    fsync_directory /opt || return 1
  fi
  [ -d "$lifecycle_root" ] && [ ! -L "$lifecycle_root" ] &&
    [ "$(stat -c '%a:%u:%g' "$lifecycle_root" 2>/dev/null)" = '700:0:0' ] || return 1
}
atomic_journal(){
  target=$1; payload=$2; parent=${target%/*}; name=${target##*/}
  partial=$parent/.$name.partial
  if [ -e "$partial" ] || [ -L "$partial" ]; then journal_file_ok "$partial" || return 1; rm -f "$partial" || return 1; fsync_directory "$parent" || return 1; fi
  (umask 077; set -C; : >"$partial") 2>/dev/null || return 1
  if ! printf '%b\n' "$payload" >"$partial" || ! chmod 0600 "$partial" || ! fsync_file "$partial"; then
    rm -f "$partial"; return 1
  fi
  mv -f "$partial" "$target" || { rm -f "$partial"; return 1; }
  fsync_directory "$parent" || return 1
}
journal_status(){
  tx=$1; status=$2
  for existing_status in ABORTED ROLLED_BACK ROLLBACK_FAILED RECOVERY_FAILED COMMITTED_RECOVERY_FAILED; do
    existing_path=$tx/$existing_status
    if [ -e "$existing_path" ] || [ -L "$existing_path" ]; then
      [ "$existing_status" = "$status" ] || return 1
      status_journal_ok "$existing_path" "$existing_status"
      return $?
    fi
  done
  atomic_journal "$tx/$status" "STATUS=$status\nREASON=$failure_reason"
}
journal_file_ok(){
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%a:%u:%g:%h' "$1" 2>/dev/null)" = '600:0:0:1' ]
}
journal_value(){
  journal_path=$1; journal_key=$2
  journal_result=$(awk -v key="$journal_key" 'index($0, key "=") == 1 {print substr($0, length(key) + 2)}' "$journal_path")
  [ "$(printf '%s\n' "$journal_result" | wc -l | tr -d ' ')" -eq 1 ] || return 1
  [ -n "$journal_result" ] || return 1
  printf '%s' "$journal_result"
}
journal_schema_ok(){
  journal_path=$1; marker=$2; expected_lines=$3; shift 3
  journal_file_ok "$journal_path" || return 1
  [ "$(wc -l <"$journal_path" | tr -d ' ')" -eq "$expected_lines" ] || return 1
  [ "$(grep -Fxc "$marker" "$journal_path" || true)" -eq 1 ] || return 1
  [ "$(( $# + 1 ))" -eq "$expected_lines" ] || return 1
  for journal_key in "$@"; do journal_value "$journal_path" "$journal_key" >/dev/null || return 1; done
}
digest_file_ok(){
  journal_file_ok "$1" || return 1
  [ "$(wc -l <"$1" | tr -d ' ')" -eq 1 ] || return 1
  digest_value=$(cat "$1") || return 1
  valid_digest "$digest_value"
}
active_journal_ok(){
  active_path=$1; expected_id=$2; expected_prepared=$3
  journal_schema_ok "$active_path" ACTIVE 6 SCHEMA OP TXID PREPARED PENDING || return 1
  [ "$(journal_value "$active_path" SCHEMA)" = openclash-sync-web-active-v1 ] &&
  [ "$(journal_value "$active_path" OP)" = update ] &&
  [ "$(journal_value "$active_path" TXID)" = "$expected_id" ] &&
  [ "$(journal_value "$active_path" PREPARED)" = "$expected_prepared" ] &&
  [ "$(journal_value "$active_path" PENDING)" = "$lifecycle_root/PENDING" ]
}
prepared_journal_ok(){
  prepared_path=$1; expected_id=$2
  journal_schema_ok "$prepared_path" PREPARED 8 SCHEMA OP TXID SERVICE_ENABLED_BEFORE SERVICE_ACTIVE_BEFORE BACKUP_MANIFEST_SHA256 SOURCE_IDENTITY || return 1
  manifest_digest=$(journal_value "$prepared_path" BACKUP_MANIFEST_SHA256) || return 1
  valid_digest "$manifest_digest" || return 1
  [ "$(journal_value "$prepared_path" SCHEMA)" = openclash-sync-web-lifecycle-v1 ] &&
  [ "$(journal_value "$prepared_path" OP)" = update ] &&
  [ "$(journal_value "$prepared_path" TXID)" = "$expected_id" ] &&
  [ "$(journal_value "$prepared_path" SERVICE_ENABLED_BEFORE)" = true ] &&
  [ "$(journal_value "$prepared_path" SERVICE_ACTIVE_BEFORE)" = true ] &&
  source_identity_ok "$(journal_value "$prepared_path" SOURCE_IDENTITY)"
}
committed_journal_ok(){
  receipt=$1; tx=$2
  journal_schema_ok "$receipt" COMMITTED 25 SCHEMA SERVICE_ENABLED_BEFORE SERVICE_ACTIVE_BEFORE \
    SERVICE_ENABLED_AFTER SERVICE_ACTIVE_AFTER app-server.py_BEFORE_SHA256 app-server.py_AFTER_SHA256 \
    app-auth-ha1_BEFORE_SHA256 app-auth-ha1_AFTER_SHA256 static-index.html_BEFORE_SHA256 static-index.html_AFTER_SHA256 \
    static-app.css_BEFORE_SHA256 static-app.css_AFTER_SHA256 static-app.js_BEFORE_SHA256 static-app.js_AFTER_SHA256 \
    static-logo.png_BEFORE_SHA256 static-logo.png_AFTER_SHA256 helper_BEFORE_SHA256 helper_AFTER_SHA256 \
    service_BEFORE_SHA256 service_AFTER_SHA256 LISTEN SERVICE_RESTARTED FIREWALL_CHANGED || return 1
  receipt_schema=$(journal_value "$receipt" SCHEMA) || return 1
  receipt_listen=$(journal_value "$receipt" LISTEN) || return 1
  case "$receipt_schema:$receipt_listen" in
    openclash-sync-web-update-v3:192.0.2.20:8088|openclash-sync-web-update-v4:127.0.0.1:8088|openclash-sync-web-update-v5:192.0.2.20:8088) ;;
    *) return 1;;
  esac
  [ -n "$receipt_schema" ] &&
  [ "$(journal_value "$receipt" SERVICE_ENABLED_BEFORE)" = true ] &&
  [ "$(journal_value "$receipt" SERVICE_ACTIVE_BEFORE)" = true ] &&
  [ "$(journal_value "$receipt" SERVICE_ENABLED_AFTER)" = true ] &&
  [ "$(journal_value "$receipt" SERVICE_ACTIVE_AFTER)" = true ] &&
  [ "$(journal_value "$receipt" SERVICE_RESTARTED)" = true ] &&
  [ "$(journal_value "$receipt" FIREWALL_CHANGED)" = false ] || return 1
  for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper service; do
    journal_file_ok "$tx/$label.before" && digest_file_ok "$tx/$label.after-sha" || return 1
    before_digest=$(sha "$tx/$label.before") || return 1
    after_digest=$(cat "$tx/$label.after-sha") || return 1
    [ "$(journal_value "$receipt" "${label}_BEFORE_SHA256")" = "$before_digest" ] &&
    [ "$(journal_value "$receipt" "${label}_AFTER_SHA256")" = "$after_digest" ] || return 1
  done
}
clear_active(){
  [ ! -e "$lifecycle_root/ACTIVE" ] && [ ! -L "$lifecycle_root/ACTIVE" ] && return 0
  rm -f "$lifecycle_root/ACTIVE" || return 1
  fsync_directory "$lifecycle_root"
}
clear_pending(){
  [ ! -e "$lifecycle_root/PENDING" ] && [ ! -L "$lifecycle_root/PENDING" ] && return 0
  rm -f "$lifecycle_root/PENDING" || return 1
  fsync_directory "$lifecycle_root"
}
clear_lifecycle(){
  # PENDING is cleared first by protocol. Recovery recognizes the resulting
  # terminal ACTIVE-only window and finishes the second unlink idempotently.
  clear_pending && clear_active
}
cleanup_lifecycle_partials(){
  partial_changed=false
  for lifecycle_partial in "$lifecycle_root/.PENDING.partial" "$lifecycle_root/.ACTIVE.partial"; do
    if [ -e "$lifecycle_partial" ] || [ -L "$lifecycle_partial" ]; then
      journal_file_ok "$lifecycle_partial" || return 1
      rm -f "$lifecycle_partial" || return 1
      partial_changed=true
    fi
  done
  [ "$partial_changed" = false ] || fsync_directory "$lifecycle_root"
}
pending_journal_ok(){
  pending_path=$1; expected_id=$2; expected_tx=$3; expected_source_identity=$4
  journal_schema_ok "$pending_path" PENDING 7 SCHEMA OP TXID TX_PATH SOURCE_PATH SOURCE_IDENTITY || return 1
  [ "$(journal_value "$pending_path" SCHEMA)" = openclash-sync-web-pending-v1 ] &&
  [ "$(journal_value "$pending_path" OP)" = update ] &&
  [ "$(journal_value "$pending_path" TXID)" = "$expected_id" ] &&
  [ "$(journal_value "$pending_path" TX_PATH)" = "$expected_tx" ] &&
  [ "$(journal_value "$pending_path" SOURCE_PATH)" = "$source" ] &&
  [ "$(journal_value "$pending_path" SOURCE_IDENTITY)" = "$expected_source_identity" ] &&
  source_identity_ok "$expected_source_identity"
}
armed_journal_ok(){
  armed_path=$1; armed_tx=$2
  journal_schema_ok "$armed_path" ARMED 5 SCHEMA SERVICE_WAS_ENABLED SERVICE_WAS_ACTIVE SERVICE_UNIT_BEFORE_SHA256 || return 1
  armed_digest=$(journal_value "$armed_path" SERVICE_UNIT_BEFORE_SHA256) || return 1
  valid_digest "$armed_digest" || return 1
  [ "$(journal_value "$armed_path" SCHEMA)" = openclash-sync-web-update-arm-v2 ] &&
  [ "$(journal_value "$armed_path" SERVICE_WAS_ENABLED)" = true ] &&
  [ "$(journal_value "$armed_path" SERVICE_WAS_ACTIVE)" = true ] &&
  [ "$armed_digest" = "$(sha "$armed_tx/service.before")" ]
}
status_journal_ok(){
  status_path=$1; expected_status=$2
  journal_schema_ok "$status_path" "STATUS=$expected_status" 2 REASON || return 1
  [ "$(journal_value "$status_path" REASON)" != '' ]
}
valid_update_tx_path(){
  candidate_id=$1; candidate_tx=$2
  active_id_ok "$candidate_id" && [ "$candidate_tx" = "/opt/openclash-sync-web-update-backup-$candidate_id" ]
}
cleanup_pending_orphan(){
  orphan=$1
  python3 -I -B - "$orphan" <<'PY_PENDING_ORPHAN'
import os
import re
import stat
import sys

path = sys.argv[1]
if not re.fullmatch(r"/opt/openclash-sync-web-update-backup-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*", path):
    raise OSError("invalid update orphan path")

labels = (
    "app-server.py", "app-auth-ha1", "static-index.html", "static-app.css",
    "static-app.js", "static-logo.png", "helper", "service",
)
allowed_files = {"SHA256SUMS.before", "PREPARED", ".PREPARED.partial"}
for label in labels:
    allowed_files.update((
        f"{label}.before", f"{label}.after-sha", f".{label}.after-sha.partial",
    ))
for status_name in ("ABORTED", "ROLLED_BACK"):
    allowed_files.update((status_name, f".{status_name}.partial"))
source_files = {
    "source/server.py", "source/openclash_web_helper.py",
    "source/openclash-sync-web.service", "source/auth-ha1",
    "source/static/index.html", "source/static/app.css", "source/static/app.js",
    "source/static/OpenClash_Sync_Logo.png",
}
allowed_files.update(source_files)
allowed_directories = {"source", "source/static"}

root_info = os.lstat(path)
if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or
        root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
    raise OSError("untrusted update orphan root")

rootfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
entries = []
try:
    def inspect(directoryfd, prefix=""):
        for name in os.listdir(directoryfd):
            relative = f"{prefix}/{name}" if prefix else name
            info = os.stat(name, dir_fd=directoryfd, follow_symlinks=False)
            if info.st_uid != 0 or info.st_gid != 0:
                raise OSError("untrusted update orphan entry owner")
            if stat.S_ISREG(info.st_mode):
                mode = stat.S_IMODE(info.st_mode)
                if relative not in allowed_files or info.st_nlink != 1 or mode & 0o077 or mode & 0o7000:
                    raise OSError("unexpected update orphan file")
                entries.append((relative, False))
            elif stat.S_ISDIR(info.st_mode):
                if relative not in allowed_directories or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("unexpected update orphan directory")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                try:
                    inspect(child, relative)
                finally:
                    os.close(child)
                entries.append((relative, True))
            else:
                raise OSError("unexpected update orphan entry type")
    inspect(rootfd)
finally:
    os.close(rootfd)

parent, name = os.path.split(path)
parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    rootfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
    try:
        for relative, is_directory in sorted(entries, key=lambda item: item[0].count("/"), reverse=True):
            parts = relative.split("/")
            directoryfd = os.dup(rootfd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                    os.close(directoryfd)
                    directoryfd = child
                if is_directory:
                    os.rmdir(parts[-1], dir_fd=directoryfd)
                else:
                    os.unlink(parts[-1], dir_fd=directoryfd)
                os.fsync(directoryfd)
            finally:
                os.close(directoryfd)
        os.fsync(rootfd)
    finally:
        os.close(rootfd)
    os.rmdir(name, dir_fd=parentfd)
    os.fsync(parentfd)
finally:
    os.close(parentfd)
PY_PENDING_ORPHAN
}
recover_pending(){
  pending=$lifecycle_root/PENDING
  [ ! -e "$pending" ] && [ ! -L "$pending" ] && return 0
  [ ! -e "$lifecycle_root/ACTIVE" ] && [ ! -L "$lifecycle_root/ACTIVE" ] || return 0
  journal_file_ok "$pending" || return 1
  pending_id=$(journal_value "$pending" TXID) || return 1
  pending_tx=$(journal_value "$pending" TX_PATH) || return 1
  pending_source_identity=$(journal_value "$pending" SOURCE_IDENTITY) || return 1
  valid_update_tx_path "$pending_id" "$pending_tx" || return 1
  pending_journal_ok "$pending" "$pending_id" "$pending_tx" "$pending_source_identity" || return 1
  if [ ! -e "$pending_tx" ] && [ ! -L "$pending_tx" ]; then
    clear_pending
    return $?
  fi
  trusted_update_tx_root "$pending_tx" || return 1
  pending_terminal_status=$(terminal_recovery_status "$pending_tx") || return 1
  case "$pending_terminal_status" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED)
      stop_service_for_recovery >/dev/null 2>&1 || true
      return 1
      ;;
  esac
  cleanup_pending_orphan "$pending_tx" || return 1
  clear_pending
}
source_identity_ok(){ case "$1" in *[!0-9:]*|:*|*:|*:*:*) return 1;; esac; }
asset_state(){
  path=$1; mode=$2; uid=$3; gid=$4; before=$5; after=$6
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf 'MISSING'; return 0; fi
  [ -f "$path" ] && [ ! -L "$path" ] || { printf 'THIRD'; return 0; }
  [ "$(stat -c '%a:%u:%g:%h' "$path" 2>/dev/null || true)" = "$mode:$uid:$gid:1" ] || { printf 'THIRD'; return 0; }
  current=$(sha "$path" 2>/dev/null || true)
  [ "$current" = "$after" ] && { printf 'AFTER'; return 0; }
  [ "$current" = "$before" ] && { printf 'BEFORE'; return 0; }
  printf 'THIRD'
}
atomic_restore(){
  source_file=$1; target_file=$2; target_mode=$3; target_uid=$4; target_gid=$5; expected_after=$6; label=$7
  [ -f "$source_file" ] && [ ! -L "$source_file" ] && [ "$(stat -c '%a:%u:%g:%h' "$source_file")" = '600:0:0:1' ] || return 1
  [ "$(sha "$target_file" 2>/dev/null || true)" = "$expected_after" ] || return 1
  target_directory=${target_file%/*}
  temporary="$target_directory/.openclash-web-restore-${recovery_tx_id}-${label}"
  (umask 077; set -C; : >"$temporary") 2>/dev/null || return 1
  if ! cp "$source_file" "$temporary" || ! chown "$target_uid:$target_gid" "$temporary" || ! chmod "$target_mode" "$temporary" ||
     ! cmp -s "$source_file" "$temporary" || ! fsync_file "$temporary" || [ "$(sha "$target_file" 2>/dev/null || true)" != "$expected_after" ]; then
    rm -f "$temporary"; return 1
  fi
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 1; }
  fsync_path "$target_file"
}
active_id_ok(){ printf '%s\n' "$1" | grep -Eq '^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$'; }
stop_service_for_recovery(){
  systemctl disable --now openclash-sync-web.service >/dev/null 2>&1 || return 1
  [ "$(systemctl show -p LoadState --value openclash-sync-web.service 2>/dev/null || true)" = loaded ] || return 1
  [ "$(systemctl show -p ActiveState --value openclash-sync-web.service 2>/dev/null || true)" = inactive ] || return 1
  [ "$(systemctl is-enabled openclash-sync-web.service 2>/dev/null || true)" = disabled ] || return 1
}
service_after_ok(){
  systemctl is-enabled --quiet openclash-sync-web.service &&
  systemctl is-active --quiet openclash-sync-web.service &&
  health_ok && service_listen_ok
}
trusted_update_tx_root(){
  [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%a:%u:%g' "$1" 2>/dev/null)" = '700:0:0' ]
}
update_recovery_targets_ok(){
  for recovery_directory in /opt "$app" "$app/static" /usr/local/sbin /etc/systemd/system \
    /etc/sudoers.d /etc "$keys" "$keys/keys"; do
    trusted_directory "$recovery_directory" || return 1
  done
  [ "$(stat -c '%a:%u:%g' "$app" 2>/dev/null)" = '755:0:0' ] &&
    [ "$(stat -c '%a:%u:%g' "$app/static" 2>/dev/null)" = '755:0:0' ] &&
    [ "$(stat -c '%a:%u:%g' "$keys" 2>/dev/null)" = '700:0:0' ] &&
    [ "$(stat -c '%a:%u:%g' "$keys/keys" 2>/dev/null)" = '700:0:0' ]
}
recovery_failed(){
  failed_tx=$1; failed_status=$2; failure_reason=$3
  stop_service_for_recovery >/dev/null 2>&1 || true
  if [ -n "$failed_tx" ] && trusted_update_tx_root "$failed_tx"; then
    journal_status "$failed_tx" "$failed_status" || true
  fi
  return 1
}
validate_recovery_residue(){
  residue_tx=$1; residue_source_identity=$2
  if [ -e "$residue_tx/COMMITTED.partial" ] || [ -L "$residue_tx/COMMITTED.partial" ]; then
    journal_file_ok "$residue_tx/COMMITTED.partial" || return 1
  fi
  if [ -e "$residue_tx/ARMED" ] || [ -L "$residue_tx/ARMED" ]; then
    armed_journal_ok "$residue_tx/ARMED" "$residue_tx" || return 1
  fi
  if [ -e "$residue_tx/ARMED.partial" ] || [ -L "$residue_tx/ARMED.partial" ]; then
    journal_file_ok "$residue_tx/ARMED.partial" || return 1
  fi
  cleanup_target_partials "$residue_tx" validate || return 1
  consume_source "$source" "$residue_source_identity" "$residue_tx/source" validate || return 1
  cleanup_source_stage_path "$residue_tx/source" validate || return 1
}
cleanup_recovery_residue(){
  residue_tx=$1; residue_source_identity=$2
  cleanup_target_partials "$residue_tx" delete || return 1
  # The original bundle is removed only while its directory identity and every
  # declared file still match the private staged copy.
  consume_source "$source" "$residue_source_identity" "$residue_tx/source" recovery || return 1
  cleanup_source_stage_path "$residue_tx/source" || return 1
  if [ -e "$residue_tx/COMMITTED.partial" ] || [ -L "$residue_tx/COMMITTED.partial" ]; then
    journal_file_ok "$residue_tx/COMMITTED.partial" || return 1
    rm -f "$residue_tx/COMMITTED.partial" || return 1
  fi
  if [ -e "$residue_tx/ARMED" ] || [ -L "$residue_tx/ARMED" ]; then
    armed_journal_ok "$residue_tx/ARMED" "$residue_tx" || return 1
    rm -f "$residue_tx/ARMED" || return 1
  fi
  if [ -e "$residue_tx/ARMED.partial" ] || [ -L "$residue_tx/ARMED.partial" ]; then
    journal_file_ok "$residue_tx/ARMED.partial" || return 1
    rm -f "$residue_tx/ARMED.partial" || return 1
  fi
  fsync_directory "$residue_tx"
}
secure_unlink_partial(){
  python3 -I -B - "$1" <<'PY_TARGET_PARTIAL_UNLINK'
import os, stat, sys
target = sys.argv[1]
if not target.startswith("/") or os.path.normpath(target) != target:
    raise OSError("invalid partial path")
parts = [part for part in target.split("/") if part]
directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for part in parts[:-1]:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        os.close(directory)
        directory = child
    before = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
    descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_size)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > 16 * 1024 * 1024
            or identity != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise OSError("untrusted partial")
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if identity != (current.st_dev, current.st_ino, current.st_size):
            raise OSError("partial changed")
        os.unlink(parts[-1], dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(descriptor)
finally:
    os.close(directory)
PY_TARGET_PARTIAL_UNLINK
}
cleanup_target_partials(){
  cleanup_tx=$1; cleanup_action=${2:-delete}
  [ "$cleanup_action" = validate ] || [ "$cleanup_action" = delete ] || return 1
  cleanup_id=${cleanup_tx##*/openclash-sync-web-update-backup-}
  active_id_ok "$cleanup_id" || return 1
  cleanup_specs="$app app-server.py 555 0 0|$app app-auth-ha1 440 0 $syncsvc_gid|$app/static static-index.html 444 0 0|$app/static static-app.css 444 0 0|$app/static static-app.js 444 0 0|$app/static static-logo.png 444 0 0|/usr/local/sbin helper 555 0 0|/etc/systemd/system service 644 0 0"
  old_ifs=$IFS; IFS='|'
  for cleanup_spec in $cleanup_specs; do
    IFS=' '; set -- $cleanup_spec; IFS='|'
    cleanup_directory=$1; cleanup_label=$2; cleanup_mode=$3; cleanup_uid=$4; cleanup_gid=$5
    [ -d "$cleanup_directory" ] && [ ! -L "$cleanup_directory" ] || continue
    expected_new="$cleanup_directory/.openclash-web-new-${cleanup_id}-${cleanup_label}"
    expected_restore="$cleanup_directory/.openclash-web-restore-${cleanup_id}-${cleanup_label}"
    for cleanup_partial in "$expected_new" "$expected_restore"; do
      if [ -e "$cleanup_partial" ] || [ -L "$cleanup_partial" ]; then
        [ -f "$cleanup_partial" ] && [ ! -L "$cleanup_partial" ] || { IFS=$old_ifs; return 1; }
        cleanup_stat=$(stat -c '%a:%u:%g:%h' "$cleanup_partial" 2>/dev/null || true)
        [ "$cleanup_stat" = "600:0:0:1" ] || [ "$cleanup_stat" = "600:$cleanup_uid:$cleanup_gid:1" ] ||
          [ "$cleanup_stat" = "$cleanup_mode:$cleanup_uid:$cleanup_gid:1" ] || { IFS=$old_ifs; return 1; }
        cleanup_size=$(stat -c '%s' "$cleanup_partial" 2>/dev/null || true)
        case "$cleanup_size" in *[!0-9]*|'') IFS=$old_ifs; return 1;; esac
        [ "$cleanup_size" -le 16777216 ] || { IFS=$old_ifs; return 1; }
        if [ "$cleanup_action" = delete ]; then
          secure_unlink_partial "$cleanup_partial" || { IFS=$old_ifs; return 1; }
        fi
      fi
    done
  done
  IFS=$old_ifs
  for cleanup_directory in "$app" "$app/static" /usr/local/sbin /etc/systemd/system; do
    [ -d "$cleanup_directory" ] && [ ! -L "$cleanup_directory" ] || continue
    for cleanup_partial in "$cleanup_directory"/.openclash-web-new-* "$cleanup_directory"/.openclash-web-restore-*; do
      [ -e "$cleanup_partial" ] || [ -L "$cleanup_partial" ] || continue
      case "$cleanup_partial" in
        "$app/.openclash-web-new-${cleanup_id}-app-server.py"|"$app/.openclash-web-restore-${cleanup_id}-app-server.py"|\
        "$app/.openclash-web-new-${cleanup_id}-app-auth-ha1"|"$app/.openclash-web-restore-${cleanup_id}-app-auth-ha1"|\
        "$app/static/.openclash-web-new-${cleanup_id}-static-index.html"|"$app/static/.openclash-web-restore-${cleanup_id}-static-index.html"|\
        "$app/static/.openclash-web-new-${cleanup_id}-static-app.css"|"$app/static/.openclash-web-restore-${cleanup_id}-static-app.css"|\
        "$app/static/.openclash-web-new-${cleanup_id}-static-app.js"|"$app/static/.openclash-web-restore-${cleanup_id}-static-app.js"|\
        "$app/static/.openclash-web-new-${cleanup_id}-static-logo.png"|"$app/static/.openclash-web-restore-${cleanup_id}-static-logo.png"|\
        "/usr/local/sbin/.openclash-web-new-${cleanup_id}-helper"|"/usr/local/sbin/.openclash-web-restore-${cleanup_id}-helper"|\
        "/etc/systemd/system/.openclash-web-new-${cleanup_id}-service"|"/etc/systemd/system/.openclash-web-restore-${cleanup_id}-service") ;;
        *) return 1;;
      esac
    done
  done
}
reject_unbound_target_partials(){
  for cleanup_directory in "$app" "$app/static" /usr/local/sbin /etc/systemd/system; do
    [ -d "$cleanup_directory" ] && [ ! -L "$cleanup_directory" ] || continue
    for cleanup_partial in "$cleanup_directory"/.openclash-web-new-* "$cleanup_directory"/.openclash-web-restore-*; do
      [ -e "$cleanup_partial" ] || [ -L "$cleanup_partial" ] || continue
      return 1
    done
  done
}
terminal_recovery_status_ok(){
  terminal_tx=$1
  terminal_count=0
  for terminal_name in ABORTED ROLLED_BACK ROLLBACK_FAILED RECOVERY_FAILED COMMITTED_RECOVERY_FAILED; do
    if [ -e "$terminal_tx/$terminal_name" ] || [ -L "$terminal_tx/$terminal_name" ]; then
      status_journal_ok "$terminal_tx/$terminal_name" "$terminal_name" || return 1
      terminal_count=$((terminal_count + 1))
    fi
  done
  [ "$terminal_count" -eq 1 ]
}
terminal_recovery_status(){
  terminal_tx=$1
  terminal_count=0
  terminal_value=NONE
  for terminal_name in ABORTED ROLLED_BACK ROLLBACK_FAILED RECOVERY_FAILED COMMITTED_RECOVERY_FAILED; do
    if [ -e "$terminal_tx/$terminal_name" ] || [ -L "$terminal_tx/$terminal_name" ]; then
      status_journal_ok "$terminal_tx/$terminal_name" "$terminal_name" || return 1
      terminal_count=$((terminal_count + 1))
      terminal_value=$terminal_name
    fi
  done
  [ "$terminal_count" -le 1 ] || return 1
  printf '%s' "$terminal_value"
}
recover_active(){
  active="$lifecycle_root/ACTIVE"
  [ ! -e "$active" ] && [ ! -L "$active" ] && return 0
  active_tx=
  journal_file_ok "$active" || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_id=$(journal_value "$active" TXID) || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_id_ok "$active_id" || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_tx="/opt/openclash-sync-web-update-backup-$active_id"
  valid_update_tx_path "$active_id" "$active_tx" && trusted_update_tx_root "$active_tx" || {
    recovery_failed '' RECOVERY_FAILED ACTIVE_TX_INVALID || true; return 1;
  }
  active_journal_ok "$active" "$active_id" "$active_tx/PREPARED" || {
    recovery_failed "$active_tx" RECOVERY_FAILED ACTIVE_INVALID || true; return 1;
  }
  prepared_journal_ok "$active_tx/PREPARED" "$active_id" || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  update_recovery_targets_ok || {
    recovery_failed "$active_tx" RECOVERY_FAILED TARGET_DIRECTORY_INVALID || true; return 1;
  }
  active_source_identity=$(journal_value "$active_tx/PREPARED" SOURCE_IDENTITY) || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  pending_present=true
  if [ ! -e "$lifecycle_root/PENDING" ] && [ ! -L "$lifecycle_root/PENDING" ]; then
    pending_present=false
  else
    pending_journal_ok "$lifecycle_root/PENDING" "$active_id" "$active_tx" "$active_source_identity" || {
      recovery_failed "$active_tx" RECOVERY_FAILED PENDING_INVALID || true; return 1;
    }
  fi
  manifest_sha=$(journal_value "$active_tx/PREPARED" BACKUP_MANIFEST_SHA256) || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  current_manifest_sha=$(sha "$active_tx/SHA256SUMS.before") || {
    recovery_failed "$active_tx" RECOVERY_FAILED BACKUP_INVALID || true; return 1;
  }
  [ "$manifest_sha" = "$current_manifest_sha" ] &&
    (cd "$active_tx" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || {
      recovery_failed "$active_tx" RECOVERY_FAILED BACKUP_INVALID || true; return 1;
    }
  for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper service; do
    journal_file_ok "$active_tx/$label.before" && digest_file_ok "$active_tx/$label.after-sha" || {
      recovery_failed "$active_tx" RECOVERY_FAILED INTENT_INVALID || true; return 1;
    }
  done
  validate_recovery_residue "$active_tx" "$active_source_identity" || {
    recovery_failed "$active_tx" RECOVERY_FAILED RESIDUE_INVALID || true; return 1;
  }
  recover_update_tx "$active_tx" "$active_source_identity" "$pending_present"
}
recover_update_tx(){
  tx=$1; recovery_source_identity=$2; recovery_pending_present=$3
  recovery_tx_id=${tx##*/openclash-sync-web-update-backup-}
  s1=$(asset_state "$app/server.py" 555 0 0 "$(sha "$tx/app-server.py.before")" "$(cat "$tx/app-server.py.after-sha")")
  s2=$(asset_state "$app/auth-ha1" 440 0 "$syncsvc_gid" "$(sha "$tx/app-auth-ha1.before")" "$(cat "$tx/app-auth-ha1.after-sha")")
  s3=$(asset_state "$app/static/index.html" 444 0 0 "$(sha "$tx/static-index.html.before")" "$(cat "$tx/static-index.html.after-sha")")
  s4=$(asset_state "$app/static/app.css" 444 0 0 "$(sha "$tx/static-app.css.before")" "$(cat "$tx/static-app.css.after-sha")")
  s5=$(asset_state "$app/static/app.js" 444 0 0 "$(sha "$tx/static-app.js.before")" "$(cat "$tx/static-app.js.after-sha")")
  s6=$(asset_state "$app/static/OpenClash_Sync_Logo.png" 444 0 0 "$(sha "$tx/static-logo.png.before")" "$(cat "$tx/static-logo.png.after-sha")")
  s7=$(asset_state "$helper" 555 0 0 "$(sha "$tx/helper.before")" "$(cat "$tx/helper.after-sha")")
  s8=$(asset_state "$service" 644 0 0 "$(sha "$tx/service.before")" "$(cat "$tx/service.after-sha")")
  states="$s1 $s2 $s3 $s4 $s5 $s6 $s7 $s8"
  terminal_status=$(terminal_recovery_status "$tx") || {
    recovery_failed "$tx" RECOVERY_FAILED TERMINAL_STATUS_INVALID || true; return 1;
  }
  case "$terminal_status" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED)
      stop_service_for_recovery >/dev/null 2>&1 || true
      return 1
      ;;
  esac
  if [ -e "$tx/COMMITTED" ] || [ -L "$tx/COMMITTED" ]; then
    [ "$terminal_status" = NONE ] || { stop_service_for_recovery >/dev/null 2>&1 || true; return 1; }
    committed_journal_ok "$tx/COMMITTED" "$tx" || {
      recovery_failed "$tx" COMMITTED_RECOVERY_FAILED COMMITTED_INVALID || true; return 1;
    }
    if [ "$states" != 'AFTER AFTER AFTER AFTER AFTER AFTER AFTER AFTER' ] || ! service_after_ok; then
      recovery_failed "$tx" COMMITTED_RECOVERY_FAILED COMMITTED_STATE_INVALID || true; return 1
    fi
    cleanup_recovery_residue "$tx" "$recovery_source_identity" || {
      recovery_failed "$tx" COMMITTED_RECOVERY_FAILED COMMITTED_CLEANUP_FAILED || true; return 1;
    }
    clear_lifecycle || {
      recovery_failed "$tx" COMMITTED_RECOVERY_FAILED LIFECYCLE_CLEANUP_FAILED || true; return 1;
    }
    printf '%s\n' 'WORKER_WEB_UPDATE=RECOVERED_COMMITTED' "BACKUP=$tx"
    return 3
  fi
  for state in $states; do
    [ "$state" != THIRD ] && [ "$state" != MISSING ] || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_STATE_INVALID || true; return 1;
    }
  done
  if [ "$terminal_status" != NONE ]; then
    [ "$states" = 'BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE' ] || {
        recovery_failed "$tx" RECOVERY_FAILED TERMINAL_WINDOW_INVALID || true; return 1;
      }
    if ! service_after_ok; then
      systemctl daemon-reload >/dev/null 2>&1 &&
        systemctl enable --now openclash-sync-web.service >/dev/null 2>&1 &&
        service_after_ok || {
          recovery_failed "$tx" RECOVERY_FAILED TERMINAL_SERVICE_RESTORE_FAILED || true; return 1;
        }
    fi
    cleanup_recovery_residue "$tx" "$recovery_source_identity" || {
      recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
    }
    clear_pending || {
      recovery_failed "$tx" RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
    }
    clear_active || {
      recovery_failed "$tx" RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
    }
    return 2
  fi
  [ "$recovery_pending_present" = true ] || {
    recovery_failed "$tx" RECOVERY_FAILED TERMINAL_WINDOW_INVALID || true; return 1;
  }
  stop_service_for_recovery || {
    recovery_failed "$tx" RECOVERY_FAILED SERVICE_STOP_FAILED || true; return 1;
  }
  cleanup_target_partials "$tx" delete || {
    recovery_failed "$tx" RECOVERY_FAILED TARGET_PARTIAL_CLEANUP_FAILED || true; return 1;
  }
  case "$states" in
    'BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE BEFORE')
      if ! systemctl daemon-reload >/dev/null 2>&1 ||
         ! systemctl enable --now openclash-sync-web.service >/dev/null 2>&1 ||
         ! service_after_ok; then
        recovery_failed "$tx" RECOVERY_FAILED BEFORE_SERVICE_RESTORE_FAILED || true
        return 1
      fi
      cleanup_recovery_residue "$tx" "$recovery_source_identity" || {
        recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
      }
      failure_reason=RECOVERED_NO_MUTATION
      journal_status "$tx" ABORTED || {
        recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
      }
      clear_lifecycle || {
        recovery_failed "$tx" RECOVERY_FAILED LIFECYCLE_CLEANUP_FAILED || true; return 1;
      }
      return 2
      ;;
    *AFTER*) ;;
    *) recovery_failed "$tx" RECOVERY_FAILED ASSET_STATE_INVALID || true; return 1;;
  esac
  for pair in "$app/server.py app-server.py 555 0 0" "$app/auth-ha1 app-auth-ha1 440 0 $syncsvc_gid" \
    "$app/static/index.html static-index.html 444 0 0" "$app/static/app.css static-app.css 444 0 0" \
    "$app/static/app.js static-app.js 444 0 0" "$app/static/OpenClash_Sync_Logo.png static-logo.png 444 0 0" \
    "$helper helper 555 0 0" "$service service 644 0 0"; do
    set -- $pair; target=$1; label=$2; mode=$3; uid=$4; gid=$5
    [ "$(asset_state "$target" "$mode" "$uid" "$gid" "$(sha "$tx/$label.before")" "$(cat "$tx/$label.after-sha")")" = AFTER ] || continue
    atomic_restore "$tx/$label.before" "$target" "$mode" "$uid" "$gid" "$(cat "$tx/$label.after-sha")" "$label" || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_RESTORE_FAILED || true; return 1;
    }
  done
  if ! systemctl daemon-reload >/dev/null 2>&1; then
    recovery_failed "$tx" RECOVERY_FAILED DAEMON_RELOAD_FAILED || true
    return 1
  fi
  if ! systemctl enable --now openclash-sync-web.service >/dev/null 2>&1 || ! service_after_ok; then
    recovery_failed "$tx" RECOVERY_FAILED SERVICE_RESTORE_FAILED || true
    return 1
  fi
  cleanup_recovery_residue "$tx" "$recovery_source_identity" || {
    recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
  }
  failure_reason=RECOVERED_TO_BEFORE
  journal_status "$tx" ROLLED_BACK || {
    recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
  }
  clear_lifecycle || {
    recovery_failed "$tx" RECOVERY_FAILED LIFECYCLE_CLEANUP_FAILED || true; return 1;
  }
  return 2
}

# This is intentionally identical to the installer's source trust boundary.
stage_source(){
  python3 -I -B - "$source" "$source_stage" 0 0 "$@" <<'PY_SOURCE_STAGE'
import os
import stat
import sys

source, destination = sys.argv[1], sys.argv[2]
expected_uid, expected_gid = int(sys.argv[3]), int(sys.argv[4])
assets = sys.argv[5:]
MAX_ASSET = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024

if not source.startswith("/") or os.path.normpath(source) != source or not assets:
    raise OSError("invalid source")

def open_chain(path):
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = [part for part in path.split("/") if part]
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, expected_uid):
                raise OSError("untrusted source directory owner or type")
            if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
                raise OSError("untrusted writable source directory")
            if index == len(parts) - 1 and (
                info.st_uid != expected_uid or info.st_gid != expected_gid or mode != 0o700
            ):
                raise OSError("source leaf must be private")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

def open_relative_directory(rootfd, parts):
    fd = os.dup(rootfd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            mode = stat.S_IMODE(info.st_mode)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or info.st_gid != expected_gid:
                raise OSError("untrusted source subtree")
            if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022):
                raise OSError("untrusted source subtree mode")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

def copy_regular(sourcefd, name, destinationfd, destination_name):
    before = os.stat(name, dir_fd=sourcefd, follow_symlinks=False)
    mode = stat.S_IMODE(before.st_mode)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_gid != expected_gid or before.st_nlink != 1:
        raise OSError("untrusted source asset")
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022) or not 1 <= before.st_size <= MAX_ASSET:
        raise OSError("untrusted source asset mode or size")
    inputfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sourcefd)
    outputfd = None
    try:
        opened = os.fstat(inputfd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_nlink != 1:
            raise OSError("source asset raced")
        outputfd = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destinationfd,
        )
        copied = 0
        while True:
            block = os.read(inputfd, 65536)
            if not block:
                break
            copied += len(block)
            if copied > MAX_ASSET:
                raise OSError("source asset grew")
            view = memoryview(block)
            while view:
                written = os.write(outputfd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
        os.fchown(outputfd, expected_uid, expected_gid)
        os.fchmod(outputfd, 0o600)
        os.fsync(outputfd)
        after = os.fstat(inputfd)
        current = os.stat(name, dir_fd=sourcefd, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink) or identity != (
            current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_nlink
        ):
            raise OSError("source asset changed")
        if copied != before.st_size:
            raise OSError("source asset size changed")
        return copied
    finally:
        if outputfd is not None:
            os.close(outputfd)
        os.close(inputfd)

sourcefd = open_chain(source)
destinationfd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    destination_info = os.fstat(destinationfd)
    if destination_info.st_uid != expected_uid or destination_info.st_gid != expected_gid or stat.S_IMODE(destination_info.st_mode) != 0o700:
        raise OSError("untrusted destination")
    source_info = os.fstat(sourcefd)
    total = 0
    created_directories = set()
    for asset in assets:
        if not asset or asset.startswith("/") or os.path.normpath(asset) != asset or ".." in asset.split("/"):
            raise OSError("invalid asset name")
        parts = asset.split("/")
        source_parent = open_relative_directory(sourcefd, parts[:-1])
        destination_parent = os.dup(destinationfd)
        try:
            accumulated = []
            for part in parts[:-1]:
                accumulated.append(part)
                key = "/".join(accumulated)
                if key not in created_directories:
                    try:
                        os.mkdir(part, 0o700, dir_fd=destination_parent)
                    except FileExistsError:
                        pass
                    created_directories.add(key)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_parent)
                info = os.fstat(child)
                if info.st_uid != expected_uid or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("untrusted destination subtree")
                os.close(destination_parent)
                destination_parent = child
            total += copy_regular(source_parent, parts[-1], destination_parent, parts[-1])
            if total > MAX_TOTAL:
                raise OSError("source bundle too large")
            os.fsync(destination_parent)
        finally:
            os.close(destination_parent)
            os.close(source_parent)
    os.fsync(destinationfd)
    expected_files = set(assets)
    expected_dirs = {""}
    for asset in assets:
        parts = asset.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            expected_dirs.add("/".join(parts[:index]))
    seen_files = set()
    seen_dirs = set()
    def inspect(directoryfd, prefix=""):
        for entry in os.listdir(directoryfd):
            relative = f"{prefix}/{entry}" if prefix else entry
            info = os.stat(entry, dir_fd=directoryfd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if relative not in expected_dirs or info.st_uid != expected_uid or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("unexpected source directory")
                seen_dirs.add(relative)
                child = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                try:
                    inspect(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if relative not in expected_files or info.st_uid != expected_uid or info.st_gid != expected_gid or info.st_nlink != 1:
                    raise OSError("unexpected source asset")
                seen_files.add(relative)
            else:
                raise OSError("unexpected source entry")
    inspect(sourcefd)
    if seen_files != expected_files or seen_dirs != expected_dirs - {""}:
        raise OSError("source manifest mismatch")
    current_source = os.fstat(sourcefd)
    if (current_source.st_dev, current_source.st_ino) != (source_info.st_dev, source_info.st_ino):
        raise OSError("source directory changed")
    print(f"{source_info.st_dev}:{source_info.st_ino}")
finally:
    os.close(destinationfd)
    os.close(sourcefd)
PY_SOURCE_STAGE
}

consume_source(){
  cleanup_source_path=${1:-$source}
  cleanup_source_identity=${2:-$source_identity}
  cleanup_staged_path=${3:-$source_stage}
  cleanup_mode=${4:-normal}
  python3 -I -B - "$cleanup_source_path" "$cleanup_source_identity" "$cleanup_staged_path" "$cleanup_mode" 0 0 <<'PY_SOURCE_CLEANUP'
import hashlib
import os
import stat
import sys

path, expected_identity, staged_path, cleanup_mode = sys.argv[1:5]
expected_uid, expected_gid = map(int, sys.argv[5:7])
parent, name = os.path.split(path)
parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

manifest = (
    "server.py", "openclash_web_helper.py", "openclash-sync-web.service", "auth-ha1",
    "static/index.html", "static/app.css", "static/app.js", "static/OpenClash_Sync_Logo.png",
)
manifest_files = set(manifest)
manifest_dirs = {"static"}

def digest(fd):
    value = hashlib.sha256()
    while True:
        block = os.read(fd, 65536)
        if not block:
            return value.hexdigest()
        value.update(block)

def inspect_tree(rootfd, require_all, compare_root=None):
    seen_files = set()
    seen_dirs = set()
    metadata = {}
    def inspect(directoryfd, prefix=""):
        for entry in os.listdir(directoryfd):
            relative = f"{prefix}/{entry}" if prefix else entry
            info = os.stat(entry, dir_fd=directoryfd, follow_symlinks=False)
            if info.st_uid != expected_uid or info.st_gid != expected_gid:
                raise OSError("source cleanup owner changed")
            if stat.S_ISDIR(info.st_mode):
                if relative not in manifest_dirs or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("source cleanup rejects unexpected directory")
                seen_dirs.add(relative)
                child = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                try:
                    inspect(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if relative not in manifest_files or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise OSError("source cleanup rejects unexpected asset")
                seen_files.add(relative)
                metadata[relative] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
            else:
                raise OSError("source cleanup rejects special entries")
    inspect(rootfd)
    if require_all and (seen_files != manifest_files or seen_dirs != manifest_dirs):
        raise OSError("source cleanup manifest mismatch")
    if not require_all and (not seen_files.issubset(manifest_files) or not seen_dirs.issubset(manifest_dirs)):
        raise OSError("source cleanup manifest mismatch")
    if compare_root is not None:
        for relative in seen_files:
            parts = relative.split("/")
            left = os.dup(rootfd)
            right = os.dup(compare_root)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=left)
                    os.close(left); left = child
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=right)
                    os.close(right); right = child
                leftfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=left)
                rightfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=right)
                try:
                    left_info = os.fstat(leftfd)
                    right_info = os.fstat(rightfd)
                    if (left_info.st_dev, left_info.st_ino, left_info.st_nlink) != (metadata[relative][0], metadata[relative][1], 1):
                        raise OSError("source cleanup asset raced")
                    if (right_info.st_uid, right_info.st_gid, stat.S_IMODE(right_info.st_mode), right_info.st_nlink) != (expected_uid, expected_gid, 0o600, 1):
                        raise OSError("source cleanup staged asset invalid")
                    if digest(leftfd) != digest(rightfd):
                        raise OSError("source cleanup source/stage mismatch")
                finally:
                    os.close(leftfd); os.close(rightfd)
            finally:
                os.close(left); os.close(right)
    return seen_files, seen_dirs, metadata

def remove_tree(rootfd, seen_files, seen_dirs):
    for relative in sorted(seen_files, key=lambda item: item.count("/"), reverse=True):
        parts = relative.split("/")
        directoryfd = os.dup(rootfd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                os.close(directoryfd); directoryfd = child
            os.unlink(parts[-1], dir_fd=directoryfd)
            os.fsync(directoryfd)
        finally:
            os.close(directoryfd)
    for relative in sorted(seen_dirs, key=lambda item: item.count("/"), reverse=True):
        parts = relative.split("/")
        directoryfd = os.dup(rootfd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                os.close(directoryfd); directoryfd = child
            os.rmdir(parts[-1], dir_fd=directoryfd)
            os.fsync(directoryfd)
        finally:
            os.close(directoryfd)
    os.fsync(rootfd)

try:
    try:
        sourcefd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
    except FileNotFoundError:
        if cleanup_mode in {"recovery", "validate"}:
            raise SystemExit(0)
        raise
    try:
        info = os.fstat(sourcefd)
        if f"{info.st_dev}:{info.st_ino}" != expected_identity:
            raise OSError("source cleanup identity changed")
        if info.st_uid != expected_uid or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError("source cleanup root invalid")
        staged_parent, staged_name = os.path.split(staged_path)
        staged_parentfd = os.open(staged_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            stagedfd = os.open(staged_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staged_parentfd)
            try:
                source_files, source_dirs, source_metadata = inspect_tree(
                    sourcefd, cleanup_mode == "normal", stagedfd
                )
                # The stage is checked separately so extra names cannot be hidden
                # by a source/stage hash comparison.
                inspect_tree(stagedfd, True)
                if cleanup_mode != "validate":
                    remove_tree(sourcefd, source_files, source_dirs)
            finally:
                os.close(stagedfd)
        finally:
            os.close(staged_parentfd)
    finally:
        os.close(sourcefd)
    if cleanup_mode != "validate":
        os.rmdir(name, dir_fd=parentfd)
        os.fsync(parentfd)
finally:
    os.close(parentfd)
PY_SOURCE_CLEANUP
}

cleanup_source_stage_path(){
  stage_path=$1
  stage_action=${2:-delete}
  [ ! -e "$stage_path" ] && [ ! -L "$stage_path" ] && return 0
  python3 -I -B - "$stage_path" "$stage_action" 0 0 <<'PY_STAGE_CLEANUP'
import hashlib
import os
import stat
import sys

path = sys.argv[1]
action = sys.argv[2]
expected_uid, expected_gid = map(int, sys.argv[3:5])
if action not in {"validate", "delete"}:
    raise OSError("invalid source stage action")
manifest = {
    "server.py": "app-server.py", "auth-ha1": "app-auth-ha1",
    "static/index.html": "static-index.html", "static/app.css": "static-app.css",
    "static/app.js": "static-app.js", "static/OpenClash_Sync_Logo.png": "static-logo.png",
    "openclash_web_helper.py": "helper", "openclash-sync-web.service": "service",
}
manifest_files = set(manifest)
manifest_dirs = {"static"}
parent, name = os.path.split(path)
parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
root = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
if not stat.S_ISDIR(root.st_mode) or root.st_uid != expected_uid or root.st_gid != expected_gid or stat.S_IMODE(root.st_mode) != 0o700:
    raise OSError("untrusted source stage")
rootfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
files, dirs = [], []
try:
    def file_digest(fd):
        value = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                return value.hexdigest()
            value.update(block)

    def inspect(fd, prefix=""):
        for name in os.listdir(fd):
            relative = f"{prefix}/{name}" if prefix else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if info.st_uid != expected_uid or info.st_gid != expected_gid:
                raise OSError("source stage owner changed")
            if stat.S_ISREG(info.st_mode):
                if relative not in manifest_files or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                    raise OSError("source stage unexpected asset")
                digest_name = f"{manifest[relative]}.after-sha"
                digest_info = os.stat(digest_name, dir_fd=parentfd, follow_symlinks=False)
                if (not stat.S_ISREG(digest_info.st_mode) or digest_info.st_uid != expected_uid or
                        digest_info.st_gid != expected_gid or stat.S_IMODE(digest_info.st_mode) != 0o600 or
                        digest_info.st_nlink != 1):
                    raise OSError("source stage digest invalid")
                digestfd = os.open(digest_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parentfd)
                assetfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    expected = os.read(digestfd, 128).decode("ascii").strip()
                    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
                        raise OSError("source stage digest malformed")
                    if file_digest(assetfd) != expected:
                        raise OSError("source stage content drift")
                finally:
                    os.close(digestfd)
                    os.close(assetfd)
                files.append(relative)
            elif stat.S_ISDIR(info.st_mode):
                if relative not in manifest_dirs or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("source stage unexpected directory")
                dirs.append(relative)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try: inspect(child, relative)
                finally: os.close(child)
            else:
                raise OSError("source stage rejects special entries")
    inspect(rootfd)
    if action == "delete":
        for relative in sorted(files, key=lambda item: item.count("/"), reverse=True):
            parts = relative.split("/"); fd = os.dup(rootfd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                os.unlink(parts[-1], dir_fd=fd); os.fsync(fd)
            finally: os.close(fd)
        for relative in sorted(dirs, key=lambda item: item.count("/"), reverse=True):
            parts = relative.split("/"); fd = os.dup(rootfd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                os.rmdir(parts[-1], dir_fd=fd); os.fsync(fd)
            finally: os.close(fd)
        os.fsync(rootfd)
finally:
    os.close(rootfd)
try:
    if action == "delete":
        os.rmdir(name, dir_fd=parentfd)
        os.fsync(parentfd)
finally:
    os.close(parentfd)
PY_STAGE_CLEANUP
}

source_root_identity(){
  python3 -I -B - "$source" <<'PY_SOURCE_IDENTITY'
import os, stat, sys
path = sys.argv[1]
if not path.startswith('/') or os.path.normpath(path) != path:
    raise OSError('invalid source path')
fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parts = [part for part in path.split('/') if part]
    for index, part in enumerate(parts):
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        info = os.fstat(child)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
            raise OSError('untrusted source directory')
        if index == len(parts) - 1 and stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError('untrusted source leaf')
        os.close(fd)
        fd = child
    info = os.fstat(fd)
    print(f'{info.st_dev}:{info.st_ino}')
finally:
    os.close(fd)
PY_SOURCE_IDENTITY
}

source=/tmp/openclash-sync-web-deploy
app=/opt/openclash-sync-web
shared_vendor=/opt/publisher-v4-openclash-worker/vendor/pyyaml-6.0.2
helper=/usr/local/sbin/openclash-web-helper
service=/etc/systemd/system/openclash-sync-web.service
sudoers=/etc/sudoers.d/openclash-sync-web
keys=/etc/openclash-web
transaction_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
backup=/opt/openclash-sync-web-update-backup-$transaction_id
source_stage=$backup/source
source_identity=
source_staged=false
source_stage_ready=false
backup_ready=false
service_mutation_started=false
asset_mutation_started=false
committed=false
syncsvc_gid=

[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 0 ] || hold ARGS 10
for command in python3 sha256sum stat find grep awk mktemp cmp install systemctl systemd-analyze visudo ss flock date; do
  command -v "$command" >/dev/null 2>&1 || hold TOOL 11
done
id syncsvc >/dev/null 2>&1 || hold SERVICE_USER 11
syncsvc_gid=$(id -g syncsvc)
shared_vendor_ok || hold SHARED_VENDOR 11
acquire_lifecycle_lock || hold LIFECYCLE_LOCK 12
trusted_directory /opt || hold INSTALLED_DIRECTORY_TRUST 12
ensure_lifecycle_root || hold LIFECYCLE_ROOT 12
cleanup_lifecycle_partials || {
  stop_service_for_recovery >/dev/null 2>&1 || true
  hold LIFECYCLE_PARTIAL 12
}
recovery_status=0
recover_active || recovery_status=$?
case "$recovery_status" in
  0) ;;
  2)
    printf '%s\n' 'WORKER_WEB_RECOVERY=PASS' 'OP=update' "BACKUP=$active_tx" \
      'NEW_TRANSACTION_STARTED=false'
    exit 0
    ;;
  3) exit 0;;
  *)
    stop_service_for_recovery >/dev/null 2>&1 || true
    hold RECOVERY 12
    ;;
esac
recover_pending || {
  stop_service_for_recovery >/dev/null 2>&1 || true
  hold PENDING_RECOVERY 12
}
reject_unbound_target_partials || {
  stop_service_for_recovery >/dev/null 2>&1 || true
  hold TARGET_PARTIAL_UNBOUND 12
}
for directory in /opt "$app" "$app/static" /usr/local/sbin /etc/systemd/system /etc/sudoers.d /etc "$keys" "$keys/keys"; do
  trusted_directory "$directory" || hold INSTALLED_DIRECTORY_TRUST 11
done
[ "$(stat -c '%a:%u:%g' "$app")" = '755:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$app/static")" = '755:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$keys")" = '700:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$keys/keys")" = '700:0:0' ] || hold INSTALLED_DIRECTORY_MODE 11
id syncsvc >/dev/null 2>&1 || hold SERVICE_USER 11
syncsvc_gid=$(id -g syncsvc)
installed_file_ok "$app/server.py" 555 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$app/auth-ha1" 440 0 "$syncsvc_gid" || hold INSTALLED_ASSET 11
installed_file_ok "$app/static/index.html" 444 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$app/static/app.css" 444 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$app/static/app.js" 444 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$app/static/OpenClash_Sync_Logo.png" 444 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$helper" 555 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$service" 644 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$sudoers" 440 0 0 || hold INSTALLED_ASSET 11
installed_file_ok "$keys/keys/router_a" 600 0 0 || hold INSTALLED_KEY 11
installed_file_ok "$keys/keys/router_b" 600 0 0 || hold INSTALLED_KEY 11
installed_file_ok "$keys/known_hosts" 600 0 0 || hold INSTALLED_KEY 11
[ "$(wc -l <"$sudoers" | tr -d ' ')" -eq 1 ] &&
grep -Fxq 'syncsvc ALL=(root) NOPASSWD: /usr/local/sbin/openclash-web-helper' "$sudoers" || hold INSTALLED_SUDOERS 11
visudo -cf "$sudoers" >/dev/null || hold INSTALLED_SUDOERS 11
health_ok || hold SERVICE_BASELINE 11
service_listen_ok || hold LISTEN_BASELINE 11

[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 12
source_identity=$(source_root_identity) || hold SOURCE_IDENTITY 12
source_identity_ok "$source_identity" || hold SOURCE_IDENTITY 12
pending_payload=$(printf '%s\n' PENDING 'SCHEMA=openclash-sync-web-pending-v1' 'OP=update' \
  "TXID=$transaction_id" "TX_PATH=$backup" "SOURCE_PATH=$source" \
  "SOURCE_IDENTITY=$source_identity") || hold PENDING_BUILD 12
atomic_journal "$lifecycle_root/PENDING" "$pending_payload" || hold PENDING_FSYNC 12
pending_journal_ok "$lifecycle_root/PENDING" "$transaction_id" "$backup" "$source_identity" || hold PENDING_SCHEMA 12
install -d -m 0700 -o root -g root "$backup" "$source_stage" || hold BACKUP_CREATE 12
fsync_directory /opt || hold BACKUP_FSYNC 12
source_stage_ready=true

cleanup_source_stage(){
  [ "$source_stage_ready" = true ] || return 0
  rm -f "$source_stage/server.py" "$source_stage/openclash_web_helper.py" \
    "$source_stage/openclash-sync-web.service" "$source_stage/auth-ha1" \
    "$source_stage/static/index.html" "$source_stage/static/app.css" \
    "$source_stage/static/app.js" "$source_stage/static/OpenClash_Sync_Logo.png" || return 1
  rmdir "$source_stage/static" 2>/dev/null || true
  rmdir "$source_stage" 2>/dev/null || return 1
  fsync_directory "$backup" || return 1
  source_stage_ready=false
}
write_status(){
  journal_status "$backup" "$1"
}
backup_file(){
  target_file=$1 label=$2 mode=$3 uid=$4 gid=$5
  installed_file_ok "$target_file" "$mode" "$uid" "$gid" || return 1
  before_inode=$(stat -c '%d:%i' "$target_file") || return 1
  before_sha=$(sha "$target_file") || return 1
  cp "$target_file" "$backup/$label.before" || return 1
  chown 0:0 "$backup/$label.before" || return 1
  chmod 0600 "$backup/$label.before" || return 1
  installed_file_ok "$target_file" "$mode" "$uid" "$gid" || return 1
  [ "$(stat -c '%d:%i' "$target_file")" = "$before_inode" ] && [ "$(sha "$target_file")" = "$before_sha" ] || return 1
  [ "$(sha "$backup/$label.before")" = "$before_sha" ] || return 1
  fsync_file "$backup/$label.before" || return 1
  (cd "$backup" && sha256sum "$label.before" >>SHA256SUMS.before) || return 1
}
write_intent(){
  label=$1 source_file=$2
  partial=$backup/.$label.after-sha.partial
  intended_sha=$(sha "$source_file") || return 1
  printf '%s\n' "$intended_sha" >"$partial" || return 1
  unset intended_sha
  chmod 0600 "$partial" || return 1
  fsync_file "$partial" || return 1
  mv -f "$partial" "$backup/$label.after-sha" || return 1
  fsync_directory "$backup" || return 1
}
atomic_replace(){
  source_file=$1 target_file=$2 target_mode=$3 target_uid=$4 target_gid=$5 expected_current=$6 label=$7
  target_directory=${target_file%/*}
  [ -f "$source_file" ] && [ ! -L "$source_file" ] || return 30
  [ -f "$target_file" ] && [ ! -L "$target_file" ] && [ "$(sha "$target_file")" = "$expected_current" ] || return 31
  source_sha=$(sha "$source_file") || return 32
  temporary="$target_directory/.openclash-web-new-${transaction_id}-${label}"
  (umask 077; set -C; : >"$temporary") 2>/dev/null || return 33
  if ! cp "$source_file" "$temporary" || ! chown "$target_uid:$target_gid" "$temporary" ||
     ! chmod "$target_mode" "$temporary" || ! cmp -s "$source_file" "$temporary" ||
     ! fsync_file "$temporary" || [ "$(sha "$source_file")" != "$source_sha" ]; then
    rm -f "$temporary"; return 34
  fi
  if [ "$(sha "$target_file" 2>/dev/null || true)" != "$expected_current" ]; then
    rm -f "$temporary"; return 35
  fi
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 36; }
  fsync_path "$target_file" || return 37
}
restore_asset(){
  target_file=$1 label=$2 mode=$3 uid=$4 gid=$5
  before_file=$backup/$label.before
  intended_file=$backup/$label.after-sha
  [ -f "$before_file" ] && [ ! -L "$before_file" ] && [ -f "$intended_file" ] && [ ! -L "$intended_file" ] || return 1
  before_sha=$(sha "$before_file") || return 1
  intended_sha=$(cat "$intended_file") || return 1
  case "$intended_sha" in *[!0-9a-f]*|'') return 1;; esac
  [ "${#intended_sha}" -eq 64 ] || return 1
  current_sha=$(sha "$target_file" 2>/dev/null || true)
  if [ "$current_sha" = "$before_sha" ]; then
    installed_file_ok "$target_file" "$mode" "$uid" "$gid"
  elif [ "$current_sha" = "$intended_sha" ]; then
    atomic_replace "$before_file" "$target_file" "$mode" "$uid" "$gid" "$current_sha" "$label" &&
    [ "$(sha "$target_file")" = "$before_sha" ]
  else
    return 1
  fi
}
rollback(){
  set +e
  rollback_ok=true
  rollback_service_stopped=true
  if [ "$service_mutation_started" = true ]; then
    stop_service_for_recovery || { rollback_ok=false; rollback_service_stopped=false; }
  fi
  if [ "$rollback_service_stopped" = true ]; then
    cleanup_target_partials "$backup" delete || rollback_ok=false
    rm -f "$backup/COMMITTED.partial" "$backup/COMMITTED" 2>/dev/null || rollback_ok=false
    fsync_directory "$backup" || rollback_ok=false
  fi
  if [ "$asset_mutation_started" = true ] && [ "$rollback_ok" = true ]; then
    if [ "$backup_ready" = true ] &&
       (cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1); then
      restore_asset "$app/server.py" app-server.py 555 0 0 || rollback_ok=false
      restore_asset "$app/auth-ha1" app-auth-ha1 440 0 "$syncsvc_gid" || rollback_ok=false
      restore_asset "$app/static/index.html" static-index.html 444 0 0 || rollback_ok=false
      restore_asset "$app/static/app.css" static-app.css 444 0 0 || rollback_ok=false
      restore_asset "$app/static/app.js" static-app.js 444 0 0 || rollback_ok=false
      restore_asset "$app/static/OpenClash_Sync_Logo.png" static-logo.png 444 0 0 || rollback_ok=false
      restore_asset "$helper" helper 555 0 0 || rollback_ok=false
      restore_asset "$service" service 644 0 0 || rollback_ok=false
      systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=false
    else
      # Never derive restore hashes from backup files after their manifest fails.
      rollback_ok=false
    fi
  fi
  if [ "$service_mutation_started" = true ] && [ "$rollback_ok" = true ]; then
    systemctl enable --now openclash-sync-web.service >/dev/null 2>&1 || rollback_ok=false
    attempt=0
    restored_healthy=false
    while [ "$attempt" -lt 20 ]; do
      attempt=$((attempt+1))
      if health_ok && service_listen_ok; then restored_healthy=true; break; fi
      sleep 1
    done
    [ "$restored_healthy" = true ] || rollback_ok=false
  fi
  if [ "$source_staged" = true ]; then
    consume_source "$source" "$source_identity" "$source_stage" recovery || rollback_ok=false
  fi
  cleanup_source_stage || rollback_ok=false
  rm -f "$backup/ARMED.partial" "$backup/ARMED" 2>/dev/null || rollback_ok=false
  fsync_directory "$backup" || rollback_ok=false
  receipt_unavailable=false
  status=ABORTED
  [ "$service_mutation_started" = true ] && status=ROLLED_BACK
  if [ "$rollback_ok" = true ]; then
    if ! write_status "$status"; then
      receipt_unavailable=true
      stop_service_for_recovery >/dev/null 2>&1 || true
      status=ROLLBACK_FAILED
    elif ! clear_lifecycle; then
      receipt_unavailable=true
      stop_service_for_recovery >/dev/null 2>&1 || true
    fi
  else
    stop_service_for_recovery >/dev/null 2>&1 || true
    rm -f "$backup/ROLLED_BACK" "$backup/ABORTED" 2>/dev/null || true
    write_status ROLLBACK_FAILED || receipt_unavailable=true
    status=ROLLBACK_FAILED
  fi
  printf '%s\n' "WORKER_WEB_UPDATE=$status" "BACKUP=$backup" "RECEIPT_UNAVAILABLE=$receipt_unavailable"
}
finish(){
  exit_code=$?
  if [ "$committed" != true ] && { [ -e "$backup/COMMITTED" ] || [ -L "$backup/COMMITTED" ]; }; then
    # A published but untrusted receipt makes the commit decision unknown. Never roll back it.
    committed=true
  fi
  [ "$committed" = true ] || rollback
  exit "$exit_code"
}
trap finish EXIT
trap 'exit 128' HUP INT TERM

: >"$backup/SHA256SUMS.before"
chmod 0600 "$backup/SHA256SUMS.before"
backup_file "$app/server.py" app-server.py 555 0 0 || hold BACKUP 13
backup_file "$app/auth-ha1" app-auth-ha1 440 0 "$syncsvc_gid" || hold BACKUP 13
backup_file "$app/static/index.html" static-index.html 444 0 0 || hold BACKUP 13
backup_file "$app/static/app.css" static-app.css 444 0 0 || hold BACKUP 13
backup_file "$app/static/app.js" static-app.js 444 0 0 || hold BACKUP 13
backup_file "$app/static/OpenClash_Sync_Logo.png" static-logo.png 444 0 0 || hold BACKUP 13
backup_file "$helper" helper 555 0 0 || hold BACKUP 13
backup_file "$service" service 644 0 0 || hold BACKUP 13
fsync_path "$backup/SHA256SUMS.before" || hold BACKUP_FSYNC 13
fsync_directory "$backup" || hold BACKUP_FSYNC 13
backup_ready=true

staged_source_identity=$(stage_source server.py openclash_web_helper.py openclash-sync-web.service auth-ha1 \
  static/index.html static/app.css static/app.js static/OpenClash_Sync_Logo.png) || hold SOURCE_TRUST 14
source_identity_ok "$staged_source_identity" && [ "$staged_source_identity" = "$source_identity" ] || hold SOURCE_IDENTITY 14
source_staged=true
python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$source_stage/server.py" "$source_stage/openclash_web_helper.py" || hold PYTHON_SYNTAX 15
converter_runtime_ok "$source_stage/server.py" "$source_stage/openclash_web_helper.py" >/dev/null 2>&1 || hold CONVERTER_RUNTIME 15
python3 -I -B - "$shared_vendor" <<'PY_PYYAML' || hold PYYAML 15
import pathlib, sys
vendor = pathlib.Path(sys.argv[1])
assert vendor.is_dir()
sys.path.insert(0, str(vendor))
import yaml
assert yaml.__version__ == "6.0.2"
PY_PYYAML
systemd-analyze verify "$source_stage/openclash-sync-web.service" >/dev/null 2>&1 || hold SERVICE_UNIT 15
auth_lines=$(wc -l <"$source_stage/auth-ha1" | tr -d ' ')
case "$auth_lines" in
  1) grep -Eq '^[0-9a-f]{64}$' "$source_stage/auth-ha1" || hold AUTH_HA1 15 ;;
  2) grep -Eq '^sha256:[0-9a-f]{64}$' "$source_stage/auth-ha1" &&
     grep -Eq '^md5:[0-9a-f]{32}$' "$source_stage/auth-ha1" || hold AUTH_HA1 15 ;;
  *) hold AUTH_HA1 15 ;;
esac

write_intent app-server.py "$source_stage/server.py" || hold PUBLISH_INTENT 16
write_intent app-auth-ha1 "$source_stage/auth-ha1" || hold PUBLISH_INTENT 16
write_intent static-index.html "$source_stage/static/index.html" || hold PUBLISH_INTENT 16
write_intent static-app.css "$source_stage/static/app.css" || hold PUBLISH_INTENT 16
write_intent static-app.js "$source_stage/static/app.js" || hold PUBLISH_INTENT 16
write_intent static-logo.png "$source_stage/static/OpenClash_Sync_Logo.png" || hold PUBLISH_INTENT 16
write_intent helper "$source_stage/openclash_web_helper.py" || hold PUBLISH_INTENT 16
write_intent service "$source_stage/openclash-sync-web.service" || hold PUBLISH_INTENT 16
backup_manifest_sha=$(sha "$backup/SHA256SUMS.before") || hold PREPARED_DIGEST 16
valid_digest "$backup_manifest_sha" || hold PREPARED_DIGEST 16
prepared_payload=$(printf '%s\n' PREPARED 'SCHEMA=openclash-sync-web-lifecycle-v1' 'OP=update' "TXID=$transaction_id" \
  'SERVICE_ENABLED_BEFORE=true' 'SERVICE_ACTIVE_BEFORE=true' "BACKUP_MANIFEST_SHA256=$backup_manifest_sha" \
  "SOURCE_IDENTITY=$source_identity") || hold PREPARED_BUILD 16
atomic_journal "$backup/PREPARED" "$prepared_payload" || hold PREPARED_FSYNC 16
prepared_journal_ok "$backup/PREPARED" "$transaction_id" || hold PREPARED_SCHEMA 16
active_payload=$(printf '%s\n' ACTIVE 'SCHEMA=openclash-sync-web-active-v1' 'OP=update' "TXID=$transaction_id" \
  "PREPARED=$backup/PREPARED" "PENDING=$lifecycle_root/PENDING") || hold ACTIVE_BUILD 16
atomic_journal "$lifecycle_root/ACTIVE" "$active_payload" || hold ACTIVE_FSYNC 16
active_journal_ok "$lifecycle_root/ACTIVE" "$transaction_id" "$backup/PREPARED" || hold ACTIVE_SCHEMA 16
service_unit_before_sha=$(sha "$service") || hold ARM_DIGEST 16
{
  printf '%s\n' 'ARMED' 'SCHEMA=openclash-sync-web-update-arm-v2' 'SERVICE_WAS_ENABLED=true' 'SERVICE_WAS_ACTIVE=true'
  printf 'SERVICE_UNIT_BEFORE_SHA256=%s\n' "$service_unit_before_sha"
} >"$backup/ARMED.partial"
chmod 0600 "$backup/ARMED.partial" || hold ARM_RECEIPT 16
fsync_file "$backup/ARMED.partial" || hold ARM_FSYNC 16
mv -f "$backup/ARMED.partial" "$backup/ARMED" || hold ARM_RECEIPT 16
fsync_directory "$backup" || hold ARM_FSYNC 16

service_mutation_started=true
systemctl disable --now openclash-sync-web.service >/dev/null || hold SERVICE_STOP 17
systemctl is-active --quiet openclash-sync-web.service && hold SERVICE_STOP 17
systemctl is-enabled --quiet openclash-sync-web.service && hold SERVICE_DISABLE 17

asset_mutation_started=true
atomic_replace "$source_stage/server.py" "$app/server.py" 0555 0 0 "$(sha "$backup/app-server.py.before")" app-server.py || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/auth-ha1" "$app/auth-ha1" 0440 0 "$syncsvc_gid" "$(sha "$backup/app-auth-ha1.before")" app-auth-ha1 || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/static/index.html" "$app/static/index.html" 0444 0 0 "$(sha "$backup/static-index.html.before")" static-index.html || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/static/app.css" "$app/static/app.css" 0444 0 0 "$(sha "$backup/static-app.css.before")" static-app.css || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/static/app.js" "$app/static/app.js" 0444 0 0 "$(sha "$backup/static-app.js.before")" static-app.js || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/static/OpenClash_Sync_Logo.png" "$app/static/OpenClash_Sync_Logo.png" 0444 0 0 "$(sha "$backup/static-logo.png.before")" static-logo.png || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/openclash_web_helper.py" "$helper" 0555 0 0 "$(sha "$backup/helper.before")" helper || hold ATOMIC_PUBLISH 18
atomic_replace "$source_stage/openclash-sync-web.service" "$service" 0644 0 0 "$(sha "$backup/service.before")" service || hold ATOMIC_PUBLISH 18

installed_file_ok "$app/server.py" 555 0 0 && cmp -s "$source_stage/server.py" "$app/server.py" || hold INSTALLED_ASSET 19
installed_file_ok "$app/auth-ha1" 440 0 "$syncsvc_gid" && cmp -s "$source_stage/auth-ha1" "$app/auth-ha1" || hold INSTALLED_ASSET 19
installed_file_ok "$app/static/index.html" 444 0 0 && cmp -s "$source_stage/static/index.html" "$app/static/index.html" || hold INSTALLED_ASSET 19
installed_file_ok "$app/static/app.css" 444 0 0 && cmp -s "$source_stage/static/app.css" "$app/static/app.css" || hold INSTALLED_ASSET 19
installed_file_ok "$app/static/app.js" 444 0 0 && cmp -s "$source_stage/static/app.js" "$app/static/app.js" || hold INSTALLED_ASSET 19
installed_file_ok "$app/static/OpenClash_Sync_Logo.png" 444 0 0 && cmp -s "$source_stage/static/OpenClash_Sync_Logo.png" "$app/static/OpenClash_Sync_Logo.png" || hold INSTALLED_ASSET 19
installed_file_ok "$helper" 555 0 0 && cmp -s "$source_stage/openclash_web_helper.py" "$helper" || hold INSTALLED_ASSET 19
installed_file_ok "$service" 644 0 0 && cmp -s "$source_stage/openclash-sync-web.service" "$service" || hold INSTALLED_ASSET 19
python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$app/server.py" "$helper" || hold INSTALLED_PYTHON_SYNTAX 19
systemd-analyze verify "$service" >/dev/null 2>&1 || hold INSTALLED_SERVICE_UNIT 19
visudo -cf "$sudoers" >/dev/null || hold INSTALLED_SUDOERS 19

systemctl daemon-reload || hold DAEMON_RELOAD 20
systemctl enable --now openclash-sync-web.service >/dev/null || hold SERVICE_START 20
attempt=0
healthy=false
while [ "$attempt" -lt 20 ]; do
  attempt=$((attempt+1))
  if health_ok && service_listen_ok && [ "$(service_listen_address)" = 192.0.2.20:8088 ]; then healthy=true; break; fi
  sleep 1
done
[ "$healthy" = true ] || hold HEALTH 20

consume_source || hold SOURCE_CLEANUP 21
cleanup_source_stage || hold STAGING_CLEANUP 21
: >"$backup/COMMITTED.partial" || hold RECEIPT 22
printf '%s\n' 'COMMITTED' 'SCHEMA=openclash-sync-web-update-v5' 'SERVICE_ENABLED_BEFORE=true' \
  'SERVICE_ACTIVE_BEFORE=true' 'SERVICE_ENABLED_AFTER=true' 'SERVICE_ACTIVE_AFTER=true' \
  >"$backup/COMMITTED.partial" || hold RECEIPT 22
for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper service; do
  before_digest=$(sha "$backup/$label.before") || hold RECEIPT_DIGEST 22
  digest_file_ok "$backup/$label.after-sha" || hold RECEIPT_DIGEST 22
  after_digest=$(cat "$backup/$label.after-sha") || hold RECEIPT_DIGEST 22
  printf '%s_BEFORE_SHA256=%s\n' "$label" "$before_digest" >>"$backup/COMMITTED.partial" || hold RECEIPT 22
  printf '%s_AFTER_SHA256=%s\n' "$label" "$after_digest" >>"$backup/COMMITTED.partial" || hold RECEIPT 22
done
printf '%s\n' 'LISTEN=192.0.2.20:8088' 'SERVICE_RESTARTED=true' 'FIREWALL_CHANGED=false' \
  >>"$backup/COMMITTED.partial" || hold RECEIPT 22
chmod 0600 "$backup/COMMITTED.partial" || hold RECEIPT 22
committed_journal_ok "$backup/COMMITTED.partial" "$backup" || hold RECEIPT_SCHEMA 22
fsync_file "$backup/COMMITTED.partial" || hold RECEIPT_FSYNC 22
mv -f "$backup/COMMITTED.partial" "$backup/COMMITTED" || hold RECEIPT 22
fsync_directory "$backup" || hold RECEIPT_FSYNC 22
committed_journal_ok "$backup/COMMITTED" "$backup" || hold RECEIPT_SCHEMA 22
rm -f "$backup/ARMED" || hold ARM_CLEANUP 22
fsync_directory "$backup" || hold RECEIPT_FSYNC 22
clear_lifecycle || hold LIFECYCLE_CLEANUP 22
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'WORKER_WEB_UPDATE=PASS' "BACKUP=$backup" 'LISTEN=192.0.2.20:8088' \
  'SERVICE=ACTIVE' 'SERVICE_ENABLED=true' 'SERVICE_RESTARTED=true' 'FIREWALL_CHANGED=false'
