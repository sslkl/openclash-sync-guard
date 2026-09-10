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
hold(){ failure_reason=$1; printf 'WORKER_WEB_INSTALL=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
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
  if [ -e "$partial" ] || [ -L "$partial" ]; then
    journal_file_ok "$partial" || return 1
    rm -f "$partial" || return 1
    fsync_directory "$parent" || return 1
  fi
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
  atomic_journal "$tx/$status" "STATUS=$status\nREASON=$failure_reason" || return 1
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
  # PENDING is removed first; recovery accepts the resulting terminal
  # ACTIVE-only window and completes the second unlink idempotently.
  clear_pending && clear_active
}
cleanup_lifecycle_partials(){
  changed=false
  for lifecycle_partial in "$lifecycle_root/.PENDING.partial" "$lifecycle_root/.ACTIVE.partial"; do
    if [ -e "$lifecycle_partial" ] || [ -L "$lifecycle_partial" ]; then
      journal_file_ok "$lifecycle_partial" || return 1
      rm -f "$lifecycle_partial" || return 1
      changed=true
    fi
  done
  [ "$changed" = false ] || fsync_directory "$lifecycle_root"
}
cleanup_orphan_transaction(){
  orphan=$1
  python3 -I -B - "$orphan" <<'PY_ORPHAN_CLEANUP'
import os, stat, sys
path = sys.argv[1]
if not path.startswith(('/opt/openclash-sync-web-install-transactions/install-', '/opt/openclash-sync-web-update-backup-')):
    raise OSError('invalid orphan path')
root = os.lstat(path)
if not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700:
    raise OSError('untrusted orphan root')
operation = 'install' if '/openclash-sync-web-install-transactions/install-' in path else 'update'
install_labels = {'app-server.py', 'app-auth-ha1', 'static-index.html', 'static-app.css', 'static-app.js', 'static-logo.png', 'helper', 'router-a', 'router-b', 'known-hosts', 'service', 'sudoers'}
update_labels = {'app-server.py', 'app-auth-ha1', 'static-index.html', 'static-app.css', 'static-app.js', 'static-logo.png', 'helper', 'service'}
labels = install_labels if operation == 'install' else update_labels
source_files = {'server.py', 'openclash_web_helper.py', 'openclash-sync-web.service', 'auth-ha1', 'static/index.html', 'static/app.css', 'static/app.js', 'static/OpenClash_Sync_Logo.png'}
if operation == 'install':
    source_files |= {'router_a', 'router_b', 'known_hosts', 'sudoers'}
root_files = {'PREPARED', '.PREPARED.partial', 'ABORTED', '.ABORTED.partial', 'ROLLED_BACK', '.ROLLED_BACK.partial', 'RECOVERY_FAILED', '.RECOVERY_FAILED.partial'}
root_files |= {f'{label}.after-sha' for label in labels} | {f'.{label}.after-sha.partial' for label in labels}
if operation == 'update':
    root_files |= {f'{label}.before' for label in labels} | {'SHA256SUMS.before'}
allowed_dirs = {'source', 'source/static'}

def purge(fd, prefix=''):
    for name in os.listdir(fd):
        relative = f'{prefix}/{name}' if prefix else name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if info.st_uid != 0 or info.st_gid != 0:
            raise OSError('untrusted orphan entry')
        if stat.S_ISREG(info.st_mode):
            if (prefix == '' and relative not in root_files) or (prefix != '' and relative.removeprefix('source/') not in source_files):
                raise OSError('unexpected orphan file')
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise OSError('untrusted orphan file mode')
            os.unlink(name, dir_fd=fd)
        elif stat.S_ISDIR(info.st_mode):
            if relative not in allowed_dirs:
                raise OSError('unexpected orphan directory')
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise OSError('untrusted orphan directory mode')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: purge(child, relative)
            finally: os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            raise OSError('untrusted orphan entry type')
    os.fsync(fd)
parent, name = os.path.split(path)
parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
    try: purge(fd)
    finally: os.close(fd)
    os.rmdir(name, dir_fd=parentfd)
    os.fsync(parentfd)
finally: os.close(parentfd)
PY_ORPHAN_CLEANUP
}
recover_pending(){
  pending="$lifecycle_root/PENDING"
  [ ! -e "$pending" ] && [ ! -L "$pending" ] && return 0
  journal_file_ok "$pending" || return 1
  pending_op=$(journal_value "$pending" OP) || return 1
  pending_id=$(journal_value "$pending" TXID) || return 1
  pending_tx=$(journal_value "$pending" TX_PATH) || return 1
  pending_source=$(journal_value "$pending" SOURCE_PATH) || return 1
  pending_source_identity=$(journal_value "$pending" SOURCE_IDENTITY) || return 1
  pending_source_manifest=$(journal_value "$pending" SOURCE_MANIFEST_SHA256) || return 1
  [ -e "$lifecycle_root/ACTIVE" ] || [ -L "$lifecycle_root/ACTIVE" ] && return 0
  active_id_ok "$pending_id" || return 1
  case "$pending_op:$pending_tx" in
    install:"$transaction_root/install-$pending_id"|update:/opt/openclash-sync-web-update-backup-"$pending_id") ;;
    *) return 1;;
  esac
  pending_journal_ok "$pending" "$pending_op" "$pending_id" "$pending_tx" || return 1
  [ "$pending_source" = "$source" ] &&
    source_identity_ok "$pending_source_identity" &&
    valid_digest "$pending_source_manifest" || return 1
  [ -e "$pending_tx" ] || [ -L "$pending_tx" ] || { clear_pending; return $?; }
  pending_terminal=$(terminal_recovery_status "$pending_tx") || return 1
  case "$pending_terminal" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED) return 1;;
  esac
  cleanup_bound_source "$pending_source" "$pending_op" "$pending_source_identity" "$pending_source_manifest" "$pending_tx/source" preserve-intact || return 1
  cleanup_orphan_transaction "$pending_tx" || return 1
  clear_pending || return 1
  return 2
}
asset_state(){
  path=$1; mode=$2; uid=$3; gid=$4; before=$5; after=$6
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf 'MISSING'; return 0; fi
  [ -f "$path" ] && [ ! -L "$path" ] || { printf 'THIRD'; return 0; }
  [ "$(stat -c '%a:%u:%g' "$path" 2>/dev/null || true)" = "$mode:$uid:$gid" ] || { printf 'THIRD'; return 0; }
  [ "$(stat -c '%h' "$path" 2>/dev/null || true)" = 1 ] || { printf 'THIRD'; return 0; }
  current=$(sha "$path" 2>/dev/null || true)
  [ "$current" = "$after" ] && { printf 'AFTER'; return 0; }
  [ "$current" = "$before" ] && { printf 'BEFORE'; return 0; }
  printf 'THIRD'
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
valid_digest(){
  case "$1" in *[!0-9a-f]*|'') return 1;; esac
  [ "${#1}" -eq 64 ]
}
digest_file_ok(){
  journal_file_ok "$1" || return 1
  [ "$(wc -l <"$1" | tr -d ' ')" -eq 1 ] || return 1
  digest_value=$(cat "$1") || return 1
  valid_digest "$digest_value"
}
pending_journal_ok(){
  pending_path=$1; expected_op=$2; expected_id=$3; expected_tx=$4
  journal_schema_ok "$pending_path" PENDING 8 SCHEMA OP TXID TX_PATH SOURCE_PATH SOURCE_IDENTITY SOURCE_MANIFEST_SHA256 || return 1
  [ "$(journal_value "$pending_path" SCHEMA)" = openclash-sync-web-pending-v1 ] &&
  [ "$(journal_value "$pending_path" OP)" = "$expected_op" ] &&
  [ "$(journal_value "$pending_path" TXID)" = "$expected_id" ] &&
  [ "$(journal_value "$pending_path" TX_PATH)" = "$expected_tx" ] &&
  [ "$(journal_value "$pending_path" SOURCE_PATH)" = "$source" ] &&
  source_identity_ok "$(journal_value "$pending_path" SOURCE_IDENTITY)" &&
  valid_digest "$(journal_value "$pending_path" SOURCE_MANIFEST_SHA256)"
}
active_journal_ok(){
  active_path=$1; expected_op=$2; expected_id=$3; expected_prepared=$4
  journal_schema_ok "$active_path" ACTIVE 6 SCHEMA OP TXID PREPARED PENDING || return 1
  [ "$(journal_value "$active_path" SCHEMA)" = openclash-sync-web-active-v1 ] &&
  [ "$(journal_value "$active_path" OP)" = "$expected_op" ] &&
  [ "$(journal_value "$active_path" TXID)" = "$expected_id" ] &&
  [ "$(journal_value "$active_path" PREPARED)" = "$expected_prepared" ] &&
  [ "$(journal_value "$active_path" PENDING)" = "$lifecycle_root/PENDING" ]
}
source_identity_ok(){ case "$1" in *[!0-9:]*|:*|*:|*:*:*) return 1;; esac; }
prepared_journal_ok(){
  prepared_path=$1; expected_op=$2; expected_id=$3
  if [ "$expected_op" = install ]; then
    journal_schema_ok "$prepared_path" PREPARED 8 SCHEMA OP TXID SERVICE_ENABLED_BEFORE SERVICE_ACTIVE_BEFORE SOURCE_IDENTITY SOURCE_MANIFEST_SHA256 || return 1
    [ "$(journal_value "$prepared_path" SERVICE_ENABLED_BEFORE)" = false ] &&
    [ "$(journal_value "$prepared_path" SERVICE_ACTIVE_BEFORE)" = false ] || return 1
  else
    journal_schema_ok "$prepared_path" PREPARED 9 SCHEMA OP TXID SERVICE_ENABLED_BEFORE SERVICE_ACTIVE_BEFORE BACKUP_MANIFEST_SHA256 SOURCE_IDENTITY SOURCE_MANIFEST_SHA256 || return 1
    [ "$(journal_value "$prepared_path" SERVICE_ENABLED_BEFORE)" = true ] &&
    [ "$(journal_value "$prepared_path" SERVICE_ACTIVE_BEFORE)" = true ] || return 1
    prepared_manifest=$(journal_value "$prepared_path" BACKUP_MANIFEST_SHA256) || return 1
    valid_digest "$prepared_manifest" || return 1
  fi
  [ "$(journal_value "$prepared_path" SCHEMA)" = openclash-sync-web-lifecycle-v1 ] &&
  [ "$(journal_value "$prepared_path" OP)" = "$expected_op" ] &&
  [ "$(journal_value "$prepared_path" TXID)" = "$expected_id" ] &&
  source_identity_ok "$(journal_value "$prepared_path" SOURCE_IDENTITY)" &&
  valid_digest "$(journal_value "$prepared_path" SOURCE_MANIFEST_SHA256)"
}
armed_journal_ok(){
  armed_path=$1; armed_tx=$2
  journal_schema_ok "$armed_path" ARMED 5 SCHEMA SERVICE_WAS_ENABLED SERVICE_WAS_ACTIVE SERVICE_UNIT_BEFORE_SHA256 || return 1
  armed_service_sha=$(journal_value "$armed_path" SERVICE_UNIT_BEFORE_SHA256) || return 1
  valid_digest "$armed_service_sha" || return 1
  [ "$(journal_value "$armed_path" SCHEMA)" = openclash-sync-web-update-arm-v2 ] &&
  [ "$(journal_value "$armed_path" SERVICE_WAS_ENABLED)" = true ] &&
  [ "$(journal_value "$armed_path" SERVICE_WAS_ACTIVE)" = true ] &&
  [ "$armed_service_sha" = "$(sha "$armed_tx/service.before")" ]
}
cleanup_transaction_staging(){
  cleanup_tx=$1; cleanup_op=$2; cleanup_action=${3:-delete}
  python3 -I -B - "$cleanup_tx" "$cleanup_op" "$cleanup_action" <<'PY_TRANSACTION_STAGING_CLEANUP'
import hashlib, os, stat, sys
tx, operation, action = sys.argv[1:]
if action not in {'validate', 'delete'}:
    raise OSError('invalid staging cleanup action')
install_mapping = {
    'server.py': 'app-server.py', 'auth-ha1': 'app-auth-ha1',
    'static/index.html': 'static-index.html', 'static/app.css': 'static-app.css',
    'static/app.js': 'static-app.js', 'static/OpenClash_Sync_Logo.png': 'static-logo.png',
    'openclash_web_helper.py': 'helper', 'router_a': 'router-a', 'router_b': 'router-b',
    'known_hosts': 'known-hosts', 'openclash-sync-web.service': 'service', 'sudoers': 'sudoers',
}
update_mapping = {key: value for key, value in install_mapping.items() if value not in {'router-a', 'router-b', 'known-hosts', 'sudoers'}}
mapping = install_mapping if operation == 'install' else update_mapping if operation == 'update' else None
if mapping is None:
    raise OSError('invalid staging operation')
root = os.lstat(tx)
if not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700:
    raise OSError('untrusted transaction root')
rootfd = os.open(tx, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        sourcefd = os.open('source', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
    except FileNotFoundError:
        sourcefd = None
    if sourcefd is None:
        sys.exit(0)
    try:
        info = os.fstat(sourcefd)
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise OSError('untrusted staged source')
        seen_files, seen_dirs = set(), {''}
        expected_dirs = {''}
        for relative in mapping:
            parts = relative.split('/')[:-1]
            for index in range(1, len(parts) + 1):
                expected_dirs.add('/'.join(parts[:index]))
        def inspect(fd, prefix=''):
            for name in os.listdir(fd):
                relative = f'{prefix}/{name}' if prefix else name
                entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode):
                    if relative not in expected_dirs or entry.st_uid != 0 or entry.st_gid != 0 or stat.S_IMODE(entry.st_mode) != 0o700:
                        raise OSError('unexpected staged directory')
                    seen_dirs.add(relative)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try: inspect(child, relative)
                    finally: os.close(child)
                elif stat.S_ISREG(entry.st_mode):
                    if relative not in mapping or entry.st_uid != 0 or entry.st_gid != 0 or stat.S_IMODE(entry.st_mode) != 0o600 or entry.st_nlink != 1:
                        raise OSError('unexpected staged file')
                    digest_name = f'{mapping[relative]}.after-sha'
                    digest_info = os.stat(digest_name, dir_fd=rootfd, follow_symlinks=False)
                    if not stat.S_ISREG(digest_info.st_mode) or digest_info.st_uid != 0 or digest_info.st_gid != 0 or stat.S_IMODE(digest_info.st_mode) != 0o600 or digest_info.st_nlink != 1:
                        raise OSError('untrusted staged digest')
                    digestfd = os.open(digest_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=rootfd)
                    try: expected = os.read(digestfd, 128).decode('ascii').strip()
                    finally: os.close(digestfd)
                    if len(expected) != 64 or any(ch not in '0123456789abcdef' for ch in expected):
                        raise OSError('invalid staged digest')
                    filefd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        actual = hashlib.sha256()
                        while True:
                            block = os.read(filefd, 65536)
                            if not block: break
                            actual.update(block)
                    finally: os.close(filefd)
                    if actual.hexdigest() != expected:
                        raise OSError('staged source drift')
                    seen_files.add(relative)
                else:
                    raise OSError('unexpected staged entry')
        inspect(sourcefd)
        if not seen_files.issubset(set(mapping)) or not seen_dirs.issubset(expected_dirs):
            raise OSError('invalid staged source subset')
        if action == 'delete':
            for relative in sorted(seen_files, key=lambda value: (value.count('/'), value), reverse=True):
                parts = relative.split('/')
                fd = os.dup(sourcefd)
                try:
                    for part in parts[:-1]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd); fd = child
                    os.unlink(parts[-1], dir_fd=fd); os.fsync(fd)
                finally: os.close(fd)
            for relative in sorted(seen_dirs - {''}, key=lambda value: value.count('/'), reverse=True):
                parts = relative.split('/')
                fd = os.dup(sourcefd)
                try:
                    for part in parts[:-1]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd); fd = child
                    os.rmdir(parts[-1], dir_fd=fd); os.fsync(fd)
                finally: os.close(fd)
            os.fsync(sourcefd)
    finally:
        os.close(sourcefd)
    if action == 'delete':
        os.rmdir('source', dir_fd=rootfd)
        os.fsync(rootfd)
finally:
    os.close(rootfd)
PY_TRANSACTION_STAGING_CLEANUP
}
cleanup_recovery_ephemera(){
  cleanup_tx=$1; cleanup_op=$2
  cleanup_target_partials "$cleanup_tx" "$cleanup_op" delete || return 1
  cleanup_prepared=$cleanup_tx/PREPARED
  cleanup_identity=$(journal_value "$cleanup_prepared" SOURCE_IDENTITY) || return 1
  cleanup_manifest=$(journal_value "$cleanup_prepared" SOURCE_MANIFEST_SHA256) || return 1
  source_identity_ok "$cleanup_identity" && valid_digest "$cleanup_manifest" || return 1
  recover_bound_source "$source" "$cleanup_identity" "$cleanup_tx/source" || return 1
  cleanup_transaction_staging "$cleanup_tx" "$cleanup_op" || return 1
  if [ -e "$cleanup_tx/COMMITTED.partial" ] || [ -L "$cleanup_tx/COMMITTED.partial" ]; then
    journal_file_ok "$cleanup_tx/COMMITTED.partial" || return 1
    rm -f "$cleanup_tx/COMMITTED.partial" || return 1
    fsync_directory "$cleanup_tx" || return 1
  fi
  if [ "$cleanup_op" = update ]; then
    if [ -e "$cleanup_tx/ARMED" ] || [ -L "$cleanup_tx/ARMED" ]; then
      armed_journal_ok "$cleanup_tx/ARMED" "$cleanup_tx" || return 1
      rm -f "$cleanup_tx/ARMED" || return 1
      fsync_directory "$cleanup_tx" || return 1
    fi
    if [ -e "$cleanup_tx/ARMED.partial" ] || [ -L "$cleanup_tx/ARMED.partial" ]; then
      journal_file_ok "$cleanup_tx/ARMED.partial" || return 1
      rm -f "$cleanup_tx/ARMED.partial" || return 1
      fsync_directory "$cleanup_tx" || return 1
    fi
  else
    [ ! -e "$cleanup_tx/ARMED" ] && [ ! -L "$cleanup_tx/ARMED" ] &&
    [ ! -e "$cleanup_tx/ARMED.partial" ] && [ ! -L "$cleanup_tx/ARMED.partial" ] || return 1
  fi
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
  cleanup_tx=$1; cleanup_op=$2; cleanup_action=${3:-delete}
  [ "$cleanup_action" = validate ] || [ "$cleanup_action" = delete ] || return 1
  cleanup_id=${cleanup_tx##*/}
  cleanup_id=${cleanup_id#install-}
  cleanup_id=${cleanup_id#openclash-sync-web-update-backup-}
  active_id_ok "$cleanup_id" || return 1
  if [ "$cleanup_op" = install ]; then
    cleanup_specs="$app app-server.py 555 0 0|$app app-auth-ha1 440 0 $syncsvc_gid|$app/static static-index.html 444 0 0|$app/static static-app.css 444 0 0|$app/static static-app.js 444 0 0|$app/static static-logo.png 444 0 0|$keys/keys router-a 600 0 0|$keys/keys router-b 600 0 0|$keys known-hosts 600 0 0|/usr/local/sbin helper 555 0 0|/etc/systemd/system service 644 0 0|/etc/sudoers.d sudoers 440 0 0"
  elif [ "$cleanup_op" = update ]; then
    cleanup_specs="$app app-server.py 555 0 0|$app app-auth-ha1 440 0 $syncsvc_gid|$app/static static-index.html 444 0 0|$app/static static-app.css 444 0 0|$app/static static-app.js 444 0 0|$app/static static-logo.png 444 0 0|/usr/local/sbin helper 555 0 0|/etc/systemd/system service 644 0 0"
  else
    return 1
  fi
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
  for cleanup_directory in "$app" "$app/static" "$keys" "$keys/keys" /usr/local/sbin /etc/systemd/system /etc/sudoers.d; do
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
        *)
          [ "$cleanup_op" = install ] || return 1
          case "$cleanup_partial" in
            "$keys/keys/.openclash-web-new-${cleanup_id}-router-a"|"$keys/keys/.openclash-web-restore-${cleanup_id}-router-a"|\
            "$keys/keys/.openclash-web-new-${cleanup_id}-router-b"|"$keys/keys/.openclash-web-restore-${cleanup_id}-router-b"|\
            "$keys/.openclash-web-new-${cleanup_id}-known-hosts"|"$keys/.openclash-web-restore-${cleanup_id}-known-hosts"|\
            "/etc/sudoers.d/.openclash-web-new-${cleanup_id}-sudoers"|"/etc/sudoers.d/.openclash-web-restore-${cleanup_id}-sudoers") ;;
            *) return 1;;
          esac
          ;;
      esac
    done
  done
}
reject_unbound_target_partials(){
  for cleanup_directory in "$app" "$app/static" "$keys" "$keys/keys" /usr/local/sbin /etc/systemd/system /etc/sudoers.d; do
    [ -d "$cleanup_directory" ] && [ ! -L "$cleanup_directory" ] || continue
    for cleanup_partial in "$cleanup_directory"/.openclash-web-new-* "$cleanup_directory"/.openclash-web-restore-*; do
      [ -e "$cleanup_partial" ] || [ -L "$cleanup_partial" ] || continue
      return 1
    done
  done
}
install_committed_journal_ok(){
  receipt=$1; tx=$2
  journal_schema_ok "$receipt" COMMITTED 18 SCHEMA SERVICE_ENABLED SERVICE_ACTIVE \
    app-server.py_AFTER_SHA256 app-auth-ha1_AFTER_SHA256 static-index.html_AFTER_SHA256 \
    static-app.css_AFTER_SHA256 static-app.js_AFTER_SHA256 static-logo.png_AFTER_SHA256 \
    helper_AFTER_SHA256 router-a_AFTER_SHA256 router-b_AFTER_SHA256 known-hosts_AFTER_SHA256 \
    service_AFTER_SHA256 sudoers_AFTER_SHA256 LISTEN FIREWALL_CHANGED || return 1
  receipt_schema=$(journal_value "$receipt" SCHEMA) || return 1
  receipt_listen=$(journal_value "$receipt" LISTEN) || return 1
  case "$receipt_schema:$receipt_listen" in
    openclash-sync-web-install-v3:192.0.2.20:8088|openclash-sync-web-install-v4:127.0.0.1:8088|openclash-sync-web-install-v5:192.0.2.20:8088) ;;
    *) return 1;;
  esac
  [ -n "$receipt_schema" ] &&
  [ "$(journal_value "$receipt" SERVICE_ENABLED)" = true ] &&
  [ "$(journal_value "$receipt" SERVICE_ACTIVE)" = true ] &&
  [ "$(journal_value "$receipt" FIREWALL_CHANGED)" = false ] || return 1
  for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper router-a router-b known-hosts service sudoers; do
    digest_file_ok "$tx/$label.after-sha" || return 1
    expected_digest=$(cat "$tx/$label.after-sha") || return 1
    receipt_digest=$(journal_value "$receipt" "${label}_AFTER_SHA256") || return 1
    valid_digest "$receipt_digest" && [ "$receipt_digest" = "$expected_digest" ] || return 1
  done
}
update_committed_journal_ok(){
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
atomic_restore(){
  source_file=$1; target_file=$2; target_mode=$3; target_uid=$4; target_gid=$5; expected_after=$6; label=$7
  [ -f "$source_file" ] && [ ! -L "$source_file" ] || return 1
  [ -f "$target_file" ] && [ ! -L "$target_file" ] || return 1
  [ "$(sha "$target_file" 2>/dev/null || true)" = "$expected_after" ] || return 1
  target_directory=${target_file%/*}
  temporary="$target_directory/.openclash-web-restore-${recovery_tx_id}-${label}"
  (umask 077; set -C; : >"$temporary") 2>/dev/null || return 1
  if ! cp "$source_file" "$temporary" || ! chown "$target_uid:$target_gid" "$temporary" ||
     ! chmod "$target_mode" "$temporary" || ! cmp -s "$source_file" "$temporary" ||
     ! fsync_file "$temporary" || [ "$(sha "$target_file" 2>/dev/null || true)" != "$expected_after" ]; then
    rm -f "$temporary"; return 1
  fi
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 1; }
  fsync_path "$target_file"
}
active_id_ok(){ printf '%s\n' "$1" | grep -Eq '^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$'; }
service_install_baseline_ok(){
  systemctl daemon-reload >/dev/null 2>&1 || return 1
  [ "$(systemctl show -p LoadState --value openclash-sync-web.service 2>/dev/null || true)" = not-found ] || return 1
  systemctl is-active --quiet openclash-sync-web.service && return 1
  systemctl is-enabled --quiet openclash-sync-web.service && return 1
  return 0
}
stop_service_for_recovery(){
  if ! systemctl disable --now openclash-sync-web.service >/dev/null 2>&1; then
    [ "$(systemctl show -p LoadState --value openclash-sync-web.service 2>/dev/null || true)" = not-found ] || return 1
  fi
  active_state_now=$(systemctl show -p ActiveState --value openclash-sync-web.service 2>/dev/null || true)
  load_state_now=$(systemctl show -p LoadState --value openclash-sync-web.service 2>/dev/null || true)
  [ "$load_state_now" = not-found ] || [ "$active_state_now" = inactive ] || return 1
  systemctl is-active --quiet openclash-sync-web.service && return 1
  systemctl is-enabled --quiet openclash-sync-web.service && return 1
  return 0
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
  python3 -I -B - "$health_address" <<'PY_RECOVERY_HEALTH' 2>/dev/null
import json, sys
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(f"http://{sys.argv[1]}/healthz", timeout=3) as response:
    assert response.status == 200 and json.load(response) == {"ok": True}
PY_RECOVERY_HEALTH
}
service_listen_ok(){
  expected_listen=$(service_listen_address) || return 1
  ss -ltn | awk 'NR>1 {print $4}' | grep -qx "$expected_listen"
}
service_after_ok(){
  systemctl is-enabled --quiet openclash-sync-web.service &&
  systemctl is-active --quiet openclash-sync-web.service &&
  service_listen_ok && health_ok
}
remove_install_directories(){
  for item in "$app/static 755" "$app 755" "$keys/keys 700" "$keys 700"; do
    set -- $item; directory=$1; mode=$2
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then continue; fi
    [ -d "$directory" ] && [ ! -L "$directory" ] &&
      [ "$(stat -c '%a:%u:%g' "$directory" 2>/dev/null)" = "$mode:0:0" ] || return 1
    rmdir "$directory" || return 1
    fsync_directory "${directory%/*}" || return 1
  done
}
verify_install_after(){
  tx=$1
  [ "$(asset_state "$app/server.py" 555 0 0 MISSING "$(cat "$tx/app-server.py.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/auth-ha1" 440 0 "$syncsvc_gid" MISSING "$(cat "$tx/app-auth-ha1.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/index.html" 444 0 0 MISSING "$(cat "$tx/static-index.html.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/app.css" 444 0 0 MISSING "$(cat "$tx/static-app.css.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/app.js" 444 0 0 MISSING "$(cat "$tx/static-app.js.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/OpenClash_Sync_Logo.png" 444 0 0 MISSING "$(cat "$tx/static-logo.png.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$helper" 555 0 0 MISSING "$(cat "$tx/helper.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$keys/keys/router_a" 600 0 0 MISSING "$(cat "$tx/router-a.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$keys/keys/router_b" 600 0 0 MISSING "$(cat "$tx/router-b.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$keys/known_hosts" 600 0 0 MISSING "$(cat "$tx/known-hosts.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$service" 644 0 0 MISSING "$(cat "$tx/service.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$sudoers" 440 0 0 MISSING "$(cat "$tx/sudoers.after-sha" 2>/dev/null || true)")" = AFTER ] && service_after_ok
}
verify_update_after(){
  tx=$1
  [ "$(asset_state "$app/server.py" 555 0 0 "$(sha "$tx/app-server.py.before" 2>/dev/null || true)" "$(cat "$tx/app-server.py.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/auth-ha1" 440 0 "$syncsvc_gid" "$(sha "$tx/app-auth-ha1.before" 2>/dev/null || true)" "$(cat "$tx/app-auth-ha1.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/index.html" 444 0 0 "$(sha "$tx/static-index.html.before" 2>/dev/null || true)" "$(cat "$tx/static-index.html.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/app.css" 444 0 0 "$(sha "$tx/static-app.css.before" 2>/dev/null || true)" "$(cat "$tx/static-app.css.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/app.js" 444 0 0 "$(sha "$tx/static-app.js.before" 2>/dev/null || true)" "$(cat "$tx/static-app.js.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$app/static/OpenClash_Sync_Logo.png" 444 0 0 "$(sha "$tx/static-logo.png.before" 2>/dev/null || true)" "$(cat "$tx/static-logo.png.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$helper" 555 0 0 "$(sha "$tx/helper.before" 2>/dev/null || true)" "$(cat "$tx/helper.after-sha" 2>/dev/null || true)")" = AFTER ] &&
  [ "$(asset_state "$service" 644 0 0 "$(sha "$tx/service.before" 2>/dev/null || true)" "$(cat "$tx/service.after-sha" 2>/dev/null || true)")" = AFTER ] && service_after_ok
}
status_journal_ok(){
  status_path=$1; expected_status=$2
  journal_file_ok "$status_path" || return 1
  [ "$(wc -l <"$status_path" | tr -d ' ')" -eq 2 ] || return 1
  [ "$(journal_value "$status_path" STATUS)" = "$expected_status" ] &&
    journal_value "$status_path" REASON >/dev/null
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
trusted_recovery_tx(){
  [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%a:%u:%g' "$1" 2>/dev/null)" = '700:0:0' ]
}
recovery_target_directories_ok(){
  for recovery_parent in /opt /usr/local/sbin /etc/systemd/system /etc/sudoers.d /etc; do
    trusted_directory "$recovery_parent" || return 1
  done
  for recovery_directory_spec in "$app 755" "$app/static 755" "$keys 700" "$keys/keys 700"; do
    set -- $recovery_directory_spec
    recovery_directory=$1; recovery_mode=$2
    if [ ! -e "$recovery_directory" ] && [ ! -L "$recovery_directory" ]; then
      continue
    fi
    [ -d "$recovery_directory" ] && [ ! -L "$recovery_directory" ] &&
      [ "$(stat -c '%a:%u:%g' "$recovery_directory" 2>/dev/null)" = "$recovery_mode:0:0" ] &&
      directory_chain_ok "$recovery_directory" || return 1
  done
}
recovery_failed(){
  failed_tx=$1; failed_status=$2; failure_reason=$3
  stop_service_for_recovery >/dev/null 2>&1 || true
  if [ -n "$failed_tx" ] && trusted_recovery_tx "$failed_tx"; then
    journal_status "$failed_tx" "$failed_status" || true
  fi
  return 1
}
validate_recovery_ephemera(){
  residue_tx=$1; residue_op=$2
  if [ -e "$residue_tx/COMMITTED.partial" ] || [ -L "$residue_tx/COMMITTED.partial" ]; then
    journal_file_ok "$residue_tx/COMMITTED.partial" || return 1
  fi
  if [ "$residue_op" = update ]; then
    if [ -e "$residue_tx/ARMED" ] || [ -L "$residue_tx/ARMED" ]; then
      armed_journal_ok "$residue_tx/ARMED" "$residue_tx" || return 1
    fi
    if [ -e "$residue_tx/ARMED.partial" ] || [ -L "$residue_tx/ARMED.partial" ]; then
      journal_file_ok "$residue_tx/ARMED.partial" || return 1
    fi
  else
    [ ! -e "$residue_tx/ARMED" ] && [ ! -L "$residue_tx/ARMED" ] &&
      [ ! -e "$residue_tx/ARMED.partial" ] && [ ! -L "$residue_tx/ARMED.partial" ] || return 1
  fi
  cleanup_target_partials "$residue_tx" "$residue_op" validate || return 1
  residue_identity=$(journal_value "$residue_tx/PREPARED" SOURCE_IDENTITY) || return 1
  recover_bound_source "$source" "$residue_identity" "$residue_tx/source" validate || return 1
  cleanup_transaction_staging "$residue_tx" "$residue_op" validate || return 1
}
recover_active(){
  active="$lifecycle_root/ACTIVE"
  [ ! -e "$active" ] && [ ! -L "$active" ] && return 0
  journal_file_ok "$active" || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_op=$(journal_value "$active" OP) || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_id=$(journal_value "$active" TXID) || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  active_id_ok "$active_id" || { recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1; }
  case "$active_op" in
    install) active_tx="$transaction_root/install-$active_id" ;;
    update) active_tx="/opt/openclash-sync-web-update-backup-$active_id" ;;
    *) recovery_failed '' RECOVERY_FAILED ACTIVE_INVALID || true; return 1 ;;
  esac
  if [ "$active_op" = install ]; then
    [ -d "$transaction_root" ] && [ ! -L "$transaction_root" ] &&
      [ "$(stat -c '%a:%u:%g' "$transaction_root" 2>/dev/null)" = '700:0:0' ] &&
      directory_chain_ok "$transaction_root" || {
        recovery_failed '' RECOVERY_FAILED TRANSACTION_ROOT_INVALID || true; return 1;
      }
  fi
  trusted_recovery_tx "$active_tx" || { recovery_failed '' RECOVERY_FAILED ACTIVE_TX_INVALID || true; return 1; }
  active_journal_ok "$active" "$active_op" "$active_id" "$active_tx/PREPARED" || {
    recovery_failed "$active_tx" RECOVERY_FAILED ACTIVE_INVALID || true; return 1;
  }
  prepared_journal_ok "$active_tx/PREPARED" "$active_op" "$active_id" || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  recovery_target_directories_ok || {
    recovery_failed "$active_tx" RECOVERY_FAILED TARGET_DIRECTORY_INVALID || true; return 1;
  }
  active_source_identity=$(journal_value "$active_tx/PREPARED" SOURCE_IDENTITY) || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  active_source_manifest=$(journal_value "$active_tx/PREPARED" SOURCE_MANIFEST_SHA256) || {
    recovery_failed "$active_tx" RECOVERY_FAILED PREPARED_INVALID || true; return 1;
  }
  active_pending_present=true
  if [ ! -e "$lifecycle_root/PENDING" ] && [ ! -L "$lifecycle_root/PENDING" ]; then
    active_pending_present=false
  else
    pending_journal_ok "$lifecycle_root/PENDING" "$active_op" "$active_id" "$active_tx" &&
      [ "$(journal_value "$lifecycle_root/PENDING" SOURCE_IDENTITY)" = "$active_source_identity" ] &&
      [ "$(journal_value "$lifecycle_root/PENDING" SOURCE_MANIFEST_SHA256)" = "$active_source_manifest" ] || {
        recovery_failed "$active_tx" RECOVERY_FAILED PENDING_INVALID || true; return 1;
      }
  fi
  if [ "$active_op" = install ]; then
    for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper router-a router-b known-hosts service sudoers; do
      digest_file_ok "$active_tx/$label.after-sha" || {
        recovery_failed "$active_tx" RECOVERY_FAILED INTENT_INVALID || true; return 1;
      }
    done
  else
    journal_file_ok "$active_tx/SHA256SUMS.before" || {
      recovery_failed "$active_tx" RECOVERY_FAILED BACKUP_INVALID || true; return 1;
    }
    manifest_sha=$(journal_value "$active_tx/PREPARED" BACKUP_MANIFEST_SHA256) || {
      recovery_failed "$active_tx" RECOVERY_FAILED BACKUP_INVALID || true; return 1;
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
  fi
  validate_recovery_ephemera "$active_tx" "$active_op" || {
    recovery_failed "$active_tx" RECOVERY_FAILED RESIDUE_INVALID || true; return 1;
  }
  active_terminal_status=$(terminal_recovery_status "$active_tx") || {
    recovery_failed "$active_tx" RECOVERY_FAILED TERMINAL_STATUS_INVALID || true; return 1;
  }
  case "$active_terminal_status" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED)
      stop_service_for_recovery >/dev/null 2>&1 || true
      return 1
      ;;
  esac
  if [ -e "$active_tx/COMMITTED" ] || [ -L "$active_tx/COMMITTED" ]; then
    [ "$active_terminal_status" = NONE ] || { stop_service_for_recovery >/dev/null 2>&1 || true; return 1; }
    if [ "$active_op" = install ]; then
      install_committed_journal_ok "$active_tx/COMMITTED" "$active_tx" || {
        recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED COMMITTED_INVALID || true; return 1;
      }
    else
      update_committed_journal_ok "$active_tx/COMMITTED" "$active_tx" || {
        recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED COMMITTED_INVALID || true; return 1;
      }
    fi
    if [ "$active_op" = install ]; then committed_ok=false; verify_install_after "$active_tx" && committed_ok=true; else committed_ok=false; verify_update_after "$active_tx" && committed_ok=true; fi
    [ "$committed_ok" = true ] || {
      recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED COMMITTED_STATE_INVALID || true; return 1;
    }
    cleanup_recovery_ephemera "$active_tx" "$active_op" || {
      recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED COMMITTED_CLEANUP_FAILED || true; return 1;
    }
    clear_pending || {
      recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
    }
    clear_active || {
      recovery_failed "$active_tx" COMMITTED_RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
    }
    printf '%s\n' 'WORKER_WEB_INSTALL=RECOVERED_COMMITTED' "TRANSACTION=$active_tx"
    return 3
  fi
  if [ "$active_op" = install ]; then
    recover_install_tx "$active_tx" "$active_pending_present" || return $?
  else
    recover_update_tx "$active_tx" "$active_pending_present" || return $?
  fi
}
recover_install_tx(){
  tx=$1; recovery_pending_present=$2; recovery_tx_id=${tx##*/install-}
  s1=$(asset_state "$app/server.py" 555 0 0 MISSING "$(cat "$tx/app-server.py.after-sha" 2>/dev/null || true)")
  s2=$(asset_state "$app/auth-ha1" 440 0 "$syncsvc_gid" MISSING "$(cat "$tx/app-auth-ha1.after-sha" 2>/dev/null || true)")
  s3=$(asset_state "$app/static/index.html" 444 0 0 MISSING "$(cat "$tx/static-index.html.after-sha" 2>/dev/null || true)")
  s4=$(asset_state "$app/static/app.css" 444 0 0 MISSING "$(cat "$tx/static-app.css.after-sha" 2>/dev/null || true)")
  s5=$(asset_state "$app/static/app.js" 444 0 0 MISSING "$(cat "$tx/static-app.js.after-sha" 2>/dev/null || true)")
  s6=$(asset_state "$app/static/OpenClash_Sync_Logo.png" 444 0 0 MISSING "$(cat "$tx/static-logo.png.after-sha" 2>/dev/null || true)")
  s7=$(asset_state "$helper" 555 0 0 MISSING "$(cat "$tx/helper.after-sha" 2>/dev/null || true)")
  s8=$(asset_state "$keys/keys/router_a" 600 0 0 MISSING "$(cat "$tx/router-a.after-sha" 2>/dev/null || true)")
  s9=$(asset_state "$keys/keys/router_b" 600 0 0 MISSING "$(cat "$tx/router-b.after-sha" 2>/dev/null || true)")
  s10=$(asset_state "$keys/known_hosts" 600 0 0 MISSING "$(cat "$tx/known-hosts.after-sha" 2>/dev/null || true)")
  s11=$(asset_state "$service" 644 0 0 MISSING "$(cat "$tx/service.after-sha" 2>/dev/null || true)")
  s12=$(asset_state "$sudoers" 440 0 0 MISSING "$(cat "$tx/sudoers.after-sha" 2>/dev/null || true)")
  states="$s1 $s2 $s3 $s4 $s5 $s6 $s7 $s8 $s9 $s10 $s11 $s12"
  for state in $states; do
    [ "$state" != THIRD ] || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_STATE_INVALID || true; return 1;
    }
  done
  terminal_status=$(terminal_recovery_status "$tx") || {
    recovery_failed "$tx" RECOVERY_FAILED TERMINAL_STATUS_INVALID || true; return 1;
  }
  case "$terminal_status" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED)
      stop_service_for_recovery >/dev/null 2>&1 || true
      return 1
      ;;
  esac
  if [ "$terminal_status" != NONE ]; then
    [ "$states" = 'MISSING MISSING MISSING MISSING MISSING MISSING MISSING MISSING MISSING MISSING MISSING MISSING' ] &&
      service_install_baseline_ok || {
        recovery_failed "$tx" RECOVERY_FAILED TERMINAL_WINDOW_INVALID || true; return 1;
      }
    cleanup_recovery_ephemera "$tx" install || {
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
  cleanup_target_partials "$tx" install delete || {
    recovery_failed "$tx" RECOVERY_FAILED TARGET_PARTIAL_CLEANUP_FAILED || true; return 1;
  }
  case "$states" in
    *AFTER*) ;;
    *)
      remove_install_directories && service_install_baseline_ok || {
        recovery_failed "$tx" RECOVERY_FAILED BASELINE_RESTORE_FAILED || true; return 1;
      }
      cleanup_recovery_ephemera "$tx" install || {
        recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
      }
      failure_reason=RECOVERED_NO_MUTATION
      journal_status "$tx" ABORTED || {
        recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
      }
      clear_pending || {
        recovery_failed "$tx" RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
      }
      clear_active || {
        recovery_failed "$tx" RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
      }
      return 2
      ;;
  esac
  for pair in \
    "$app/server.py app-server.py 555 0 0" "$app/auth-ha1 app-auth-ha1 440 0 $syncsvc_gid" \
    "$app/static/index.html static-index.html 444 0 0" "$app/static/app.css static-app.css 444 0 0" \
    "$app/static/app.js static-app.js 444 0 0" "$app/static/OpenClash_Sync_Logo.png static-logo.png 444 0 0" \
    "$helper helper 555 0 0" "$keys/keys/router_a router-a 600 0 0" \
    "$keys/keys/router_b router-b 600 0 0" "$keys/known_hosts known-hosts 600 0 0" \
    "$service service 644 0 0" "$sudoers sudoers 440 0 0"; do
    set -- $pair; target=$1; label=$2; mode=$3; uid=$4; gid=$5
    state=$(asset_state "$target" "$mode" "$uid" "$gid" MISSING "$(cat "$tx/$label.after-sha" 2>/dev/null || true)")
    [ "$state" = AFTER ] || continue
    rm -f "$target" && fsync_directory "${target%/*}" || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_REMOVE_FAILED || true; return 1;
    }
  done
  remove_install_directories && service_install_baseline_ok || {
    recovery_failed "$tx" RECOVERY_FAILED BASELINE_RESTORE_FAILED || true; return 1;
  }
  cleanup_recovery_ephemera "$tx" install || {
    recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
  }
  failure_reason=RECOVERED_TO_ABSENT
  journal_status "$tx" ROLLED_BACK || {
    recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
  }
  clear_pending || {
    recovery_failed "$tx" RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
  }
  clear_active || {
    recovery_failed "$tx" RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
  }
  return 2
}
recover_update_tx(){
  tx=$1; recovery_pending_present=$2; recovery_tx_id=${tx##*/openclash-sync-web-update-backup-}
  s1=$(asset_state "$app/server.py" 555 0 0 "$(sha "$tx/app-server.py.before" 2>/dev/null || true)" "$(cat "$tx/app-server.py.after-sha" 2>/dev/null || true)")
  s2=$(asset_state "$app/auth-ha1" 440 0 "$syncsvc_gid" "$(sha "$tx/app-auth-ha1.before" 2>/dev/null || true)" "$(cat "$tx/app-auth-ha1.after-sha" 2>/dev/null || true)")
  s3=$(asset_state "$app/static/index.html" 444 0 0 "$(sha "$tx/static-index.html.before" 2>/dev/null || true)" "$(cat "$tx/static-index.html.after-sha" 2>/dev/null || true)")
  s4=$(asset_state "$app/static/app.css" 444 0 0 "$(sha "$tx/static-app.css.before" 2>/dev/null || true)" "$(cat "$tx/static-app.css.after-sha" 2>/dev/null || true)")
  s5=$(asset_state "$app/static/app.js" 444 0 0 "$(sha "$tx/static-app.js.before" 2>/dev/null || true)" "$(cat "$tx/static-app.js.after-sha" 2>/dev/null || true)")
  s6=$(asset_state "$app/static/OpenClash_Sync_Logo.png" 444 0 0 "$(sha "$tx/static-logo.png.before" 2>/dev/null || true)" "$(cat "$tx/static-logo.png.after-sha" 2>/dev/null || true)")
  s7=$(asset_state "$helper" 555 0 0 "$(sha "$tx/helper.before" 2>/dev/null || true)" "$(cat "$tx/helper.after-sha" 2>/dev/null || true)")
  s8=$(asset_state "$service" 644 0 0 "$(sha "$tx/service.before" 2>/dev/null || true)" "$(cat "$tx/service.after-sha" 2>/dev/null || true)")
  states="$s1 $s2 $s3 $s4 $s5 $s6 $s7 $s8"
  for state in $states; do
    [ "$state" != THIRD ] && [ "$state" != MISSING ] || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_STATE_INVALID || true; return 1;
    }
  done
  terminal_status=$(terminal_recovery_status "$tx") || {
    recovery_failed "$tx" RECOVERY_FAILED TERMINAL_STATUS_INVALID || true; return 1;
  }
  case "$terminal_status" in
    ROLLBACK_FAILED|RECOVERY_FAILED|COMMITTED_RECOVERY_FAILED)
      stop_service_for_recovery >/dev/null 2>&1 || true
      return 1
      ;;
  esac
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
    cleanup_recovery_ephemera "$tx" update || {
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
  cleanup_target_partials "$tx" update delete || {
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
      cleanup_recovery_ephemera "$tx" update || {
        recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
      }
      failure_reason=RECOVERED_NO_MUTATION
      journal_status "$tx" ABORTED || {
        recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
      }
      clear_pending || {
        recovery_failed "$tx" RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
      }
      clear_active || {
        recovery_failed "$tx" RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
      }
      return 2
      ;;
    *AFTER*) ;;
    *) recovery_failed "$tx" RECOVERY_FAILED ASSET_STATE_INVALID || true; return 1;;
  esac
  for pair in \
    "$app/server.py app-server.py 555 0 0" "$app/auth-ha1 app-auth-ha1 440 0 $syncsvc_gid" \
    "$app/static/index.html static-index.html 444 0 0" "$app/static/app.css static-app.css 444 0 0" \
    "$app/static/app.js static-app.js 444 0 0" "$app/static/OpenClash_Sync_Logo.png static-logo.png 444 0 0" \
    "$helper helper 555 0 0" "$service service 644 0 0"; do
    set -- $pair; target=$1; label=$2; mode=$3; uid=$4; gid=$5
    state=$(asset_state "$target" "$mode" "$uid" "$gid" "$(sha "$tx/$label.before" 2>/dev/null || true)" "$(cat "$tx/$label.after-sha" 2>/dev/null || true)")
    [ "$state" = AFTER ] || continue
    atomic_restore "$tx/$label.before" "$target" "$mode" "$uid" "$gid" "$(cat "$tx/$label.after-sha")" "$label" || {
      recovery_failed "$tx" RECOVERY_FAILED ASSET_RESTORE_FAILED || true; return 1;
    }
  done
  systemctl daemon-reload >/dev/null 2>&1 || {
    recovery_failed "$tx" RECOVERY_FAILED DAEMON_RELOAD_FAILED || true; return 1;
  }
  systemctl enable --now openclash-sync-web.service >/dev/null 2>&1 && service_after_ok || {
    recovery_failed "$tx" RECOVERY_FAILED SERVICE_RESTORE_FAILED || true; return 1;
  }
  cleanup_recovery_ephemera "$tx" update || {
    recovery_failed "$tx" RECOVERY_FAILED RECOVERY_CLEANUP_FAILED || true; return 1;
  }
  failure_reason=RECOVERED_TO_BEFORE
  journal_status "$tx" ROLLED_BACK || {
    recovery_failed "$tx" RECOVERY_FAILED STATUS_WRITE_FAILED || true; return 1;
  }
  clear_pending || {
    recovery_failed "$tx" RECOVERY_FAILED PENDING_CLEANUP_FAILED || true; return 1;
  }
  clear_active || {
    recovery_failed "$tx" RECOVERY_FAILED ACTIVE_CLEANUP_FAILED || true; return 1;
  }
  return 2
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

# Copy all executable inputs while directory descriptors pin every path component.
# The production caller fixes expected uid/gid to root; tests can exercise the same
# routine with an unprivileged owner without weakening the production contract.
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

source_bundle(){
  bundle_action=$1; bundle_path=$2; bundle_op=$3; bundle_identity=${4:-}; bundle_manifest=${5:-}
  python3 -I -B - "$bundle_action" "$bundle_path" "$bundle_op" "$bundle_identity" "$bundle_manifest" <<'PY_SOURCE_BUNDLE'
import hashlib, os, stat, sys
action, path, operation, expected_identity, expected_manifest = sys.argv[1:]
install_files = {
    'server.py', 'openclash_web_helper.py', 'openclash-sync-web.service', 'auth-ha1',
    'router_a', 'router_b', 'known_hosts', 'static/index.html', 'static/app.css',
    'static/app.js', 'static/OpenClash_Sync_Logo.png',
}
update_files = {
    'server.py', 'openclash_web_helper.py', 'openclash-sync-web.service', 'auth-ha1',
    'static/index.html', 'static/app.css', 'static/app.js', 'static/OpenClash_Sync_Logo.png',
}
files = install_files if operation == 'install' else update_files if operation == 'update' else None
if files is None or action not in {'attest', 'consume'} or not path.startswith('/') or os.path.normpath(path) != path:
    raise OSError('invalid source bundle request')
directories = {''}
for item in files:
    parts = item.split('/')[:-1]
    for index in range(1, len(parts) + 1):
        directories.add('/'.join(parts[:index]))

fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for index, part in enumerate(part for part in path.split('/') if part):
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        info = os.fstat(child)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
            raise OSError('untrusted source directory')
        if mode & 0o022 and not (index < len([p for p in path.split('/') if p]) - 1 and info.st_uid == 0 and mode & stat.S_ISVTX):
            raise OSError('untrusted writable source directory')
        os.close(fd)
        fd = child
    root = os.fstat(fd)
    if stat.S_IMODE(root.st_mode) != 0o700:
        raise OSError('untrusted source leaf')
    identity = f'{root.st_dev}:{root.st_ino}'
    digest = hashlib.sha256()
    seen_files, seen_directories = set(), {''}

    def inspect(directoryfd, prefix=''):
        nonlocal_total = 0
        for name in sorted(os.listdir(directoryfd)):
            relative = f'{prefix}/{name}' if prefix else name
            info = os.stat(name, dir_fd=directoryfd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if relative not in directories or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError('unexpected source directory')
                seen_directories.add(relative)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                try:
                    nonlocal_total += inspect(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                mode = stat.S_IMODE(info.st_mode)
                if relative not in files or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1:
                    raise OSError('unexpected source asset')
                if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022) or not 1 <= info.st_size <= 16 * 1024 * 1024:
                    raise OSError('untrusted source asset metadata')
                inputfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directoryfd)
                try:
                    opened = os.fstat(inputfd)
                    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink) != (
                        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, 1
                    ):
                        raise OSError('source asset raced')
                    file_digest = hashlib.sha256()
                    copied = 0
                    while True:
                        block = os.read(inputfd, 65536)
                        if not block:
                            break
                        copied += len(block)
                        file_digest.update(block)
                    if copied != info.st_size:
                        raise OSError('source asset size changed')
                finally:
                    os.close(inputfd)
                seen_files.add(relative)
                digest.update(relative.encode('utf-8') + b'\0')
                digest.update(f'{mode:o}\0{info.st_size}\0'.encode('ascii'))
                digest.update(file_digest.digest())
                nonlocal_total += info.st_size
            else:
                raise OSError('unexpected source entry')
        return nonlocal_total

    total = inspect(fd)
    if total > 32 * 1024 * 1024 or seen_files != files or seen_directories != directories:
        raise OSError('source bundle manifest mismatch')
    manifest = digest.hexdigest()
    if action == 'attest':
        print(f'{identity} {manifest}')
    else:
        if identity != expected_identity or manifest != expected_manifest:
            raise OSError('source bundle changed')
        for item in sorted(files, key=lambda value: (value.count('/'), value), reverse=True):
            parent_parts, leaf = item.split('/')[:-1], item.split('/')[-1]
            parentfd = os.dup(fd)
            try:
                for part in parent_parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                    os.close(parentfd)
                    parentfd = child
                os.unlink(leaf, dir_fd=parentfd)
                os.fsync(parentfd)
            finally:
                os.close(parentfd)
        for directory in sorted(directories - {''}, key=lambda value: value.count('/'), reverse=True):
            parent_parts, leaf = directory.split('/')[:-1], directory.split('/')[-1]
            parentfd = os.dup(fd)
            try:
                for part in parent_parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                    os.close(parentfd)
                    parentfd = child
                os.rmdir(leaf, dir_fd=parentfd)
                os.fsync(parentfd)
            finally:
                os.close(parentfd)
        os.fsync(fd)
finally:
    os.close(fd)
if action == 'consume':
    parent, name = os.path.split(path)
    parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.rmdir(name, dir_fd=parentfd)
        os.fsync(parentfd)
    finally:
        os.close(parentfd)
PY_SOURCE_BUNDLE
}
source_bundle_attestation(){ source_bundle attest "$source" "$1"; }
consume_source(){ source_bundle consume "$source" "$source_operation" "$source_identity" "$source_manifest_sha"; }
source_path_identity(){
  python3 -I -B - "$1" <<'PY_SOURCE_PATH_IDENTITY'
import os, stat, sys
path = sys.argv[1]
parent, name = os.path.split(path)
parentfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError('source is not a directory')
        print(f'{info.st_dev}:{info.st_ino}')
    finally:
        os.close(fd)
finally:
    os.close(parentfd)
PY_SOURCE_PATH_IDENTITY
}
cleanup_bound_source(){
  bound_path=$1; bound_operation=$2; bound_identity=$3; bound_manifest=$4; bound_stage_path=$5
  bound_policy=${6:-consume}
  if [ ! -e "$bound_path" ] && [ ! -L "$bound_path" ]; then return 0; fi
  current_identity=$(source_path_identity "$bound_path" 2>/dev/null) || return 1
  [ "$current_identity" = "$bound_identity" ] || return 1
  current_attestation=
  if current_attestation=$(source_bundle attest "$bound_path" "$bound_operation"); then
    [ "$current_attestation" = "$bound_identity $bound_manifest" ] || return 1
    [ "$bound_policy" = preserve-intact ] && return 0
  fi
  [ "$bound_policy" = preserve-intact ] || [ "$bound_policy" = consume ] || return 1
  # Recovery must accept the trusted remaining subset after a SIGKILL in the
  # source-bundle unlink loop. The staged copy is the binding evidence.
  [ -n "$bound_stage_path" ] || return 1
  recover_bound_source "$bound_path" "$bound_identity" "$bound_stage_path" delete
}
recover_bound_source(){
  recover_source_path=$1; recover_source_identity=$2; recover_stage_path=$3
  recover_source_action=${4:-delete}
  python3 -I -B - "$recover_source_path" "$recover_source_identity" "$recover_stage_path" "$recover_source_action" 0 0 <<'PY_RECOVER_SOURCE'
import hashlib
import os
import stat
import sys

path, expected_identity, staged_path, action = sys.argv[1:5]
expected_uid, expected_gid = map(int, sys.argv[5:7])
if action not in {"validate", "delete"}:
    raise OSError("invalid recovery source action")
files = {
    "server.py", "openclash_web_helper.py", "openclash-sync-web.service", "auth-ha1",
    "router_a", "router_b", "known_hosts", "static/index.html", "static/app.css",
    "static/app.js", "static/OpenClash_Sync_Logo.png",
}
directories = {"static"}

def digest(fd):
    value = hashlib.sha256()
    while True:
        block = os.read(fd, 65536)
        if not block:
            return value.digest()
        value.update(block)

def open_relative(rootfd, parts):
    fd = os.dup(rootfd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

source_parent, source_name = os.path.split(path)
source_parentfd = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    try:
        sourcefd = os.open(source_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_parentfd)
    except FileNotFoundError:
        raise SystemExit(0)
    try:
        source_root = os.fstat(sourcefd)
        if f"{source_root.st_dev}:{source_root.st_ino}" != expected_identity:
            raise SystemExit(0)
        if source_root.st_uid != expected_uid or source_root.st_gid != expected_gid or stat.S_IMODE(source_root.st_mode) != 0o700:
            raise OSError("untrusted recovery source root")

        staged_parent, staged_name = os.path.split(staged_path)
        staged_parentfd = os.open(staged_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            stagedfd = os.open(staged_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=staged_parentfd)
            try:
                staged_root = os.fstat(stagedfd)
                if staged_root.st_uid != expected_uid or staged_root.st_gid != expected_gid or stat.S_IMODE(staged_root.st_mode) != 0o700:
                    raise OSError("untrusted recovery stage root")
                seen_files = set()
                seen_directories = set()

                def inspect(directoryfd, prefix=""):
                    for name in os.listdir(directoryfd):
                        relative = f"{prefix}/{name}" if prefix else name
                        info = os.stat(name, dir_fd=directoryfd, follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if relative not in directories or info.st_uid != expected_uid or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) != 0o700:
                                raise OSError("unexpected recovery source directory")
                            seen_directories.add(relative)
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directoryfd)
                            try:
                                inspect(child, relative)
                            finally:
                                os.close(child)
                        elif stat.S_ISREG(info.st_mode):
                            mode = stat.S_IMODE(info.st_mode)
                            if relative not in files or info.st_uid != expected_uid or info.st_gid != expected_gid or info.st_nlink != 1:
                                raise OSError("unexpected recovery source asset")
                            if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX | 0o022) or not 1 <= info.st_size <= 16 * 1024 * 1024:
                                raise OSError("untrusted recovery source metadata")
                            parts = relative.split("/")
                            left_parent = open_relative(sourcefd, parts[:-1])
                            right_parent = open_relative(stagedfd, parts[:-1])
                            try:
                                leftfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=left_parent)
                                rightfd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=right_parent)
                                try:
                                    left = os.fstat(leftfd)
                                    right = os.fstat(rightfd)
                                    if (left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_nlink) != (
                                        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, 1
                                    ):
                                        raise OSError("recovery source asset raced")
                                    if right.st_uid != expected_uid or right.st_gid != expected_gid or stat.S_IMODE(right.st_mode) != 0o600 or right.st_nlink != 1:
                                        raise OSError("untrusted recovery staged asset")
                                    if digest(leftfd) != digest(rightfd):
                                        raise OSError("recovery source differs from stage")
                                finally:
                                    os.close(leftfd)
                                    os.close(rightfd)
                            finally:
                                os.close(left_parent)
                                os.close(right_parent)
                            seen_files.add(relative)
                        else:
                            raise OSError("unexpected recovery source entry")

                inspect(sourcefd)
                if not seen_files.issubset(files) or not seen_directories.issubset(directories):
                    raise OSError("recovery source manifest mismatch")
                if action == "delete":
                    for relative in sorted(seen_files, key=lambda item: (item.count("/"), item), reverse=True):
                        parts = relative.split("/")
                        parentfd = open_relative(sourcefd, parts[:-1])
                        try:
                            os.unlink(parts[-1], dir_fd=parentfd)
                            os.fsync(parentfd)
                        finally:
                            os.close(parentfd)
                    for relative in sorted(seen_directories, key=lambda item: item.count("/"), reverse=True):
                        parts = relative.split("/")
                        parentfd = open_relative(sourcefd, parts[:-1])
                        try:
                            os.rmdir(parts[-1], dir_fd=parentfd)
                            os.fsync(parentfd)
                        finally:
                            os.close(parentfd)
                    os.fsync(sourcefd)
            finally:
                os.close(stagedfd)
        finally:
            os.close(staged_parentfd)
    finally:
        os.close(sourcefd)
    if action == "delete":
        os.rmdir(source_name, dir_fd=source_parentfd)
        os.fsync(source_parentfd)
finally:
    os.close(source_parentfd)
PY_RECOVER_SOURCE
}

atomic_publish(){
  source_file=$1 target_file=$2 target_mode=$3 target_uid=$4 target_gid=$5 expectation=$6 label=$7
  target_directory=${target_file%/*}
  [ -f "$source_file" ] && [ ! -L "$source_file" ] || return 30
  if [ "$expectation" = absent ]; then [ ! -e "$target_file" ] && [ ! -L "$target_file" ] || return 31; fi
  source_sha=$(sha "$source_file") || return 32
  temporary="$target_directory/.openclash-web-new-${transaction_id}-${label}"
  (umask 077; set -C; : >"$temporary") 2>/dev/null || return 33
  if ! cp "$source_file" "$temporary" || ! chown "$target_uid:$target_gid" "$temporary" ||
     ! chmod "$target_mode" "$temporary" || ! cmp -s "$source_file" "$temporary" ||
     ! fsync_file "$temporary" || [ "$(sha "$source_file")" != "$source_sha" ]; then
    rm -f "$temporary"; return 34
  fi
  if [ "$expectation" = absent ] && { [ -e "$target_file" ] || [ -L "$target_file" ]; }; then
    rm -f "$temporary"; return 35
  fi
  mv -f "$temporary" "$target_file" || { rm -f "$temporary"; return 36; }
  fsync_path "$target_file" || return 37
}

source=/tmp/openclash-sync-web-deploy
app=/opt/openclash-sync-web
shared_vendor=/opt/publisher-v4-openclash-worker/vendor/pyyaml-6.0.2
helper=/usr/local/sbin/openclash-web-helper
service=/etc/systemd/system/openclash-sync-web.service
sudoers=/etc/sudoers.d/openclash-sync-web
keys=/etc/openclash-web
transaction_root=/opt/openclash-sync-web-install-transactions
transaction_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
transaction=$transaction_root/install-$transaction_id
source_stage=$transaction/source
source_operation=install
source_identity=
source_manifest_sha=
source_stage_ready=false
target_mutation_started=false
service_mutation_started=false
committed=false
syncsvc_gid=

[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 0 ] || hold ARGS 10
for command in python3 sha256sum stat find grep awk sort mktemp cmp install systemctl systemd-analyze visudo ss ssh-keygen getent flock date; do
  command -v "$command" >/dev/null 2>&1 || hold TOOL 11
done
id syncsvc >/dev/null 2>&1 || hold SERVICE_USER 11
syncsvc_gid=$(id -g syncsvc)
shared_vendor_ok || hold SHARED_VENDOR 11
acquire_lifecycle_lock || hold LIFECYCLE_LOCK 12
trusted_directory /opt || hold TARGET_DIRECTORY_TRUST 12
ensure_lifecycle_root || hold LIFECYCLE_ROOT 12
cleanup_lifecycle_partials || { stop_service_for_recovery >/dev/null 2>&1 || true; hold LIFECYCLE_PARTIAL 12; }
recovery_status=0
recover_active || recovery_status=$?
case "$recovery_status" in
  0) ;;
  2)
    printf '%s\n' 'WORKER_WEB_RECOVERY=PASS' "OP=$active_op" "TRANSACTION=$active_tx" \
      'NEW_TRANSACTION_STARTED=false'
    exit 0
    ;;
  3) exit 0;;
  *) stop_service_for_recovery >/dev/null 2>&1 || true; hold RECOVERY 12;;
esac
pending_recovery_status=0
recover_pending || pending_recovery_status=$?
case "$pending_recovery_status" in
  0) ;;
  2)
    printf '%s\n' 'WORKER_WEB_RECOVERY=PASS' 'PHASE=PENDING' \
      'NEW_TRANSACTION_STARTED=false'
    exit 0
    ;;
  *) stop_service_for_recovery >/dev/null 2>&1 || true; hold PENDING_RECOVERY 12;;
esac
reject_unbound_target_partials || { stop_service_for_recovery >/dev/null 2>&1 || true; hold TARGET_PARTIAL_UNBOUND 12; }
for directory in /opt /usr/local/sbin /etc/systemd/system /etc/sudoers.d /etc; do
  trusted_directory "$directory" || hold TARGET_DIRECTORY_TRUST 11
done
for path in "$app" "$helper" "$service" "$sudoers" "$keys"; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || hold TARGET_EXISTS 11
done
id syncsvc >/dev/null 2>&1 || hold SERVICE_USER 11
syncsvc_gid=$(id -g syncsvc)
[ "$(getent group syncsvc | cut -d: -f3)" = "$syncsvc_gid" ] || hold SERVICE_GROUP 11
unit_state=$(systemctl show -p LoadState --value openclash-sync-web.service 2>/dev/null || true)
[ "$unit_state" = not-found ] || hold SERVICE_ALREADY_PRESENT 11
systemctl is-active --quiet openclash-sync-web.service && hold SERVICE_ALREADY_ACTIVE 11
systemctl is-enabled --quiet openclash-sync-web.service && hold SERVICE_ALREADY_ENABLED 11
ss -ltn | awk 'NR>1 {print $4}' | grep -q ':8088$' && hold PORT_IN_USE 11

if [ ! -e "$transaction_root" ] && [ ! -L "$transaction_root" ]; then
  install -d -m 0700 -o root -g root "$transaction_root" || hold TRANSACTION_ROOT_CREATE 12
  fsync_directory /opt || hold TRANSACTION_ROOT_FSYNC 12
fi
[ -d "$transaction_root" ] && [ ! -L "$transaction_root" ] &&
[ "$(stat -c '%a:%u:%g' "$transaction_root")" = '700:0:0' ] || hold TRANSACTION_ROOT_TRUST 12
[ ! -e "$transaction" ] && [ ! -L "$transaction" ] || hold TRANSACTION_EXISTS 12
source_attestation=$(source_bundle_attestation install) || hold SOURCE_TRUST 12
source_identity=${source_attestation%% *}
source_manifest_sha=${source_attestation#* }
source_identity_ok "$source_identity" && valid_digest "$source_manifest_sha" && [ "$source_identity $source_manifest_sha" = "$source_attestation" ] || hold SOURCE_IDENTITY 12
pending_payload=$(printf '%s\n' PENDING 'SCHEMA=openclash-sync-web-pending-v1' 'OP=install' "TXID=$transaction_id" \
  "TX_PATH=$transaction" "SOURCE_PATH=$source" "SOURCE_IDENTITY=$source_identity" \
  "SOURCE_MANIFEST_SHA256=$source_manifest_sha") || hold PENDING_BUILD 12
atomic_journal "$lifecycle_root/PENDING" "$pending_payload" || hold PENDING_FSYNC 12
pending_journal_ok "$lifecycle_root/PENDING" install "$transaction_id" "$transaction" || hold PENDING_SCHEMA 12
install -d -m 0700 -o root -g root "$transaction" "$source_stage" || hold TRANSACTION_CREATE 12
fsync_directory "$transaction_root" || hold TRANSACTION_FSYNC 12
source_stage_ready=true

cleanup_source_stage(){
  [ "$source_stage_ready" = true ] || return 0
  rm -f "$source_stage/server.py" "$source_stage/openclash_web_helper.py" \
    "$source_stage/openclash-sync-web.service" "$source_stage/auth-ha1" \
    "$source_stage/router_a" "$source_stage/router_b" "$source_stage/known_hosts" \
    "$source_stage/sudoers" "$source_stage/static/index.html" "$source_stage/static/app.css" \
    "$source_stage/static/app.js" "$source_stage/static/OpenClash_Sync_Logo.png" || return 1
  rmdir "$source_stage/static" 2>/dev/null || true
  rmdir "$source_stage" 2>/dev/null || return 1
  fsync_directory "$transaction" || return 1
  source_stage_ready=false
}
write_status(){
  status=$1
  partial=$transaction/.${status}.partial
  printf '%s\n' "STATUS=$status" "REASON=$failure_reason" >"$partial" || return 1
  chmod 0600 "$partial" || return 1
  fsync_file "$partial" || return 1
  mv -f "$partial" "$transaction/$status" || return 1
  fsync_directory "$transaction" || return 1
}
write_intent(){
  label=$1 source_file=$2
  partial=$transaction/.$label.after-sha.partial
  intended_sha=$(sha "$source_file") || return 1
  printf '%s\n' "$intended_sha" >"$partial" || return 1
  unset intended_sha
  chmod 0600 "$partial" || return 1
  fsync_file "$partial" || return 1
  mv -f "$partial" "$transaction/$label.after-sha" || return 1
  fsync_directory "$transaction" || return 1
}
remove_published(){
  target_file=$1 label=$2
  if [ ! -e "$target_file" ] && [ ! -L "$target_file" ]; then return 0; fi
  intended_file=$transaction/$label.after-sha
  [ -f "$intended_file" ] && [ ! -L "$intended_file" ] || return 1
  intended_sha=$(cat "$intended_file") || return 1
  case "$intended_sha" in *[!0-9a-f]*|'') return 1;; esac
  [ "${#intended_sha}" -eq 64 ] || return 1
  [ -f "$target_file" ] && [ ! -L "$target_file" ] &&
  [ "$(sha "$target_file" 2>/dev/null || true)" = "$intended_sha" ] || return 1
  rm -f "$target_file" || return 1
  fsync_directory "${target_file%/*}" || return 1
}
rollback(){
  set +e
  rollback_ok=true
  rollback_service_stopped=true
  if [ "$service_mutation_started" = true ]; then
    stop_service_for_recovery || { rollback_ok=false; rollback_service_stopped=false; }
  fi
  if [ "$rollback_service_stopped" = true ]; then
    cleanup_target_partials "$transaction" install delete || rollback_ok=false
    rm -f "$transaction/COMMITTED.partial" "$transaction/COMMITTED" 2>/dev/null || rollback_ok=false
    fsync_directory "$transaction" || rollback_ok=false
  fi
  if [ "$target_mutation_started" = true ] && [ "$rollback_ok" = true ]; then
    remove_published "$service" service || rollback_ok=false
    remove_published "$sudoers" sudoers || rollback_ok=false
    remove_published "$helper" helper || rollback_ok=false
    remove_published "$app/server.py" app-server.py || rollback_ok=false
    remove_published "$app/auth-ha1" app-auth-ha1 || rollback_ok=false
    remove_published "$app/static/index.html" static-index.html || rollback_ok=false
    remove_published "$app/static/app.css" static-app.css || rollback_ok=false
    remove_published "$app/static/app.js" static-app.js || rollback_ok=false
    remove_published "$app/static/OpenClash_Sync_Logo.png" static-logo.png || rollback_ok=false
    remove_published "$keys/keys/router_a" router-a || rollback_ok=false
    remove_published "$keys/keys/router_b" router-b || rollback_ok=false
    remove_published "$keys/known_hosts" known-hosts || rollback_ok=false
    rmdir "$app/static" "$app" "$keys/keys" "$keys" 2>/dev/null || rollback_ok=false
    fsync_directory /opt || rollback_ok=false
    fsync_directory /etc || rollback_ok=false
    service_install_baseline_ok || rollback_ok=false
  fi
  cleanup_bound_source "$source" install "$source_identity" "$source_manifest_sha" "$source_stage" || rollback_ok=false
  cleanup_source_stage || rollback_ok=false
  receipt_unavailable=false
  status=ABORTED
  [ "$target_mutation_started" = true ] && status=ROLLED_BACK
  if [ "$rollback_ok" = true ]; then
    write_status "$status" || receipt_unavailable=true
    if [ "$receipt_unavailable" = false ]; then
      clear_lifecycle || receipt_unavailable=true
    fi
  else
    systemctl disable --now openclash-sync-web.service >/dev/null 2>&1 || true
    rm -f "$transaction/ROLLED_BACK" "$transaction/ABORTED" 2>/dev/null || true
    write_status ROLLBACK_FAILED || receipt_unavailable=true
    status=ROLLBACK_FAILED
  fi
  printf '%s\n' "WORKER_WEB_INSTALL=$status" "TRANSACTION=$transaction" "RECEIPT_UNAVAILABLE=$receipt_unavailable"
}
finish(){
  exit_code=$?
  if [ "$committed" != true ] && { [ -e "$transaction/COMMITTED" ] || [ -L "$transaction/COMMITTED" ]; }; then
    # A published but untrusted receipt makes the commit decision unknown. Never roll back it.
    committed=true
  fi
  [ "$committed" = true ] || rollback
  exit "$exit_code"
}
trap finish EXIT
trap 'exit 128' HUP INT TERM

staged_source_identity=$(stage_source server.py openclash_web_helper.py openclash-sync-web.service auth-ha1 \
  router_a router_b known_hosts static/index.html static/app.css static/app.js \
  static/OpenClash_Sync_Logo.png) || hold SOURCE_TRUST 13
source_identity_ok "$staged_source_identity" && [ "$staged_source_identity" = "$source_identity" ] || hold SOURCE_IDENTITY 13
post_stage_attestation=$(source_bundle_attestation install) || hold SOURCE_DRIFT 13
[ "$post_stage_attestation" = "$source_identity $source_manifest_sha" ] || hold SOURCE_DRIFT 13
recover_bound_source "$source" "$source_identity" "$source_stage" validate || hold SOURCE_STAGE_DRIFT 13

python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$source_stage/server.py" "$source_stage/openclash_web_helper.py" || hold PYTHON_SYNTAX 14
converter_runtime_ok "$source_stage/server.py" "$source_stage/openclash_web_helper.py" >/dev/null 2>&1 || hold CONVERTER_RUNTIME 14
python3 -I -B - "$shared_vendor" <<'PY_PYYAML' || hold PYYAML 15
import pathlib, sys
vendor = pathlib.Path(sys.argv[1])
assert vendor.is_dir()
sys.path.insert(0, str(vendor))
import yaml
assert yaml.__version__ == "6.0.2"
PY_PYYAML
systemd-analyze verify "$source_stage/openclash-sync-web.service" >/dev/null 2>&1 || hold SERVICE_UNIT 16
auth_lines=$(wc -l <"$source_stage/auth-ha1" | tr -d ' ')
case "$auth_lines" in
  1) grep -Eq '^[0-9a-f]{64}$' "$source_stage/auth-ha1" || hold AUTH_HA1 17 ;;
  2) grep -Eq '^sha256:[0-9a-f]{64}$' "$source_stage/auth-ha1" &&
     grep -Eq '^md5:[0-9a-f]{32}$' "$source_stage/auth-ha1" || hold AUTH_HA1 17 ;;
  *) hold AUTH_HA1 17 ;;
esac
router_a_public=$(ssh-keygen -y -P '' -f "$source_stage/router_a" 2>/dev/null) || hold ROUTER_KEY 17
router_b_public=$(ssh-keygen -y -P '' -f "$source_stage/router_b" 2>/dev/null) || hold ROUTER_KEY 17
[ -n "$router_a_public" ] && [ -n "$router_b_public" ] &&
[ "$router_a_public" != "$router_b_public" ] || hold ROUTER_KEY_REUSE 17
unset router_a_public router_b_public
[ "$(wc -l <"$source_stage/known_hosts" | tr -d ' ')" -eq 2 ] || hold KNOWN_HOSTS 17
awk '
  NF != 3 || $2 != "ssh-ed25519" || $3 !~ /^[A-Za-z0-9+\/=]+$/ {exit 1}
  $1 == "192.0.2.10" {router_a++; next}
  $1 == "192.0.2.11" {router_b++; next}
  {exit 1}
  END {exit !(NR == 2 && router_a == 1 && router_b == 1)}
' "$source_stage/known_hosts" || hold KNOWN_HOSTS 17
[ "$(awk '{print $3}' "$source_stage/known_hosts" | sort -u | wc -l | tr -d ' ')" -eq 2 ] || hold KNOWN_HOST_REUSE 17
printf '%s\n' 'syncsvc ALL=(root) NOPASSWD: /usr/local/sbin/openclash-web-helper' >"$source_stage/sudoers"
chmod 0600 "$source_stage/sudoers"
fsync_path "$source_stage/sudoers" || hold SOURCE_FSYNC 17
visudo -cf "$source_stage/sudoers" >/dev/null || hold SUDOERS 18

write_intent app-server.py "$source_stage/server.py" || hold PUBLISH_INTENT 18
write_intent app-auth-ha1 "$source_stage/auth-ha1" || hold PUBLISH_INTENT 18
write_intent static-index.html "$source_stage/static/index.html" || hold PUBLISH_INTENT 18
write_intent static-app.css "$source_stage/static/app.css" || hold PUBLISH_INTENT 18
write_intent static-app.js "$source_stage/static/app.js" || hold PUBLISH_INTENT 18
write_intent static-logo.png "$source_stage/static/OpenClash_Sync_Logo.png" || hold PUBLISH_INTENT 18
write_intent helper "$source_stage/openclash_web_helper.py" || hold PUBLISH_INTENT 18
write_intent router-a "$source_stage/router_a" || hold PUBLISH_INTENT 18
write_intent router-b "$source_stage/router_b" || hold PUBLISH_INTENT 18
write_intent known-hosts "$source_stage/known_hosts" || hold PUBLISH_INTENT 18
write_intent service "$source_stage/openclash-sync-web.service" || hold PUBLISH_INTENT 18
write_intent sudoers "$source_stage/sudoers" || hold PUBLISH_INTENT 18
prepared_payload=$(printf '%s\n' PREPARED 'SCHEMA=openclash-sync-web-lifecycle-v1' 'OP=install' "TXID=$transaction_id" \
  'SERVICE_ENABLED_BEFORE=false' 'SERVICE_ACTIVE_BEFORE=false' "SOURCE_IDENTITY=$source_identity" \
  "SOURCE_MANIFEST_SHA256=$source_manifest_sha") || hold PREPARED_BUILD 18
atomic_journal "$transaction/PREPARED" "$prepared_payload" || hold PREPARED_FSYNC 18
prepared_journal_ok "$transaction/PREPARED" install "$transaction_id" || hold PREPARED_SCHEMA 18
active_payload=$(printf '%s\n' ACTIVE 'SCHEMA=openclash-sync-web-active-v1' 'OP=install' "TXID=$transaction_id" \
  "PREPARED=$transaction/PREPARED" "PENDING=$lifecycle_root/PENDING") || hold ACTIVE_BUILD 18
atomic_journal "$lifecycle_root/ACTIVE" "$active_payload" || hold ACTIVE_FSYNC 18
active_journal_ok "$lifecycle_root/ACTIVE" install "$transaction_id" "$transaction/PREPARED" || hold ACTIVE_SCHEMA 18

target_mutation_started=true
install -d -m 0755 -o root -g root "$app" "$app/static" || hold APP_DIRECTORY 19
install -d -m 0700 -o root -g root "$keys" "$keys/keys" || hold KEY_DIRECTORY 19
fsync_directory /opt || hold DIRECTORY_FSYNC 19
fsync_directory /etc || hold DIRECTORY_FSYNC 19
fsync_directory "$app" || hold DIRECTORY_FSYNC 19
fsync_directory "$keys" || hold DIRECTORY_FSYNC 19

atomic_publish "$source_stage/server.py" "$app/server.py" 0555 0 0 absent app-server.py || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/auth-ha1" "$app/auth-ha1" 0440 0 "$syncsvc_gid" absent app-auth-ha1 || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/static/index.html" "$app/static/index.html" 0444 0 0 absent static-index.html || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/static/app.css" "$app/static/app.css" 0444 0 0 absent static-app.css || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/static/app.js" "$app/static/app.js" 0444 0 0 absent static-app.js || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/static/OpenClash_Sync_Logo.png" "$app/static/OpenClash_Sync_Logo.png" 0444 0 0 absent static-logo.png || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/openclash_web_helper.py" "$helper" 0555 0 0 absent helper || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/router_a" "$keys/keys/router_a" 0600 0 0 absent router-a || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/router_b" "$keys/keys/router_b" 0600 0 0 absent router-b || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/known_hosts" "$keys/known_hosts" 0600 0 0 absent known-hosts || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/openclash-sync-web.service" "$service" 0644 0 0 absent service || hold ATOMIC_PUBLISH 20
atomic_publish "$source_stage/sudoers" "$sudoers" 0440 0 0 absent sudoers || hold ATOMIC_PUBLISH 20

[ "$(stat -c '%a:%u:%g' "$app")" = '755:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$app/static")" = '755:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$keys")" = '700:0:0' ] &&
[ "$(stat -c '%a:%u:%g' "$keys/keys")" = '700:0:0' ] || hold INSTALLED_DIRECTORY_MODE 21
installed_file_ok "$app/server.py" 555 0 0 && cmp -s "$source_stage/server.py" "$app/server.py" || hold INSTALLED_ASSET 21
installed_file_ok "$app/auth-ha1" 440 0 "$syncsvc_gid" && cmp -s "$source_stage/auth-ha1" "$app/auth-ha1" || hold INSTALLED_ASSET 21
installed_file_ok "$app/static/index.html" 444 0 0 && cmp -s "$source_stage/static/index.html" "$app/static/index.html" || hold INSTALLED_ASSET 21
installed_file_ok "$app/static/app.css" 444 0 0 && cmp -s "$source_stage/static/app.css" "$app/static/app.css" || hold INSTALLED_ASSET 21
installed_file_ok "$app/static/app.js" 444 0 0 && cmp -s "$source_stage/static/app.js" "$app/static/app.js" || hold INSTALLED_ASSET 21
installed_file_ok "$app/static/OpenClash_Sync_Logo.png" 444 0 0 && cmp -s "$source_stage/static/OpenClash_Sync_Logo.png" "$app/static/OpenClash_Sync_Logo.png" || hold INSTALLED_ASSET 21
installed_file_ok "$helper" 555 0 0 && cmp -s "$source_stage/openclash_web_helper.py" "$helper" || hold INSTALLED_ASSET 21
installed_file_ok "$keys/keys/router_a" 600 0 0 && cmp -s "$source_stage/router_a" "$keys/keys/router_a" || hold INSTALLED_ASSET 21
installed_file_ok "$keys/keys/router_b" 600 0 0 && cmp -s "$source_stage/router_b" "$keys/keys/router_b" || hold INSTALLED_ASSET 21
installed_file_ok "$keys/known_hosts" 600 0 0 && cmp -s "$source_stage/known_hosts" "$keys/known_hosts" || hold INSTALLED_ASSET 21
installed_file_ok "$service" 644 0 0 && cmp -s "$source_stage/openclash-sync-web.service" "$service" || hold INSTALLED_ASSET 21
installed_file_ok "$sudoers" 440 0 0 && cmp -s "$source_stage/sudoers" "$sudoers" || hold INSTALLED_ASSET 21
visudo -cf "$sudoers" >/dev/null || hold INSTALLED_SUDOERS 21
systemd-analyze verify "$service" >/dev/null 2>&1 || hold INSTALLED_SERVICE_UNIT 21
python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$app/server.py" "$helper" || hold INSTALLED_PYTHON_SYNTAX 21

service_mutation_started=true
systemctl daemon-reload || hold DAEMON_RELOAD 22
systemctl enable --now openclash-sync-web.service >/dev/null || hold SERVICE_START 22
systemctl is-enabled --quiet openclash-sync-web.service || hold SERVICE_ENABLE 22
systemctl is-active --quiet openclash-sync-web.service || hold SERVICE_START 22
attempt=0
healthy=false
while [ "$attempt" -lt 20 ]; do
  attempt=$((attempt+1))
  if service_after_ok && [ "$(service_listen_address)" = 192.0.2.20:8088 ]; then healthy=true; break; fi
  sleep 1
done
[ "$healthy" = true ] || hold HEALTH 22
service_listen_ok || hold LISTEN 22

consume_source || hold SOURCE_CLEANUP 23
cleanup_source_stage || hold STAGING_CLEANUP 23
: >"$transaction/COMMITTED.partial" || hold RECEIPT 24
printf '%s\n' 'COMMITTED' 'SCHEMA=openclash-sync-web-install-v5' 'SERVICE_ENABLED=true' 'SERVICE_ACTIVE=true' \
  >"$transaction/COMMITTED.partial" || hold RECEIPT 24
for label in app-server.py app-auth-ha1 static-index.html static-app.css static-app.js static-logo.png helper router-a router-b known-hosts service sudoers; do
  digest_file_ok "$transaction/$label.after-sha" || hold RECEIPT_DIGEST 24
  receipt_digest=$(cat "$transaction/$label.after-sha") || hold RECEIPT_DIGEST 24
  printf '%s_AFTER_SHA256=%s\n' "$label" "$receipt_digest" >>"$transaction/COMMITTED.partial" || hold RECEIPT 24
done
printf '%s\n' 'LISTEN=192.0.2.20:8088' 'FIREWALL_CHANGED=false' >>"$transaction/COMMITTED.partial" || hold RECEIPT 24
chmod 0600 "$transaction/COMMITTED.partial" || hold RECEIPT 24
install_committed_journal_ok "$transaction/COMMITTED.partial" "$transaction" || hold RECEIPT_SCHEMA 24
fsync_file "$transaction/COMMITTED.partial" || hold RECEIPT_FSYNC 24
mv -f "$transaction/COMMITTED.partial" "$transaction/COMMITTED" || hold RECEIPT 24
fsync_directory "$transaction" || hold RECEIPT_FSYNC 24
install_committed_journal_ok "$transaction/COMMITTED" "$transaction" || hold RECEIPT_SCHEMA 24
clear_lifecycle || hold LIFECYCLE_CLEANUP 24
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'WORKER_WEB_INSTALL=PASS' "TRANSACTION=$transaction" 'LISTEN=192.0.2.20:8088' \
  'SERVICE=ACTIVE' 'SERVICE_ENABLED=true' 'FIREWALL_CHANGED=false'
