#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'WORKER_ROLLBACK=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 1 ] || hold ARGS 11
deployment_id=$1
case "$deployment_id" in *[!0-9A-Z-]*|'') hold DEPLOYMENT_ID 11;; esac
[ "${#deployment_id}" -ge 8 ] && [ "${#deployment_id}" -le 48 ] || hold DEPLOYMENT_ID 11

root=/opt/publisher-v4-openclash-worker
backup=/opt/publisher-v4-openclash-worker-backups/publisher-v4-openclash-worker-contract-$deployment_id
auth=/home/syncsvc/.ssh/authorized_keys
contract=maying-converter-shape-contract.json
normalizer=maying_normalizer.py
reconciler=maying_converter_reconciler.py
worker=openclash_worker.py
vendor_version=pyyaml-6.0.2
vendor_rel=vendor/$vendor_version
vendor_files='LICENSE SOURCE.json yaml/__init__.py yaml/composer.py yaml/constructor.py yaml/cyaml.py yaml/dumper.py yaml/emitter.py yaml/error.py yaml/events.py yaml/loader.py yaml/nodes.py yaml/parser.py yaml/reader.py yaml/representer.py yaml/resolver.py yaml/scanner.py yaml/serializer.py yaml/tokens.py'

vendor_root_sha(){
  vendor_root=$1
  (
    cd "$vendor_root/$vendor_version" || exit 1
    for file in $vendor_files; do sha256sum "$file"; done
  ) | sha256sum | awk '{print $1}'
}
validate_vendor_root(){
  vendor_root=$1
  [ -d "$vendor_root" ] && [ ! -L "$vendor_root" ] && [ -d "$vendor_root/$vendor_version" ] && \
    [ ! -L "$vendor_root/$vendor_version" ] && [ -d "$vendor_root/$vendor_version/yaml" ] && \
    [ ! -L "$vendor_root/$vendor_version/yaml" ] || return 1
  [ "$(find "$vendor_root/$vendor_version" -type f | wc -l | tr -d ' ')" -eq 19 ] || return 1
  [ "$(find "$vendor_root/$vendor_version" -type l | wc -l | tr -d ' ')" -eq 0 ] || return 1
  for file in $vendor_files; do [ -f "$vendor_root/$vendor_version/$file" ] && [ ! -L "$vendor_root/$vendor_version/$file" ] || return 1; done
  /usr/bin/python3 -I -B -c 'import json,pathlib,sys; root=pathlib.Path(sys.argv[1]).resolve(); meta=json.load(open(root/"SOURCE.json",encoding="utf-8")); assert meta.get("version")=="6.0.2"; assert meta.get("source_sha256")=="d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e"; sys.path.insert(0,str(root)); import yaml; assert yaml.__version__=="6.0.2"; assert pathlib.Path(yaml.__file__).resolve().is_relative_to(root)' "$vendor_root/$vendor_version"
}
validate_vendor_tree(){ validate_vendor_root "$1/vendor"; }
vendor_tree_sha(){ vendor_root_sha "$1/vendor"; }

[ -d "$root" ] && [ ! -L "$root" ] || hold WORKER_ROOT 12
[ -d "$backup" ] && [ ! -L "$backup" ] || hold BACKUP 13
[ "$(stat -c '%a:%u:%g' "$backup")" = '700:0:0' ] || hold BACKUP_MODE 13
[ -f "$backup/COMMITTED" ] && [ ! -L "$backup/COMMITTED" ] || hold COMMITTED 13
[ "$(stat -c '%a:%u:%g' "$backup/COMMITTED")" = '600:0:0' ] || hold COMMITTED_MODE 13
[ ! -e "$backup/ROLLBACK-COMMITTED" ] || hold ALREADY_ROLLED_BACK 13
[ ! -e "$backup/rollback-current" ] || hold ROLLBACK_STATE_EXISTS 13
find "$root" "$backup" -xdev -type l | grep -q . && hold SYMLINK 14
(cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || hold BACKUP_HASH 15

receipt_value(){
  key=$1
  value=$(sed -n "s/^$key=//p" "$backup/COMMITTED")
  [ "$(printf '%s\n' "$value" | wc -l | tr -d ' ')" -eq 1 ] || return 1
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}
contract_before=$(receipt_value CONTRACT_PRESENT_BEFORE) || hold RECEIPT 16
case "$contract_before" in true|false) ;; *) hold RECEIPT 16;; esac
vendor_before=$(receipt_value VENDOR_PRESENT_BEFORE) || hold RECEIPT 16
case "$vendor_before" in true|false) ;; *) hold RECEIPT 16;; esac
vendor_expected=$(receipt_value VENDOR_TREE_SHA256) || hold RECEIPT 16
forced_expected=$(receipt_value FORCED_COMMAND_SHA256) || hold RECEIPT 16
anchor_expected=$(receipt_value SOURCE_ANCHOR_FILE_SHA256) || hold RECEIPT 16
policy_expected=$(receipt_value NORMALIZATION_POLICY_FILE_SHA256) || hold RECEIPT 16
auth_expected=$(receipt_value AUTHORIZED_KEYS_SHA256) || hold RECEIPT 16
for digest in "$forced_expected" "$anchor_expected" "$policy_expected" "$auth_expected" "$vendor_expected"; do
  case "$digest" in *[!0-9a-f]*|'') hold RECEIPT 16;; esac
  [ "${#digest}" -eq 64 ] || hold RECEIPT 16
done
validate_vendor_tree "$root" || hold CURRENT_VENDOR 17
[ "$(vendor_tree_sha "$root")" = "$vendor_expected" ] || hold CURRENT_VENDOR_DRIFT 17

for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
  label=$(printf '%s' "$file" | tr '[:lower:].-' '[:upper:]__')
  expected=$(receipt_value "${label}_AFTER_SHA256") || hold RECEIPT 16
  case "$expected" in *[!0-9a-f]*|'') hold RECEIPT 16;; esac
  [ "${#expected}" -eq 64 ] || hold RECEIPT 16
  [ -f "$root/$file" ] && [ ! -L "$root/$file" ] || hold CURRENT_ASSET 17
  [ "$(sha256sum "$root/$file" | awk '{print $1}')" = "$expected" ] || hold CURRENT_DRIFT 17
done
[ "$(sha256sum "$root/forced-command" | awk '{print $1}')" = "$forced_expected" ] || hold FORCED_COMMAND_DRIFT 17
[ "$(sha256sum "$root/source-host.sha256" | awk '{print $1}')" = "$anchor_expected" ] || hold SOURCE_ANCHOR_DRIFT 17
[ "$(sha256sum "$root/normalization-policy" | awk '{print $1}')" = "$policy_expected" ] || hold POLICY_DRIFT 17
[ "$(sha256sum "$auth" | awk '{print $1}')" = "$auth_expected" ] || hold AUTHORIZED_KEYS_DRIFT 17
current_backup=$backup/rollback-current
install -d -m 0700 -o root -g root "$current_backup"
for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
  install -m 0600 -o root -g root "$root/$file" "$current_backup/$file"
done
install -d -m 0700 -o root -g root "$current_backup/vendor" "$current_backup/$vendor_rel" "$current_backup/$vendor_rel/yaml"
for file in $vendor_files; do
  install -m 0600 -o root -g root "$root/$vendor_rel/$file" "$current_backup/$vendor_rel/$file"
done
(cd "$current_backup" && sha256sum "$contract" "$normalizer" "$reconciler" "$worker" >SHA256SUMS)
for file in $vendor_files; do
  (cd "$current_backup" && sha256sum "$vendor_rel/$file" >>SHA256SUMS)
done
chown root:root "$current_backup/SHA256SUMS"
chmod 0600 "$current_backup/SHA256SUMS"

atomic_install(){
  source_file=$1
  target_file=$2
  temporary=$target_file.rollback-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 31
  install -m 0444 -o root -g root "$source_file" "$temporary"
  mv -f "$temporary" "$target_file"
}
install_vendor_from(){
  source_vendor=$1
  target_base=$2
  validate_vendor_root "$source_vendor" || return 41
  [ ! -e "$target_base/vendor" ] && [ ! -L "$target_base/vendor" ] || return 42
  temporary=$target_base/vendor.rollback-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 43
  install -d -m 0555 -o root -g root "$temporary/$vendor_version" "$temporary/$vendor_version/yaml"
  chmod 0555 "$temporary" "$temporary/$vendor_version" "$temporary/$vendor_version/yaml"
  for file in $vendor_files; do
    install -m 0444 -o root -g root "$source_vendor/$vendor_version/$file" "$temporary/$vendor_version/$file"
  done
  validate_vendor_root "$temporary" || return 44
  [ "$(vendor_root_sha "$source_vendor")" = "$(vendor_root_sha "$temporary")" ] || return 45
  mv "$temporary" "$target_base/vendor"
}
remove_vendor(){
  base=$1
  validate_vendor_tree "$base" || return 46
  for file in $vendor_files; do rm -f "$base/$vendor_rel/$file" || return 47; done
  rmdir "$base/$vendor_rel/yaml" "$base/$vendor_rel" "$base/vendor" || return 48
}
cleanup_temporaries(){
  rm -f "$root/$normalizer.rollback-$deployment_id" "$root/$reconciler.rollback-$deployment_id" \
    "$root/$contract.rollback-$deployment_id" "$root/$worker.rollback-$deployment_id"
  if [ -d "$root/vendor.rollback-$deployment_id" ] && [ ! -L "$root/vendor.rollback-$deployment_id" ]; then
    for file in $vendor_files; do rm -f "$root/vendor.rollback-$deployment_id/$vendor_version/$file"; done
    rmdir "$root/vendor.rollback-$deployment_id/$vendor_version/yaml" \
      "$root/vendor.rollback-$deployment_id/$vendor_version" "$root/vendor.rollback-$deployment_id" \
      2>/dev/null || true
  fi
}
restore_updated(){
  set +e
  restore_ok=true
  cleanup_temporaries
  if [ ! -e "$root/vendor" ]; then
    install_vendor_from "$current_backup/vendor" "$root" || restore_ok=false
  fi
  atomic_install "$current_backup/$normalizer" "$root/$normalizer" || restore_ok=false
  atomic_install "$current_backup/$reconciler" "$root/$reconciler" || restore_ok=false
  atomic_install "$current_backup/$contract" "$root/$contract" || restore_ok=false
  atomic_install "$current_backup/$worker" "$root/$worker" || restore_ok=false
  (cd "$current_backup" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || restore_ok=false
  validate_vendor_tree "$root" || restore_ok=false
  [ "$(vendor_tree_sha "$root" 2>/dev/null)" = "$(vendor_root_sha "$current_backup/vendor" 2>/dev/null)" ] || restore_ok=false
  marker=ROLLBACK_RECOVERY_FAILED
  [ "$restore_ok" = true ] && marker=ROLLBACK_RECOVERED_TO_UPDATED
  printf '%s\n' "$marker" >"$backup/$marker"
  chown root:root "$backup/$marker"
  chmod 0600 "$backup/$marker"
  printf 'WORKER_ROLLBACK=%s\n' "$marker"
}
committed=false
finish(){ [ "$committed" = true ] || restore_updated; }
trap finish EXIT
trap 'exit 128' HUP INT TERM

# Roll back the Worker first. The old Worker ignores the still-present contract
# and is compatible with both receipt versions while dependencies are restored.
atomic_install "$backup/$worker.before" "$root/$worker" || hold ATOMIC_WORKER 30
atomic_install "$backup/$normalizer.before" "$root/$normalizer" || hold ATOMIC_NORMALIZER 30
atomic_install "$backup/$reconciler.before" "$root/$reconciler" || hold ATOMIC_RECONCILER 30
if [ "$contract_before" = true ]; then
  atomic_install "$backup/$contract.before" "$root/$contract" || hold ATOMIC_CONTRACT 30
else
  rm -f "$root/$contract" || hold CONTRACT_REMOVE 30
fi
if [ "$vendor_before" = false ]; then
  remove_vendor "$root" || hold VENDOR_REMOVE 30
fi

for file in "$normalizer" "$reconciler" "$worker"; do
  [ "$(sha256sum "$root/$file" | awk '{print $1}')" = "$(sha256sum "$backup/$file.before" | awk '{print $1}')" ] || hold RESTORE_HASH 31
  [ "$(stat -c '%a:%u:%g' "$root/$file")" = '444:0:0' ] || hold RESTORE_MODE 31
done
if [ "$contract_before" = true ]; then
  [ "$(sha256sum "$root/$contract" | awk '{print $1}')" = "$(sha256sum "$backup/$contract.before" | awk '{print $1}')" ] || hold RESTORE_HASH 31
else
  [ ! -e "$root/$contract" ] || hold RESTORE_CONTRACT 31
fi
if [ "$vendor_before" = false ]; then
  [ ! -e "$root/vendor" ] || hold RESTORE_VENDOR 31
else
  validate_vendor_tree "$root" || hold RESTORE_VENDOR 31
  [ "$(vendor_tree_sha "$root")" = "$vendor_expected" ] || hold RESTORE_VENDOR 31
fi
[ "$(sha256sum "$root/forced-command" | awk '{print $1}')" = "$forced_expected" ] || hold FORCED_COMMAND_DRIFT 32
[ "$(sha256sum "$root/source-host.sha256" | awk '{print $1}')" = "$anchor_expected" ] || hold SOURCE_ANCHOR_DRIFT 32
[ "$(sha256sum "$root/normalization-policy" | awk '{print $1}')" = "$policy_expected" ] || hold POLICY_DRIFT 32
[ "$(sha256sum "$auth" | awk '{print $1}')" = "$auth_expected" ] || hold AUTHORIZED_KEYS_DRIFT 32
/usr/bin/python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$root/$normalizer" "$root/$reconciler" "$root/$worker" || hold RESTORE_SYNTAX 33
find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 33
find "$root" -xdev -type d -name __pycache__ | grep -q . && hold PYTHON_CACHE 33

printf '%s\n' 'ROLLBACK-COMMITTED' "DEPLOYMENT_ID=$deployment_id" "CONTRACT_PRESENT_AFTER=$contract_before" \
  "VENDOR_PRESENT_AFTER=$vendor_before" \
  'FORCED_COMMAND_CHANGED=false' 'AUTHORIZED_KEYS_CHANGED=false' 'SOURCE_ANCHOR_CHANGED=false' \
  'NORMALIZATION_POLICY_CHANGED=false' 'SERVICE_RESTARTED=false' >"$backup/ROLLBACK-COMMITTED"
chown root:root "$backup/ROLLBACK-COMMITTED"
chmod 0600 "$backup/ROLLBACK-COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'WORKER_ROLLBACK=PASS' "DEPLOYMENT_ID=$deployment_id" "CONTRACT_PRESENT_AFTER=$contract_before" \
  "VENDOR_PRESENT_AFTER=$vendor_before" 'UPDATED_STATE_BACKED_UP=true' 'FORCED_COMMAND_CHANGED=false' 'AUTHORIZED_KEYS_CHANGED=false' \
  'SOURCE_ANCHOR_CHANGED=false' 'NORMALIZATION_POLICY_CHANGED=false' 'SERVICE_RESTARTED=false'
