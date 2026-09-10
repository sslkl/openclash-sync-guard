#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

hold(){ printf 'WORKER_UPDATE=HOLD\nREASON=%s\n' "$1"; exit "${2:-1}"; }
[ "$(id -u)" -eq 0 ] || hold ROOT 10
[ "$#" -eq 2 ] || hold ARGS 11
source_dir=$1
deployment_id=$2
case "$source_dir" in /*) ;; *) hold SOURCE_DIR 12;; esac
case "$deployment_id" in *[!0-9A-Z-]*|'') hold DEPLOYMENT_ID 12;; esac
[ "${#deployment_id}" -ge 8 ] && [ "${#deployment_id}" -le 48 ] || hold DEPLOYMENT_ID 12
[ -d "$source_dir" ] && [ ! -L "$source_dir" ] || hold SOURCE_DIR 12
[ "$(stat -c '%u:%g' "$source_dir")" = '0:0' ] || hold SOURCE_DIR_OWNER 12
find "$source_dir" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && hold SOURCE_DIR_WRITABLE 12

root=/opt/publisher-v4-openclash-worker
backup_root=/opt/publisher-v4-openclash-worker-backups
backup=$backup_root/publisher-v4-openclash-worker-contract-$deployment_id
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

for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
  [ -f "$source_dir/$file" ] && [ ! -L "$source_dir/$file" ] || hold SOURCE_ASSET 13
  [ "$(stat -c '%u:%g' "$source_dir/$file")" = '0:0' ] || hold SOURCE_OWNER 13
  find "$source_dir/$file" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && hold SOURCE_WRITABLE 13
done
validate_vendor_tree "$source_dir" || hold SOURCE_VENDOR 13
for path in "$source_dir/vendor" "$source_dir/$vendor_rel" "$source_dir/$vendor_rel/yaml"; do
  [ "$(stat -c '%u:%g' "$path")" = '0:0' ] || hold SOURCE_OWNER 13
  find "$path" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && hold SOURCE_WRITABLE 13
done
for file in $vendor_files; do
  path=$source_dir/$vendor_rel/$file
  [ "$(stat -c '%u:%g' "$path")" = '0:0' ] || hold SOURCE_OWNER 13
  find "$path" -maxdepth 0 \( -perm -0020 -o -perm -0002 \) | grep -q . && hold SOURCE_WRITABLE 13
done
[ -d "$root" ] && [ ! -L "$root" ] || hold WORKER_ROOT 14
[ "$(stat -c '%a:%u:%g' "$root")" = '755:0:0' ] || hold WORKER_ROOT_MODE 14
find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 15
for file in "$normalizer" "$reconciler" "$worker" source-host.sha256 normalization-policy; do
  [ -f "$root/$file" ] && [ ! -L "$root/$file" ] || hold INSTALLED_ASSET 16
  [ "$(stat -c '%a:%u:%g' "$root/$file")" = '444:0:0' ] || hold INSTALLED_MODE 16
done
[ -f "$root/forced-command" ] && [ ! -L "$root/forced-command" ] || hold INSTALLED_ASSET 16
[ "$(stat -c '%a:%u:%g' "$root/forced-command")" = '555:0:0' ] || hold INSTALLED_MODE 16
[ -f "$auth" ] && [ ! -L "$auth" ] || hold AUTHORIZED_KEYS 17
contract_before=false
if [ -e "$root/$contract" ]; then
  [ -f "$root/$contract" ] && [ ! -L "$root/$contract" ] || hold INSTALLED_CONTRACT 17
  [ "$(stat -c '%a:%u:%g' "$root/$contract")" = '444:0:0' ] || hold INSTALLED_MODE 17
  contract_before=true
fi
vendor_before=false
if [ -e "$root/vendor" ]; then
  validate_vendor_tree "$root" || hold INSTALLED_VENDOR 17
  vendor_before=true
fi

/usr/bin/python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$source_dir/$normalizer" "$source_dir/$reconciler" "$source_dir/$worker" || hold SOURCE_SYNTAX 18
/usr/bin/python3 -I -B -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); assert value.get("schema")=="publisher-v4-maying-converter-shape-contract-v2"; assert value.get("allowed_top_level_keys")==["allow-lan","external-controller","log-level","mode","port","proxies","proxy-groups","rules","socks-port"]' \
  "$source_dir/$contract" || hold SOURCE_CONTRACT 18

[ ! -L "$backup_root" ] || hold BACKUP_ROOT 19
if [ ! -e "$backup_root" ]; then
  install -d -m 0700 -o root -g root "$backup_root"
fi
[ -d "$backup_root" ] || hold BACKUP_ROOT 19
[ ! -e "$backup" ] && [ ! -L "$backup" ] || hold BACKUP_EXISTS 19
[ "$(stat -c '%a:%u:%g' "$backup_root")" = '700:0:0' ] || hold BACKUP_ROOT_MODE 19
install -d -m 0700 -o root -g root "$backup"

for file in "$normalizer" "$reconciler" "$worker"; do
  install -m 0600 -o root -g root "$root/$file" "$backup/$file.before"
done
if [ "$contract_before" = true ]; then
  install -m 0600 -o root -g root "$root/$contract" "$backup/$contract.before"
  contract_before=true
fi
(cd "$backup" && sha256sum "$normalizer.before" "$reconciler.before" "$worker.before" >SHA256SUMS.before)
if [ "$contract_before" = true ]; then
  (cd "$backup" && sha256sum "$contract.before" >>SHA256SUMS.before)
fi
chown root:root "$backup/SHA256SUMS.before"
chmod 0600 "$backup/SHA256SUMS.before"

forced_before=$(sha256sum "$root/forced-command" | awk '{print $1}')
anchor_before=$(sha256sum "$root/source-host.sha256" | awk '{print $1}')
policy_before=$(sha256sum "$root/normalization-policy" | awk '{print $1}')
auth_before=$(sha256sum "$auth" | awk '{print $1}')

atomic_install(){
  source_file=$1
  target_file=$2
  temporary=$target_file.update-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 31
  install -m 0444 -o root -g root "$source_file" "$temporary"
  mv -f "$temporary" "$target_file"
}
install_vendor(){
  source_base=$1
  target_base=$2
  [ ! -e "$target_base/vendor" ] && [ ! -L "$target_base/vendor" ] || return 41
  temporary=$target_base/vendor.update-$deployment_id
  [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 42
  install -d -m 0555 -o root -g root "$temporary/$vendor_version" "$temporary/$vendor_version/yaml"
  chmod 0555 "$temporary" "$temporary/$vendor_version" "$temporary/$vendor_version/yaml"
  for file in $vendor_files; do
    install -m 0444 -o root -g root "$source_base/$vendor_rel/$file" "$temporary/$vendor_version/$file"
  done
  validate_vendor_root "$temporary" || return 43
  [ "$(vendor_tree_sha "$source_base")" = "$(vendor_root_sha "$temporary")" ] || return 44
  mv "$temporary" "$target_base/vendor"
}
remove_vendor(){
  base=$1
  validate_vendor_tree "$base" || return 45
  for file in $vendor_files; do rm -f "$base/$vendor_rel/$file" || return 46; done
  rmdir "$base/$vendor_rel/yaml" "$base/$vendor_rel" "$base/vendor" || return 47
}
staging=$root/.contract-update-$deployment_id
cleanup_temporaries(){
  rm -f "$root/$normalizer.update-$deployment_id" "$root/$reconciler.update-$deployment_id" \
    "$root/$contract.update-$deployment_id" "$root/$worker.update-$deployment_id"
  if [ -d "$root/vendor.update-$deployment_id" ] && [ ! -L "$root/vendor.update-$deployment_id" ]; then
    for file in $vendor_files; do rm -f "$root/vendor.update-$deployment_id/$vendor_version/$file"; done
    rmdir "$root/vendor.update-$deployment_id/$vendor_version/yaml" \
      "$root/vendor.update-$deployment_id/$vendor_version" \
      "$root/vendor.update-$deployment_id" 2>/dev/null || true
  fi
  if [ -d "$staging" ] && [ ! -L "$staging" ]; then
    rm -f "$staging/$contract" "$staging/$normalizer" "$staging/$reconciler" "$staging/$worker"
    for file in $vendor_files; do rm -f "$staging/$vendor_rel/$file"; done
    rmdir "$staging/$vendor_rel/yaml" "$staging/$vendor_rel" "$staging/vendor" 2>/dev/null || true
    rmdir "$staging" 2>/dev/null || true
  fi
}
rollback(){
  set +e
  rollback_ok=true
  cleanup_temporaries
  atomic_install "$backup/$worker.before" "$root/$worker" || rollback_ok=false
  atomic_install "$backup/$normalizer.before" "$root/$normalizer" || rollback_ok=false
  atomic_install "$backup/$reconciler.before" "$root/$reconciler" || rollback_ok=false
  if [ "$contract_before" = true ]; then
    atomic_install "$backup/$contract.before" "$root/$contract" || rollback_ok=false
  else
    rm -f "$root/$contract" || rollback_ok=false
  fi
  if [ "$vendor_before" = false ] && [ -e "$root/vendor" ]; then
    remove_vendor "$root" || rollback_ok=false
  fi
  (cd "$backup" && sha256sum -c SHA256SUMS.before >/dev/null 2>&1) || rollback_ok=false
  for file in "$normalizer" "$reconciler" "$worker"; do
    [ "$(sha256sum "$root/$file" 2>/dev/null | awk '{print $1}')" = "$(sha256sum "$backup/$file.before" | awk '{print $1}')" ] || rollback_ok=false
  done
  [ "$(sha256sum "$root/forced-command" 2>/dev/null | awk '{print $1}')" = "$forced_before" ] || rollback_ok=false
  [ "$(sha256sum "$root/source-host.sha256" 2>/dev/null | awk '{print $1}')" = "$anchor_before" ] || rollback_ok=false
  [ "$(sha256sum "$root/normalization-policy" 2>/dev/null | awk '{print $1}')" = "$policy_before" ] || rollback_ok=false
  [ "$(sha256sum "$auth" 2>/dev/null | awk '{print $1}')" = "$auth_before" ] || rollback_ok=false
  if [ "$contract_before" = true ]; then
    [ "$(sha256sum "$root/$contract" 2>/dev/null | awk '{print $1}')" = "$(sha256sum "$backup/$contract.before" | awk '{print $1}')" ] || rollback_ok=false
  else
    [ ! -e "$root/$contract" ] || rollback_ok=false
  fi
  if [ "$vendor_before" = false ]; then
    [ ! -e "$root/vendor" ] || rollback_ok=false
  else
    validate_vendor_tree "$root" || rollback_ok=false
  fi
  marker=ROLLBACK_FAILED
  [ "$rollback_ok" = true ] && marker=ROLLED_BACK
  printf '%s\n' "$marker" >"$backup/$marker"
  chown root:root "$backup/$marker"
  chmod 0600 "$backup/$marker"
  printf 'WORKER_UPDATE=%s\n' "$marker"
}
committed=false
finish(){ [ "$committed" = true ] || rollback; }
trap finish EXIT
trap 'exit 128' HUP INT TERM

[ ! -e "$staging" ] && [ ! -L "$staging" ] || hold STAGING_EXISTS 29
install -d -m 0700 -o root -g root "$staging"
for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
  install -m 0400 -o root -g root "$source_dir/$file" "$staging/$file"
  [ "$(sha256sum "$staging/$file" | awk '{print $1}')" = "$(sha256sum "$source_dir/$file" | awk '{print $1}')" ] || hold STAGING_HASH 29
done
install -d -m 0500 -o root -g root "$staging/vendor" "$staging/$vendor_rel" "$staging/$vendor_rel/yaml"
for file in $vendor_files; do
  install -m 0400 -o root -g root "$source_dir/$vendor_rel/$file" "$staging/$vendor_rel/$file"
done
validate_vendor_tree "$staging" || hold STAGING_VENDOR 29
[ "$(vendor_tree_sha "$staging")" = "$(vendor_tree_sha "$source_dir")" ] || hold STAGING_VENDOR_HASH 29
/usr/bin/python3 -I -B -c 'import ast,sys; [ast.parse(open(path,"rb").read(),filename=path) for path in sys.argv[1:]]' \
  "$staging/$normalizer" "$staging/$reconciler" "$staging/$worker" || hold STAGING_SYNTAX 29
/usr/bin/python3 -I -B -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); assert value.get("schema")=="publisher-v4-maying-converter-shape-contract-v2"' \
  "$staging/$contract" || hold STAGING_CONTRACT 29

# Compatibility order: old Worker tolerates the new receipts and ignores the
# contract and vendor, so dependencies and contract are published before the new Worker.
if [ "$vendor_before" = false ]; then
  install_vendor "$staging" "$root" || hold ATOMIC_VENDOR 30
else
  [ "$(vendor_tree_sha "$root")" = "$(vendor_tree_sha "$staging")" ] || hold INSTALLED_VENDOR_DRIFT 30
fi
atomic_install "$staging/$normalizer" "$root/$normalizer" || hold ATOMIC_NORMALIZER 30
atomic_install "$staging/$reconciler" "$root/$reconciler" || hold ATOMIC_RECONCILER 30
atomic_install "$staging/$contract" "$root/$contract" || hold ATOMIC_CONTRACT 30
atomic_install "$staging/$worker" "$root/$worker" || hold ATOMIC_WORKER 30

for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
  [ "$(stat -c '%a:%u:%g' "$root/$file")" = '444:0:0' ] || hold UPDATED_MODE 31
  [ "$(sha256sum "$root/$file" | awk '{print $1}')" = "$(sha256sum "$staging/$file" | awk '{print $1}')" ] || hold UPDATED_HASH 31
done
validate_vendor_tree "$root" || hold UPDATED_VENDOR 31
[ "$(vendor_tree_sha "$root")" = "$(vendor_tree_sha "$staging")" ] || hold UPDATED_VENDOR_HASH 31
for path in "$root/vendor" "$root/$vendor_rel" "$root/$vendor_rel/yaml"; do
  [ "$(stat -c '%a:%u:%g' "$path")" = '555:0:0' ] || hold UPDATED_VENDOR_MODE 31
done
for file in $vendor_files; do
  [ "$(stat -c '%a:%u:%g' "$root/$vendor_rel/$file")" = '444:0:0' ] || hold UPDATED_VENDOR_MODE 31
done
[ "$(sha256sum "$root/forced-command" | awk '{print $1}')" = "$forced_before" ] || hold FORCED_COMMAND_DRIFT 32
[ "$(sha256sum "$root/source-host.sha256" | awk '{print $1}')" = "$anchor_before" ] || hold SOURCE_ANCHOR_DRIFT 32
[ "$(sha256sum "$root/normalization-policy" | awk '{print $1}')" = "$policy_before" ] || hold POLICY_DRIFT 32
[ "$(sha256sum "$auth" | awk '{print $1}')" = "$auth_before" ] || hold AUTHORIZED_KEYS_DRIFT 32
find "$root" -xdev -type l | grep -q . && hold WORKER_SYMLINK 33
find "$root" -xdev -type d -name __pycache__ | grep -q . && hold PYTHON_CACHE 33
cleanup_temporaries
[ ! -e "$staging" ] || hold STAGING_CLEANUP 33

{
  printf '%s\n' 'COMMITTED' "DEPLOYMENT_ID=$deployment_id" "CONTRACT_PRESENT_BEFORE=$contract_before" \
    "VENDOR_PRESENT_BEFORE=$vendor_before" "VENDOR_TREE_SHA256=$(vendor_tree_sha "$root")" 'VENDORED_PYYAML_VERSION=6.0.2'
  for file in "$contract" "$normalizer" "$reconciler" "$worker"; do
    label=$(printf '%s' "$file" | tr '[:lower:].-' '[:upper:]__')
    printf '%s_AFTER_SHA256=%s\n' "$label" "$(sha256sum "$root/$file" | awk '{print $1}')"
  done
  printf '%s\n' "FORCED_COMMAND_SHA256=$forced_before" "SOURCE_ANCHOR_FILE_SHA256=$anchor_before" \
    "NORMALIZATION_POLICY_FILE_SHA256=$policy_before" "AUTHORIZED_KEYS_SHA256=$auth_before" \
    'FORCED_COMMAND_CHANGED=false' 'AUTHORIZED_KEYS_CHANGED=false' 'SOURCE_ANCHOR_CHANGED=false' \
    'NORMALIZATION_POLICY_CHANGED=false' 'SERVICE_RESTARTED=false'
} >"$backup/COMMITTED"
chown root:root "$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
committed=true
trap - EXIT HUP INT TERM
printf '%s\n' 'WORKER_UPDATE=PASS' "DEPLOYMENT_ID=$deployment_id" "CONTRACT_PRESENT_BEFORE=$contract_before" \
  "VENDOR_PRESENT_BEFORE=$vendor_before" 'CONTRACT_INSTALLED=true' 'VENDORED_PYYAML=6.0.2' \
  'WORKER_PUBLISHED_LAST=true' 'FORCED_COMMAND_CHANGED=false' \
  'AUTHORIZED_KEYS_CHANGED=false' 'SOURCE_ANCHOR_CHANGED=false' 'NORMALIZATION_POLICY_CHANGED=false' \
  'SERVICE_RESTARTED=false'
