#!/usr/bin/env python3
"""Build/install immutable converter releases. Standard library, no credentials.

Build on the Mac in a project work directory. Install on WORKER as root before
updating the web app. A release is inactive until the guarded app/helper update
selects its exact digest. Old/incomplete releases are retained, never executed
or deleted by this program. No service, Docker, network, or shell commands.
"""
from __future__ import annotations
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

FILES = tuple(sorted(('subscription_converter.py', 'converter_apply.py', 'converter_engine.py',
    'converter_fetch.py', 'converter_formats.py', 'converter_mellow.py', 'converter_services.py', 'converter_sandbox.py', 'converter_surge.py',
    'static/converter.js', 'static/converter_apply.js', 'static/converter_services.js')))
LIMIT = 2 * 1024 * 1024
PRODUCTION_ROOT = Path('/opt/openclash-sync-converter')


class BundleError(ValueError):
    pass


def read_file(root: Path, name: str, *, owner=None, mode=None) -> bytes:
    """Descriptor-relative, no symlink traversal; reject hardlinks and drift."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= LIMIT:
                raise BundleError('invalid source file')
            if owner is not None and (before.st_uid, before.st_gid) != owner:
                raise BundleError('invalid owner')
            if mode is not None and stat.S_IMODE(before.st_mode) != mode:
                raise BundleError('invalid mode')
            data = b''
            while len(data) <= LIMIT:
                block = os.read(fd, min(65536, LIMIT + 1 - len(data)))
                if not block: break
                data += block
            after = os.fstat(fd); named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_mode, x.st_uid, x.st_gid, x.st_nlink)
            if identity(before) != identity(after) or identity(after) != identity(named) or len(data) != before.st_size:
                raise BundleError('source drift')
            return data
        finally: os.close(fd)
    finally: os.close(directory)


def canonical(files):
    if set(files) != set(FILES) or sum(map(len, files.values())) > LIMIT:
        raise BundleError('invalid file set or budget')
    return ''.join(f'{hashlib.sha256(files[name]).hexdigest()}  {name}\n' for name in FILES).encode()


def identity(files):
    return hashlib.sha256(canonical(files)).hexdigest()


def syntax(files):
    for name, body in files.items():
        body.decode('utf-8')
        if b'\0' in body: raise BundleError('invalid content')
        if name.endswith('.py'): ast.parse(body, filename=name)


def source_files(root):
    root = Path(root).absolute()
    files = {name: read_file(root, name) for name in FILES}
    canonical(files); syntax(files)
    return files


def directory_chain(root, owner):
    current = root
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != owner or info.st_mode & 0o022:
            raise BundleError('untrusted directory chain')
        if current.parent == current: return
        current = current.parent


def verify(root, expected, *, owner=None, immutable=True):
    root = Path(root).absolute()
    if not re.fullmatch(r'[0-9a-f]{64}', expected): raise BundleError('invalid release id')
    seen = set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        path = Path(directory); info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or (immutable and stat.S_IMODE(info.st_mode) != 0o555):
            raise BundleError('invalid release directory')
        if owner is not None and (info.st_uid, info.st_gid) != owner: raise BundleError('invalid directory owner')
        for child in dirs:
            if (path / child).relative_to(root).as_posix() != 'static': raise BundleError('unexpected directory')
            if (path / child).is_symlink(): raise BundleError('symlink directory')
        seen.update((path / name).relative_to(root).as_posix() for name in names)
    if seen != set(FILES) | {'SHA256SUMS'}: raise BundleError('unexpected release files')
    files = {name: read_file(root, name, owner=owner, mode=0o444 if immutable else None) for name in FILES}
    manifest = read_file(root, 'SHA256SUMS', owner=owner, mode=0o444 if immutable else None)
    if manifest != canonical(files) or hashlib.sha256(manifest).hexdigest() != expected:
        raise BundleError('release digest mismatch')
    syntax(files)
    return files


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def make_public_directory(path, *, owner=None):
    """Set an already trusted code directory to 0755 despite a restrictive umask."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd); named = Path(path).lstat()
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
        if not stat.S_ISDIR(info.st_mode) or fields(info) != fields(named) or info.st_mode & 0o022:
            raise BundleError('untrusted public directory')
        if owner is not None and (info.st_uid, info.st_gid) != owner:
            raise BundleError('invalid public directory owner')
        os.fchmod(fd, 0o755); os.fsync(fd)
    finally:
        os.close(fd)


def publish(files, destination, *, production=False):
    root = Path(destination).absolute(); digest = identity(files)
    if production:
        if os.geteuid() != 0 or root != PRODUCTION_ROOT: raise BundleError('root-only fixed production destination')
        directory_chain(root.parent, (0, 0))
    created = False
    if not root.exists():
        try:
            root.mkdir(mode=0o755); created = True
        except FileExistsError: pass
        fsync_dir(root.parent)
    if root.is_symlink() or not root.is_dir(): raise BundleError('invalid destination')
    if production: directory_chain(root, (0, 0))
    # mkdir's mode is masked by umask (the production transport uses 0077).
    # Existing local private staging roots retain their caller-selected mode.
    if created or production:
        make_public_directory(root, owner=(0, 0) if production else None)
    canonical(files); syntax(files)
    lock = root / '.publish.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise BundleError('untrusted publication lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        named = lock.lstat()
        if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
            raise BundleError('publication lock changed')
        return publish_locked(files, root, digest, production=production)
    finally:
        os.close(fd)


def publish_locked(files, root, digest, *, production):
    final = root / digest
    if final.exists() or final.is_symlink():
        verify(final, digest, owner=(0, 0) if production else None)
        return final
    # Never overwrite an existing candidate. It is private and not referenced by
    # any app/helper. An interrupted candidate may safely remain for later audit.
    candidate = root / ('.candidate-' + secrets.token_hex(12))
    candidate.mkdir(mode=0o700)
    (candidate / 'static').mkdir(mode=0o700)
    for name, body in dict(files, SHA256SUMS=canonical(files)).items():
        fd = os.open(candidate / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(body); output.flush(); os.fsync(fd)
            os.fchmod(fd, 0o444); os.fsync(fd)
        finally: os.close(fd)
    (candidate / 'static').chmod(0o555); fsync_dir(candidate / 'static')
    candidate.chmod(0o555); fsync_dir(candidate)
    verify(candidate, digest, owner=(0, 0) if production else None)
    # Publication is serialized under a descriptor-checked root-owned lock.
    # A pre-existing path (even an empty directory) is rejected or verified.
    if final.exists() or final.is_symlink():
        verify(final, digest, owner=(0, 0) if production else None)
        return final
    os.rename(candidate, final)
    fsync_dir(root)
    verify(final, digest, owner=(0, 0) if production else None)
    return final


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('build'); p.add_argument('source'); p.add_argument('destination')
    p = sub.add_parser('install'); p.add_argument('bundle'); p.add_argument('expected')
    p = sub.add_parser('verify'); p.add_argument('bundle'); p.add_argument('expected')
    args = parser.parse_args()
    try:
        if args.action == 'build':
            root = publish(source_files(args.source), args.destination)
        elif args.action == 'install':
            # Read and hash the complete source into bounded memory before any
            # write, so changes to a user-owned staging directory cannot change
            # the privileged published bytes. Installed code is never executed.
            if os.geteuid() != 0: raise BundleError('root required')
            files = verify(args.bundle, args.expected, immutable=False)
            root = publish(files, PRODUCTION_ROOT, production=True)
        else:
            root = Path(args.bundle); verify(root, args.expected)
        print(json.dumps({'ok': True, 'release_id': root.name, 'path': str(root), 'activated': False}))
        return 0
    except (OSError, ValueError, SyntaxError):
        print(json.dumps({'ok': False, 'code': 'RUNTIME_BUNDLE_INVALID', 'activated': False}))
        return 1


if __name__ == '__main__': raise SystemExit(main())
