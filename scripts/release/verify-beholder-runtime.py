#!/usr/bin/env python3
"""Verify Beholder components from an already authenticated native Release archive.

This checks component integrity and availability; the OneNod Release verifier
must authenticate the archive's provenance before downloaded code is executed.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile

COMPONENTS = {
    'beholder-e1-core': 'beholder-core',
    'beholder-e2-gatekeeper': 'beholder-gatekeeper',
    'beholder-evidence': 'beholder-evidence',
}
SUPPORT = {'managed.example.toml', 'verify-runtime.py'}
PREFIX = 'onenod/beholder/'
MAX_BYTES = 128 * 1024 * 1024


def fail(message):
    raise RuntimeError(message)


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def checked_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_BYTES:
        fail('Invalid Beholder file: ' + path.name)
    return path.read_bytes()


def verify_directory(directory, version, commit, arch, execute=True):
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or arch not in ('arm64', 'amd64'):
        fail('Invalid expected release identity')
    manifest = json.loads(checked_file(directory / 'manifest.json'))
    if not (manifest.get('schema_version') == 1
            and manifest.get('record_type') == 'onenod_beholder_artifacts'
            and manifest.get('beholder_version') == 'v33'
            and manifest.get('release_version') == version
            and manifest.get('source_commit') == commit
            and manifest.get('architecture') == arch):
        fail('Beholder manifest does not match the authenticated Release')
    expected = set(COMPONENTS) | SUPPORT
    if set(manifest.get('files', {})) != expected:
        fail('Beholder manifest does not contain the exact component set')
    for name, descriptor in manifest['files'].items():
        path = directory / name
        raw = checked_file(path)
        if digest(raw) != descriptor.get('sha256'):
            fail('Beholder component hash mismatch: ' + name)
        if name not in COMPONENTS:
            continue
        component = COMPONENTS[name]
        identifier = 'com.github.vizards.onenod.' + component
        if descriptor.get('identifier') != identifier:
            fail('Beholder component role mismatch: ' + name)
        exact = descriptor.get('exact_code_identity', {})
        if (exact.get('architecture') != arch or not exact.get('cdhash')
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', exact.get('designated_requirement_data_sha256', ''))):
            fail('Beholder exact code identity is incomplete: ' + name)
        if not execute:
            continue
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        inspection = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', '-r-', str(path)],
                                    check=True, capture_output=True, text=True)
        details = inspection.stdout + '\n' + inspection.stderr
        if ('Identifier=' + identifier not in details.splitlines()
                or not re.search(r'flags=[^\n]*\bruntime\b', details)):
            fail('Beholder code identity or Hardened Runtime mismatch: ' + name)
        cdhash = re.search(r'^CDHash=([0-9a-f]+)$', details, re.MULTILINE)
        if (cdhash is None or base64.urlsafe_b64encode(bytes.fromhex(cdhash[1])).decode().rstrip('=')
                != exact['cdhash']):
            fail('Beholder code hash differs from the archive descriptor: ' + name)
        requirement = re.search(r'^(?:# )?designated => (.+)$', details, re.MULTILINE)
        if requirement is None:
            fail('Beholder designated requirement is missing: ' + name)
        with tempfile.TemporaryDirectory(prefix='beholder-requirement-') as temporary:
            compiled = Path(temporary) / 'requirement'
            subprocess.run(['/usr/bin/csreq', '-r=' + requirement[1], '-b', str(compiled)],
                           check=True, capture_output=True)
            if digest(checked_file(compiled)) != exact['designated_requirement_data_sha256']:
                fail('Beholder designated requirement differs from the archive descriptor: ' + name)
        slices = subprocess.check_output(['/usr/bin/lipo', '-archs', str(path)], text=True).strip()
        if slices != ('x86_64' if arch == 'amd64' else 'arm64'):
            fail('Beholder native architecture mismatch: ' + name)
        arguments = ['--identity'] if name == 'beholder-evidence' else ['--mode', 'identity']
        identity = json.loads(subprocess.check_output([str(path), *arguments], timeout=10))
        if not (identity.get('schema_version') == 1 and identity.get('component') == component
                and identity.get('product_version') == version and identity.get('source_commit') == commit
                and identity.get('release_tag') == 'v' + version):
            fail('Beholder executable build or role mismatch: ' + name)
    return manifest


def verify_archive(archive, version, commit, arch):
    with tempfile.TemporaryDirectory(prefix='beholder-runtime-verify-') as temporary:
        directory = Path(temporary)
        seen, total = set(), 0
        with tarfile.open(archive, 'r:gz') as source:
            for entry in source:
                if not entry.name.startswith(PREFIX):
                    continue
                name = entry.name[len(PREFIX):]
                if (name not in set(COMPONENTS) | SUPPORT | {'manifest.json'} or not entry.isfile()
                        or name in seen or entry.size <= 0 or entry.size > MAX_BYTES - total):
                    fail('Unsafe or unexpected Beholder archive entry')
                seen.add(name)
                total += entry.size
                raw = source.extractfile(entry).read(entry.size + 1)
                if len(raw) != entry.size:
                    fail('Truncated Beholder archive entry')
                path = directory / name
                path.write_bytes(raw)
                path.chmod(0o700 if name in COMPONENTS else 0o600)
        return verify_directory(directory, version, commit, arch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--arch', choices=['arm64', 'amd64'], required=True)
    args = parser.parse_args()
    verify_archive(args.archive, args.version, args.commit, args.arch)
    print(json.dumps({'beholder_version': 'v33', 'release_version': args.version,
                      'source_commit': args.commit, 'architecture': args.arch, 'verified': True}))


if __name__ == '__main__':
    main()
