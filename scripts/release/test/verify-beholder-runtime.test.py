import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-beholder-runtime.py'
SPEC = importlib.util.spec_from_file_location('beholder_runtime_verifier', SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class RuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.version, self.commit = '0.0.2-alpha.52', 'a' * 40
        self.manifest = {'schema_version': 1, 'record_type': 'onenod_beholder_artifacts',
                         'beholder_version': 'v32', 'release_version': self.version,
                         'source_commit': self.commit, 'architecture': 'arm64', 'files': {}}
        for name in set(verifier.COMPONENTS) | verifier.SUPPORT:
            raw = ('dummy ' + name).encode()
            (self.root / name).write_bytes(raw)
            descriptor = {'sha256': verifier.digest(raw)}
            if name in verifier.COMPONENTS:
                descriptor.update(identifier='com.github.vizards.onenod.' + verifier.COMPONENTS[name],
                                  exact_code_identity={'architecture': 'arm64', 'cdhash': 'dummy',
                                                       'designated_requirement_data_sha256': 'sha256:' + 'b' * 64})
            self.manifest['files'][name] = descriptor
        self.persist()

    def persist(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest))

    def verify(self):
        return verifier.verify_directory(self.root, self.version, self.commit, 'arm64', execute=False)

    def test_exact_component_set(self):
        self.verify()
        del self.manifest['files']['beholder-e2-gatekeeper']
        self.persist()
        with self.assertRaisesRegex(RuntimeError, 'exact component set'):
            self.verify()

    def test_changed_binary_fails_before_execution(self):
        (self.root / 'beholder-e1-core').write_bytes(b'changed core')
        with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
            self.verify()

    def test_swapped_role_rejected_even_with_updated_digest(self):
        self.manifest['files']['beholder-e1-core']['identifier'] = 'com.github.vizards.onenod.beholder-gatekeeper'
        self.persist()
        with self.assertRaisesRegex(RuntimeError, 'role mismatch'):
            self.verify()

    def test_wrong_release_and_architecture_rejected(self):
        for field, value in [('source_commit', 'c' * 40), ('architecture', 'amd64'), ('release_version', '0.0.2-alpha.51')]:
            old = self.manifest[field]
            self.manifest[field] = value
            self.persist()
            with self.assertRaisesRegex(RuntimeError, 'authenticated Release'):
                self.verify()
            self.manifest[field] = old

    def test_link_is_not_a_component(self):
        path = self.root / 'beholder-e1-core'
        path.unlink()
        path.symlink_to(self.root / 'beholder-e2-gatekeeper')
        with self.assertRaisesRegex(RuntimeError, 'Invalid Beholder file'):
            self.verify()

    def test_unsafe_archive_name_is_rejected_without_extracting(self):
        archive = self.root / 'unsafe.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            member = tarfile.TarInfo('onenod/beholder/../../outside')
            member.size = 4
            output.addfile(member, io.BytesIO(b'test'))
        with self.assertRaisesRegex(RuntimeError, 'Unsafe or unexpected'):
            verifier.verify_archive(archive, self.version, self.commit, 'arm64')
        self.assertFalse((self.root / 'outside').exists())


if __name__ == '__main__':
    unittest.main()
