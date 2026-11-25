"""Fresh-process readback of an explicitly supplied, actual legacy KMI capture.

Set MAPLESU_LEGACY_TARGET_CONTRACT to a current source-only target-contract.json.
No kernel image fixture, compiler or device is synthesized by this regression.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

READER = Path(__file__).resolve().parents[1] / 'target_kmi.py'
CHILD = '''
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("fresh_legacy_kmi", sys.argv[1])
kmi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kmi)
try:
    kmi.read_contract(Path(sys.argv[2]))
except ValueError as error:
    if not sys.argv[3] or not str(error).startswith(sys.argv[3]):
        raise
    print(str(error))
else:
    if sys.argv[3]:
        raise AssertionError("expected strict contract rejection")
    print("PASS_FRESH_LEGACY_READBACK")
'''


@unittest.skipUnless(os.environ.get('MAPLESU_LEGACY_TARGET_CONTRACT'),
    'Set MAPLESU_LEGACY_TARGET_CONTRACT to an actual current legacy capture')
class LegacyKmiImportTest(unittest.TestCase):
    def setUp(self):
        self.contract_path = Path(os.environ['MAPLESU_LEGACY_TARGET_CONTRACT']).resolve(strict=True)
        self.contract = json.loads(self.contract_path.read_bytes())
        self.assertEqual('legacy-lto-cfi', self.contract['cfiMode'])
        self.assertTrue(any(row.get('proof') == 'actual-symbol-bounded-uninstrumented-trace-loop-and-btf'
            for rows in self.contract['legacyCfi']['taskProfileCallsites'].values() for row in rows),
            'The actual fixture must exercise the BTF trace fallback import')

    def read_fresh(self, expected='', mutate=None):
        with tempfile.TemporaryDirectory(prefix='legacy-kmi-readback-') as directory:
            path = self.contract_path
            if mutate:
                mutate(self.contract)
                # read_contract resolves generated sibling inputs relative to
                # its JSON; retain those exact checked identities in the copy.
                for name in ('profile', 'targetSymvers'):
                    sibling = self.contract_path.parent / Path(self.contract[name]['path']).name
                    (Path(directory) / sibling.name).write_bytes(sibling.read_bytes())
                path = Path(directory) / 'target-contract.json'
                path.write_text(json.dumps(self.contract), encoding='utf-8')
            environment = dict(os.environ)
            environment.pop('PYTHONPATH', None)
            result = subprocess.run([sys.executable, '-B', '-c', CHILD,
                str(READER), str(path), expected], cwd=directory, env=environment,
                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return result.stdout

    def test_standalone_reader_self_resolves_actual_btf_dependency(self):
        self.assertIn('PASS_FRESH_LEGACY_READBACK', self.read_fresh())

    def test_actual_legacy_facts_mismatch_still_rejects(self):
        self.read_fresh('ULTRA_BRIDGE_LEGACY_TARGET_CONTRACT',
            lambda data: data['legacyCfi'].__setitem__('targetSha256', '0' * 64))

    def test_generator_identity_mismatch_still_rejects(self):
        self.read_fresh('ULTRA_BRIDGE_KMI_INPUT_CHANGED:',
            lambda data: data['generator'].__setitem__('sha256', '0' * 64))


if __name__ == '__main__':
    unittest.main(verbosity=2)
