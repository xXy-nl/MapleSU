"""Strict strip receipts retain debug facts without changing the published ELF."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BASE = Path(__file__).parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('strip_metadata_package', path)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    return api


package = load(BASE / 'package.py')
task = load(BASE / 'task_profile_abi.py')
legacy = load(BASE / 'task_profile_legacy.py')


def elf_bytes(debug=False, code=b'\xc0\x03\x5f\xd6', relocation=0):
    names = b'\0entry\0source.c\0'
    symbols = bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 0, 4)
    if debug:
        symbols += struct.pack('<IBBHQQ', 7, 4, 0, 0xfff1, 0, 0)
    sections = [('.text', code, 1, 6, 0, 0, 4, 0),
        ('.strtab', names, 3, 0, 0, 0, 1, 0),
        ('.symtab', symbols, 2, 0, 2, 1, 8, 24),
        ('.rela.text', struct.pack('<QQq', 0, (1 << 32) | 283, relocation), 4, 0, 3, 1, 8, 24),
        ('.modinfo', b'license=GPL\0', 1, 2, 0, 0, 1, 0)]
    if debug:
        sections.append(('.debug_info', b'explicit inert DWARF fixture', 1, 0, 0, 0, 1, 0))
    strings = b'\0' + b''.join(name.encode() + b'\0' for name, *_ in sections) + b'.shstrtab\0'
    sections.append(('.shstrtab', strings, 3, 0, 0, 0, 1, 0))
    body, headers = bytearray(64), [bytes(64)]
    for name, data, kind, flags, link, info, alignment, entsize in sections:
        body += bytes((-len(body)) % alignment)
        headers.append(struct.pack('<IIQQQQIIQQ', strings.index(name.encode()), kind, flags,
            0, len(body), len(data), link, info, alignment, entsize))
        body += data
    body += bytes((-len(body)) % 8)
    shoff = len(body)
    body += b''.join(headers)
    body[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
        1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), len(headers) - 1)
    return bytes(body)


class DerivedReached(Exception):
    pass


class StripMetadataChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = self.root / 'module'
        self.evidence = self.root / 'kernel'
        self.module.mkdir()
        self.evidence.mkdir()
        self.bridge = self.module / 'maplesu_ultra_bridge.ko'
        self.original = self.evidence / 'maplesu_ultra_bridge.unstripped.ko'
        self.bridge.write_bytes(elf_bytes())
        self.original.write_bytes(elf_bytes(debug=True))
        self.build = self.evidence / 'BUILD.json'
        original = dict(package.file_identity(self.original),
            path='/run-evidence/kernel/maplesu_ultra_bridge.unstripped.ko')
        final = dict(package.file_identity(self.bridge), path='/module/maplesu_ultra_bridge.ko')
        self.receipt = dict(exitCode=0, inputsUnchanged=True, nativeComponentsOnly=False,
            artifacts=[final], stripDebug=dict(exitCode=0, input=original, unstripped=original, output=final))
        self.save()

    def save(self):
        self.build.write_text(json.dumps(self.receipt), encoding='utf-8')

    def test_strict_original_selected_and_final_unchanged(self):
        before = self.bridge.read_bytes()
        self.assertEqual(package.module_debug_source(self.bridge, self.build), self.original.resolve())
        self.assertEqual(self.bridge.read_bytes(), before)

    def test_legacy_build_without_strip_keeps_its_real_module(self):
        del self.receipt['stripDebug']
        self.save()
        self.assertEqual(package.module_debug_source(self.bridge, self.build), self.bridge)

    def test_signed_module_is_not_replaced(self):
        final = self.receipt['artifacts'][0]
        self.receipt['stripDebug'] = dict(status='SIGNED_MODULE_PRESERVED', input=final, output=final)
        self.save()
        self.assertEqual(package.module_debug_source(self.bridge, self.build), self.bridge)

    def test_relocated_canonical_receipt_keeps_original_evidence(self):
        old = self.root / 'build-evidence'
        old.mkdir()
        original = old / self.original.name
        self.original.replace(original)
        self.receipt['stripDebug']['unstripped']['path'] = '/output/cohort/build-evidence/' + original.name
        self.save()
        self.assertEqual(package.module_debug_source(self.bridge, self.build), original.resolve())

    def test_missing_original_is_rejected(self):
        self.original.unlink()
        with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_MISSING'):
            package.module_debug_source(self.bridge, self.build)

    def test_changed_original_is_rejected(self):
        self.original.write_bytes(self.original.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'INPUT_CHANGED:unstripped-module'):
            package.module_debug_source(self.bridge, self.build)

    def test_retained_code_difference_is_rejected_even_with_fresh_hash(self):
        self.original.write_bytes(elf_bytes(debug=True, code=bytes(4)))
        identity = package.file_identity(self.original)
        self.receipt['stripDebug'].update(input=identity, unstripped=identity)
        self.save()
        with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_RUNTIME_CHANGED'):
            package.module_debug_source(self.bridge, self.build)

    def test_retained_relocation_difference_is_rejected(self):
        self.original.write_bytes(elf_bytes(debug=True, relocation=4))
        identity = package.file_identity(self.original)
        self.receipt['stripDebug'].update(input=identity, unstripped=identity)
        self.save()
        with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_RUNTIME_CHANGED'):
            package.module_debug_source(self.bridge, self.build)

    def test_failed_strip_is_rejected(self):
        self.receipt['stripDebug']['exitCode'] = 7
        self.save()
        with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_STRIP_RECEIPT'):
            package.module_debug_source(self.bridge, self.build)

    def test_failed_or_drifting_or_partial_build_is_rejected(self):
        for key, value in (('exitCode', 7), ('inputsUnchanged', False), ('nativeComponentsOnly', True)):
            with self.subTest(key=key):
                saved = self.receipt[key]
                self.receipt[key] = value
                self.save()
                with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_STRICT_BUILD_REQUIRED'):
                    package.module_debug_source(self.bridge, self.build)
                self.receipt[key] = saved

    def test_missing_or_ambiguous_final_artifact_is_rejected(self):
        artifact = self.receipt['artifacts'][0]
        for rows in ([], [artifact, artifact]):
            with self.subTest(count=len(rows)):
                self.receipt['artifacts'] = rows
                self.save()
                with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_STRICT_ARTIFACT_REQUIRED'):
                    package.module_debug_source(self.bridge, self.build)

    def test_final_module_identity_is_not_replaced_by_debug_identity(self):
        self.bridge.write_bytes(self.original.read_bytes())
        with self.assertRaisesRegex(ValueError, 'INPUT_CHANGED:debug-final-module'):
            package.module_debug_source(self.bridge, self.build)

    def test_new_debug_provenance_required_and_rechecked(self):
        with self.assertRaisesRegex(ValueError, 'DEBUG_SOURCE_PROVENANCE_REQUIRED'):
            package.verify_module_debug_source({}, self.bridge, self.build)
        proof = dict(moduleDebugSource=package.file_identity(self.original))
        package.verify_module_debug_source(proof, self.bridge, self.build)
        proof['moduleDebugSource']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'INPUT_CHANGED:module-debug-source'):
            package.verify_module_debug_source(proof, self.bridge, self.build)

    def test_session_lto_actual_derive_uses_retained_debug_source(self):
        # Execute the real entry through its first derivation. Only preceding
        # source/TU ports and the external pahole boundary are substituted.
        obj = self.module / 'session.o'
        obj.write_bytes(b'BC\xc0\xde explicit bitcode fixture')
        command = self.module / '.session.o.cmd'
        command.write_text('cmd := clang -c -o /module/session.o /module/session.c\n/module/session.h\n')
        paths = {}
        for name in ('source-selection', 'claim-builder'):
            paths[name] = self.root / name
            paths[name].write_text('{}')
        sources = {prefix + name: dict(staged=name) for name in ('session.c', 'session.h')
            for prefix in ('runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/',)}
        # Production logical names are fixed, while staged names are fixture-local.
        sources = {key.replace('session.', 'su_exec_session.'): value for key, value in sources.items()}
        args = ['package.py', 'session-abi', '--bridge', str(self.bridge), '--session-object', str(obj),
            '--session-command', str(command), '--source-selection', str(paths['source-selection']),
            '--build-receipt', str(self.build), '--claim-builder', str(paths['claim-builder']),
            '--pahole', str(self.root / 'pahole'), '--llvm-objcopy', str(self.root / 'llvm-objcopy'),
            '--output', str(self.root / 'derived')]

        def derive(argv, **kwargs):
            data = Path(argv[-1]).read_bytes()
            if package.ELFFile(__import__('io').BytesIO(data)).get_section_by_name('.debug_info') is None:
                return SimpleNamespace(returncode=7)
            raise DerivedReached()

        with patch.object(sys, 'argv', args), patch.object(package, 'session_source_proof', return_value=sources), \
                patch.object(package, 'python_dependency', return_value=None), \
                patch.object(package.subprocess, 'run', side_effect=derive):
            with self.assertRaises(DerivedReached):
                package.session_abi_main()

    def task_inputs(self, legacy_mode):
        command = self.module / 'task.cmd'
        policy = dict(mode='legacy-lto-cfi' if legacy_mode else 'kcfi', normalizeIntegers=False)
        flag = '-flto -fsanitize=cfi' if legacy_mode else '-fsanitize=kcfi'
        command.write_text('cmd := clang ' + flag +
            ' -c -o /module/task.o /module/task.c\n/module/host/state.h\n')
        probe_command = self.module / 'probe.cmd'
        probe_command.write_text('cmd := clang ' + flag +
            ' -c -o /module/probe.o /module/probe.c\n/module/host/state.h\n')
        paths = dict(bridge=self.bridge, **{'build-receipt': self.build,
            'task-command': command, 'native-probe-command': probe_command})
        for name in ('task-object', 'source-selection', 'target-config', 'build-config',
                'source-successor', 'claim-builder', 'native-probe-source', 'native-probe-object',
                'target-contract', 'target-image', 'claim-reference', 'claim-elf'):
            paths[name] = self.module / {'task-object': 'task.o', 'native-probe-object': 'probe.o',
                'native-probe-source': 'probe.c', 'claim-builder': 'claim_builder.py'}.get(name, name)
            paths[name].write_text('{}')
        paths['native-probe-source'].write_bytes(task.NATIVE_PROBE_SOURCE.encode('ascii'))
        paths['task-object'].write_bytes(b'BC\xc0\xde fixture')
        paths['native-probe-object'].write_bytes(b'BC\xc0\xde fixture')
        for name in ('build-config', 'target-config'):
            paths[name].write_text('CONFIG_CFI=y\n')
        implementation = dict(schema='maplesu-task-profile-implementation/1', present=True,
            metadataComplete=True, sourceSuccessorIdentity=package.file_identity(paths['source-successor']),
            sourceSuccessor={}, functions={name: {} for name in task.FUNCTIONS})
        paths['claim-reference'].write_text(json.dumps(dict(claimSha256=package.file_identity(paths['claim-elf'])['sha256'],
            taskProfileAbi=dict(implementation=implementation,
                configIdentity=package.file_identity(paths['build-config'])))))
        image = package.file_identity(paths['target-image'])
        paths['target-contract'].write_text(json.dumps(dict(cfiMode='legacy-lto-cfi',
            inputs=dict(kernelImage=image), legacyCfi=dict(targetSha256=image['sha256'],
                taskProfileCallsites={name: [] for name in task.CALLBACKS}))))
        paths['claim-builder'].write_text('def session_cfi_policy(command): return ' + repr(policy) + '\n')
        for relative in ('.native_legacy_cfi.o.cmd', 'producer/module/.maplesu_boot_sdk.o.cmd'):
            path = self.module / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('explicit fixture command')
        arguments = ('bridge', 'task-object', 'task-command', 'source-selection', 'build-receipt',
            'target-config', 'build-config', 'source-successor', 'claim-builder', 'native-probe-source',
            'native-probe-object', 'native-probe-command') + (('target-contract', 'target-image')
                if legacy_mode else ('claim-reference', 'claim-elf'))
        argv = ['task_profile_abi.py'] + (['legacy'] if legacy_mode else [])
        for name in arguments:
            argv += ['--' + name, str(paths[name])]
        argv += ['--pahole', str(self.root / 'pahole'), '--llvm-objcopy', str(self.root / 'llvm-objcopy'),
            '--output', str(self.root / 'task-derived'), '--path-binding', '/build-config=' + str(self.root)]
        if not legacy_mode:
            argv += ['--path-binding', '/claim=' + str(self.root)]
        sources = {'runtime/ultra/identity/kernel/manager_task_state.h': dict(staged='host/state.h')}
        return argv, sources, policy

    @staticmethod
    def derive_with_debug(argv, **kwargs):
        data = Path(argv[-1]).read_bytes()
        if package.ELFFile(__import__('io').BytesIO(data)).get_section_by_name('.debug_info') is None:
            return SimpleNamespace(returncode=7)
        raise DerivedReached()

    def test_task_profile_actual_derive_uses_retained_debug_source(self):
        args, sources, _ = self.task_inputs(False)
        with patch.object(sys, 'argv', args), patch.object(task, 'source_proof', return_value=sources), \
                patch.object(task.package, 'python_dependency', return_value=None), \
                patch.object(task.subprocess, 'run', side_effect=self.derive_with_debug):
            with self.assertRaises(DerivedReached):
                task.main()

    def test_legacy_task_profile_actual_derive_uses_retained_debug_source(self):
        args, sources, policy = self.task_inputs(True)
        real_load = task.load_api

        def api_load(name, path):
            if name == 'task_profile_legacy_flags':
                return SimpleNamespace(command_policy=lambda path: dict(identity=package.file_identity(path)))
            return real_load(name, path)

        with patch.object(sys, 'argv', args), patch.object(task, 'source_proof', return_value=sources), \
                patch.object(task.package, 'python_dependency', return_value=None), \
                patch.object(task, 'load_api', side_effect=api_load), \
                patch.object(legacy, 'dependency', return_value=SimpleNamespace()), \
                patch.object(legacy, 'actual_policy', return_value=policy), \
                patch.object(legacy, '__file__', str(BASE / 'task_profile_legacy.py')), \
                patch.object(legacy.subprocess, 'run', side_effect=self.derive_with_debug):
            with self.assertRaises(DerivedReached):
                legacy.main(task)


if __name__ == '__main__':
    unittest.main()
