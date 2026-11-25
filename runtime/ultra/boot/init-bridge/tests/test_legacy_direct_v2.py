"""Synthetic ELF boundary regressions, plus optional native binder byte checks.

The fixture contains no executable host instructions. The optional C library
only parses and rewrites in-memory ELF bytes; it never loads a kernel module.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import types

HERE = Path(__file__).resolve().parents[1]
SHDR, SYM, RELA = struct.Struct('<IIQQQQIIQQ'), struct.Struct('<IBBHQQ'), struct.Struct('<QQq')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


direct = load('direct_v2', HERE / 'legacy_direct.py')
package = load('package_v2', HERE / 'package.py')
kmi = load('kmi_v2', HERE / 'target_kmi.py')
package.legacy_cfi_api = lambda: types.SimpleNamespace(verify_module=lambda data, facts: {'syntheticCfiSeam': True})
PROVIDERS = ['init_module', 'msu_boot_sdk_init', 'msu_manager_resident_init', 'msu_management_init',
             'msu_runtime_service_register', 'msu_su_registry_create', 'msu_su_read_current']
CONFIG = {'CONFIG_ARM64': 'y', 'CONFIG_MODULES': 'y', 'CONFIG_MODVERSIONS': 'y', 'CONFIG_MODULE_SIG_PROTECT': 'y'}
CONTRACT = {'cfiMode': 'legacy-lto-cfi', 'legacyCfi': {}, 'unprotectedSymbols': ['ordinary_export']}
SYMVERS = b'0x00000001\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n0x00000002\tordinary_export\tvmlinux\tEXPORT_SYMBOL_GPL\tFIXTURE_NS\n'


def fixture(targets=('__module_address', 'sha256'), marker=None, extra=()):
    aliases = [direct.DIRECT_PREFIX + name for name in targets]
    if marker is None:
        marker = direct.DIRECT_V2_MAGIC + b''.join((alias + '\0' + target + '\0').encode()
            for alias, target in zip(aliases, targets)) + b'\0'
    labels = ['', '.shstrtab', '.strtab', '.symtab', '.text', '.rela.text', '.msu_direct_calls', '__versions', '.modinfo']
    shstr = b'\0' + b'\0'.join(label.encode() for label in labels[1:]) + b'\0'
    names = aliases + ['ordinary_export', 'sha256'] + PROVIDERS + list(extra)
    strings = b'\0' + b'\0'.join(name.encode() for name in names) + b'\0'
    symbols = SYM.pack(0, 0, 0, 0, 0, 0) + b''.join(
        SYM.pack(strings.index(name.encode() + b'\0'), 0x10 if index <= len(aliases) else 0x12,
                 0, 0 if index <= len(aliases) else 4, 0, 0)
        for index, name in enumerate(names))
    call_count = len(aliases) + 1
    chunks = [b'', shstr, strings, symbols, struct.pack('<%dI' % call_count, *([0x94000000] * call_count)),
              b''.join(RELA.pack(index * 4, ((index + 1) << 32) | 283, 0) for index in range(call_count)),
              marker, struct.pack('<Q56sQ56s', 1, b'module_layout', 2, b'ordinary_export'),
              b'vermagic=5.10.1 fixture aarch64\0license=GPL\0import_ns=FIXTURE_NS\0']
    data, headers, offsets = bytearray(64), [], []
    for index, chunk in enumerate(chunks):
        data += b'\0' * (-len(data) % 8)
        at = len(data)
        offsets.append(at)
        data += chunk
        headers.append(SHDR.pack(shstr.index(labels[index].encode() + b'\0') if index else 0,
            [0, 3, 3, 2, 1, 4, 1, 1, 1][index], 6 if index == 4 else 0, 0, at, len(chunk),
            2 if index == 3 else 3 if index == 5 else 0, 1 if index == 3 else 4 if index == 5 else 0,
            8, 24 if index in (3, 5) else 0))
    data += b'\0' * (-len(data) % 8)
    shoff = len(data)
    data += b''.join(headers)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, b'\x7fELF\x02\x01\x01' + b'\0' * 9,
        1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), 1)
    return data, offsets, shoff


def run(args):
    rows = []
    binder = None
    if args.binder:
        library = ctypes.CDLL(str(args.binder))
        callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t)
        binder = library.msu_bind_legacy_direct
        binder.argtypes = [ctypes.c_void_p, ctypes.c_size_t, callback, ctypes.c_void_p]
        binder.restype = ctypes.c_int

    def check(label, mutate=None, expected_error=None, targets=('__module_address', 'sha256'),
              marker=None, extra=(), package_error=None, resolver_error=0, missing=False):
        data, offsets, shoff = fixture(targets, marker, extra)
        if mutate:
            mutate(data, offsets, shoff)
        original = bytes(data)
        try:
            facts = direct.inspect(data, 'legacy-lto-cfi')
        except ValueError as error:
            assert expected_error and expected_error in str(error), (label, str(error), expected_error)
            facts = {'rejected': str(error)}
        else:
            assert expected_error is None, (label, 'unexpected parser acceptance')
            assert facts['directImportsV2'] == [dict(alias=direct.DIRECT_PREFIX + name, target=name) for name in targets]
            assert facts['directMarkerSha256'] == hashlib.sha256(data[offsets[6]:offsets[6] +
                SHDR.unpack_from(data, shoff + 6 * SHDR.size)[5]]).hexdigest()
            try:
                packaged = package.inspect_module(data, '5.10.1', CONFIG, SYMVERS, CONTRACT)
            except ValueError as error:
                assert package_error and package_error in str(error), (label, str(error), package_error)
            else:
                assert package_error is None
                assert packaged['ordinaryImports'] == ['ordinary_export']
        assert bytes(data) == original
        binder_result = None
        if binder:
            seen = []
            @callback
            def resolve(context, requested, addresses, count):
                seen.extend(requested[index].decode() for index in range(count))
                for index in range(count):
                    addresses[index] = 0 if missing and index == count - 1 else 0xffffffc008100000 + index * 0x100
                return resolver_error
            buffer = (ctypes.c_ubyte * len(data)).from_buffer(data)
            binder_result = binder(buffer, len(data), resolve, None)
            expected = -22 if expected_error else resolver_error if resolver_error else -2 if missing else 1
            assert binder_result == expected, (label, binder_result, expected)
            if expected_error:
                assert seen == []
            else:
                assert seen == list(targets)
            if binder_result == 1:
                expected_bytes = bytearray(original)
                for index in range(len(targets)):
                    at = offsets[3] + (index + 1) * SYM.size
                    fields = list(SYM.unpack_from(expected_bytes, at))
                    fields[3], fields[4] = 0xfff1, 0xffffffc008100000 + index * 0x100
                    SYM.pack_into(expected_bytes, at, *fields)
                assert data == expected_bytes, label
            else:
                assert bytes(data) == original, label
        rows.append({'case': label, 'facts': facts, 'binderReturn': binder_result})

    check('two-exact-aliases-local-defined-sha256-ordinary-crc-namespace-retained')
    check('full-77-source-allowlist-binds-atomically', targets=direct.DIRECT_TARGETS_V2)
    check('resolver-error-keeps-all-elf-bytes', resolver_error=-5)
    check('missing-last-target-keeps-all-elf-bytes', missing=True)
    check('marker-empty', marker=direct.DIRECT_V2_MAGIC + b'\0', expected_error='DIRECT_MARKER')
    check('marker-unsorted', targets=('sha256', '__module_address'), expected_error='DIRECT_MARKER')
    check('marker-duplicate-target', targets=('sha256', 'sha256'), expected_error='DIRECT_MARKER')
    check('marker-unknown-target', targets=('unreviewed_target',), expected_error='DIRECT_MARKER')
    check('marker-wrong-alias', marker=direct.DIRECT_V2_MAGIC + b'other\0sha256\0\0', expected_error='DIRECT_MARKER')
    check('marker-extra-terminator', marker=direct.DIRECT_V2_MAGIC + b'msu_direct_target_sha256\0sha256\0\0\0', expected_error='DIRECT_MARKER')
    check('marker-odd-fields', marker=direct.DIRECT_V2_MAGIC + b'msu_direct_target_sha256\0\0', expected_error='DIRECT_MARKER')
    check('marker-nonascii', marker=direct.DIRECT_V2_MAGIC + b'\xff\0sha256\0\0', expected_error='DIRECT_MARKER')
    check('alias-missing', lambda d, o, s: struct.pack_into('<I', d, o[3] + SYM.size,
        struct.unpack_from('<I', d, o[3] + 3 * SYM.size)[0]), expected_error='DECLARED_ALIAS_MISSING')
    check('alias-weak', lambda d, o, s: d.__setitem__(o[3] + SYM.size + 4, 0x20), expected_error='DIRECT_SYMBOL')
    check('alias-local-defined', lambda d, o, s: struct.pack_into('<H', d, o[3] + SYM.size + 6, 4), expected_error='DIRECT_SYMBOL')
    check('alias-object', lambda d, o, s: d.__setitem__(o[3] + SYM.size + 4, 0x11), expected_error='DIRECT_SYMBOL')
    check('alias-duplicate-symbol', lambda d, o, s: struct.pack_into('<I', d, o[3] + 3 * SYM.size,
        struct.unpack_from('<I', d, o[3] + SYM.size)[0]), expected_error='DIRECT_SYMBOL')
    check('alias-undeclared-local', extra=('msu_direct_target_prepare_creds',), expected_error='UNDECLARED_ALIAS')
    check('alias-address-taken', lambda d, o, s: struct.pack_into('<Q', d, o[5] + 8, (1 << 32) | 257), expected_error='DIRECT_RELOCATION')
    check('alias-nonzero-addend', lambda d, o, s: struct.pack_into('<q', d, o[5] + 16, 4), expected_error='DIRECT_RELOCATION')
    check('alias-wrong-opcode', lambda d, o, s: struct.pack_into('<I', d, o[4], 0xd503201f), expected_error='DIRECT_OPCODE')
    check('alias-nonexecuting-code', lambda d, o, s: struct.pack_into('<Q', d, s + 4 * SHDR.size + 8, 2), expected_error='DIRECT_RELOCATION')
    check('alias-offset-overrun', lambda d, o, s: struct.pack_into('<Q', d, o[5], 12), expected_error='DIRECT_RELOCATION')
    check('alias-no-calls', lambda d, o, s: struct.pack_into('<Q', d, o[5] + 8, (3 << 32) | 283), expected_error='CALL_REQUIRED')
    check('ordinary-crc-mismatch-still-fails', lambda d, o, s: struct.pack_into('<Q', d, o[7] + 64, 3), package_error='IMPORT_CRC:ordinary_export')
    data, offsets, shoff = fixture(extra=('reference_prepare_creds', 'reference___vmalloc_node_range', 'ref___d_path'))
    required, optional = kmi.native_private_symbols(data)
    assert required == ['__vmalloc_node_range', 'prepare_creds'] and optional == ['__d_path']
    rows.append({'case': 'compiled-sdk-reference-names-included-direct-native-ref-names-excluded',
                 'privateSymbols': required, 'optionalPrivateSymbols': optional})
    table = types.SimpleNamespace(all_offsets=lambda name: [0] if name == '__module_address' else [4])
    targets, marker = kmi.direct_native_targets(fixture()[0], b'\0' * 8, table)
    assert [row['target'] for row in targets] == ['__module_address', 'sha256'] and marker
    rows.append({'case': 'direct-native-body-does-not-invent-canonical-jumptable', 'directTargets': targets})
    args.output.write_text(json.dumps({'schema': 'maplesu-legacy-direct-v2-boundary-regression/1',
        'cases': rows, 'binderLibrary': str(args.binder) if args.binder else None,
        'syntheticPackageCfiSeam': True, 'targetAbiQualified': False, 'moduleLoaded': False}, indent=2) + '\n')
    print('DIRECT_V2_CASES=' + str(len(rows)) + ' binder=' + str(bool(binder)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binder', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
