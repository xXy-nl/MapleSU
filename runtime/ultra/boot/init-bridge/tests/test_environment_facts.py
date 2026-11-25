"""Real stage and bridge environment wiring; kernel calls are explicit mocks."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import re

import test_stage

BRIDGE = Path(__file__).resolve().parents[1]
CC = os.environ.get('BRIDGE_FIXTURE_CC', 'C:/msys64/ucrt64/bin/gcc.exe' if os.name == 'nt' else 'gcc')


class EnvironmentFactsChecks(unittest.TestCase):
    def compile_run(self, fixture, execmem=False):
        with tempfile.TemporaryDirectory(prefix='bridge-environment-facts-') as directory:
            path = Path(directory)
            if execmem:
                (path / 'linux').mkdir()
                (path / 'linux/execmem.h').write_text('/* selected backend fixture */\n')
            (path / 'fixture.c').write_text(fixture)
            binary = path / 'fixture.exe'
            environment = dict(os.environ)
            environment['PATH'] = str(Path(CC).parent) + os.pathsep + environment.get('PATH', '')
            subprocess.run([CC, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-UNDEBUG',
                            '-I', str(path), str(path / 'fixture.c'), '-o', str(binary)], check=True, env=environment, timeout=25)
            subprocess.run([str(binary)], check=True, env=environment, timeout=5)

    def test_real_stage_keeps_environment_producer(self):
        case = test_stage.StageChecks()
        case.setUp()
        case.run_stage()
        header = case.files[case.output / 'boot_sdk_layout.h'].decode()
        self.assertIn('#define MSU_BS_ENVIRONMENT 1\n', header)
        self.assertIn('#define MSU_BS_EXECVE_REG 1\n', header)

    def test_real_bridge_preserves_live_layout_environment(self):
        source = (BRIDGE / 'bridge.c').read_text()
        begin = source.index('    error = msu_init_bridge_native_layout(')
        end = source.index('    native_attempted = true;', begin)
        body = source[begin:end]
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct msu_boot_sdk_layout { unsigned int environment; };
struct msu_deployment_namespace_record { unsigned int unused; };
static int msu_init_bridge_native_layout(unsigned int flags, unsigned int release,
    struct msu_boot_sdk_layout *layout) { (void)flags; (void)release; layout->environment=1; return 0; }
static int msu_preinit_start(void) { return 0; }
static int msu_boot_events_start(const struct msu_deployment_namespace_record *record) { (void)record; return 0; }
#define pr_warn(...) ((void)0)
int main(void) {
    struct msu_boot_sdk_layout layout = {0};
    struct msu_deployment_namespace_record deployment = {0};
    unsigned int allocator_flags = 0;
    unsigned int execmem_free = 0;
    int error, events_attempted = 0;
    char deployment_namespace[17] = {0};
''' + body + r'''
    if (layout.environment != 1) { fputs("live environment fact was cleared\n", stderr); return 1; }
    (void)events_attempted;
    return 0;
clear: return error ? 2 : 3;
failed: return 4;
}
'''
        self.compile_run(fixture)

    def test_real_bridge_passes_the_compiled_release_backend(self):
        source = (BRIDGE / 'bridge.c').read_text()
        begin = source.index('    error = msu_init_bridge_native_layout(')
        end = source.index('    native_attempted = true;', begin)
        body = source[begin:end]
        declaration_start = source.find('#if __has_include(<linux/execmem.h>)', source.index('static int __init msu_init_bridge_start'))
        declaration = (source[declaration_start:source.index('    unsigned int n;', declaration_start)]
                       if declaration_start >= 0 else '')
        for execmem in (False, True):
            with self.subTest(execmem=execmem):
                self.compile_run(r'''
#include <assert.h>
#include <stdbool.h>
struct msu_boot_sdk_layout { unsigned int environment; };
struct msu_deployment_namespace_record { unsigned int unused; };
static int msu_init_bridge_native_layout(unsigned int flags, unsigned int release,
    struct msu_boot_sdk_layout *layout) {
    (void)flags; if (release != EXPECTED_RELEASE) return -99; layout->environment=1; return 0;
}
static int msu_preinit_start(void) { return 0; }
static int msu_boot_events_start(const struct msu_deployment_namespace_record *p) { (void)p; return 0; }
#define pr_warn(...) ((void)0)
int main(void) {
    struct msu_boot_sdk_layout layout = {0};
    struct msu_deployment_namespace_record deployment = {0};
    unsigned int allocator_flags = 0;
    int error, events_attempted = 0;
    char deployment_namespace[17] = {0};
''' .replace('EXPECTED_RELEASE', str(int(execmem))) + declaration + body + r'''
    (void)events_attempted; assert(layout.environment == 1); return 0;
clear: return error ? 2 : 3;
failed: return 4;
}
''', execmem=execmem)

    def test_actual_filename_field_and_failures(self):
        source = (BRIDGE / 'native_sdk_imports.c').read_text()
        begin = source.index('int msu_init_bridge_environment_filename(')
        end = source.index('\nstatic noinline void reference_environment_release', begin)
        self.compile_run(r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
#define MSU_INIT_BRIDGE_RUNTIME_FACTS 1
struct msu_runtime_btf_field { unsigned int offset, bytes, owner_bytes, kind, type_id; };
static struct msu_runtime_btf_field fixture = {24, sizeof(void *), 64, 2, 17};
static int query_error;
static int msu_runtime_facts_field(const char *owner, const char *member, struct msu_runtime_btf_field *out) {
    assert(!strcmp(owner,"filename") && !strcmp(member,"name"));
    if (query_error) return query_error;
    *out = fixture; return 0;
}
''' + source[begin:end] + r'''
int main(void) {
    unsigned int out=99;
    assert(!msu_init_bridge_environment_filename(&out) && out==24);
    fixture.offset=0; assert(!msu_init_bridge_environment_filename(&out) && out==0);
    fixture.offset=256; fixture.owner_bytes=1024; out=99;
    assert(msu_init_bridge_environment_filename(&out)==-EOVERFLOW && out==99);
    fixture.owner_bytes=64; fixture.offset=7; assert(msu_init_bridge_environment_filename(&out)==-EPROTO && out==99);
    fixture.offset=24; fixture.bytes=4; assert(msu_init_bridge_environment_filename(&out)==-EPROTO && out==99);
    fixture.bytes=sizeof(void *); fixture.kind=1;
    assert(msu_init_bridge_environment_filename(&out)==-EPROTO && out==99);
    fixture.kind=2; query_error=-ENOENT;
    assert(msu_init_bridge_environment_filename(&out)==-ENOENT && out==99);
    query_error=0; fixture.owner_bytes=8;
    assert(msu_init_bridge_environment_filename(&out)==-EPROTO && out==99);
    assert(msu_init_bridge_environment_filename(0)==-EINVAL);
    return 0;
}
''')

    def test_claim_consumer_preserves_legacy_and_accepts_append64(self):
        root = BRIDGE.parents[3]
        source = (root / 'runtime/ultra/identity/kernel/manager_claim_bootstrap.c').read_text()
        clause = re.search(r'\(resident->append_bytes != MAPLESU_LEGACY_METADATA_V2_BYTES.*?\)', source, re.S).group()
        self.compile_run(r'''
#include <assert.h>
#define MAPLESU_LEGACY_METADATA_V2_BYTES 54
#define MAPLESU_LEGACY_METADATA_AUDIT_BYTES 58
#define MAPLESU_APPEND64_BYTES 88
struct resident { unsigned int append_bytes; };
static int accepted(unsigned int bytes) {
    struct resident value = {bytes}; const struct resident *resident=&value;
    return !''' + clause + r''';
}
int main(void) {
    assert(accepted(54) && accepted(58) && accepted(88));
    assert(!accepted(0) && !accepted(57) && !accepted(87) && !accepted(89));
    return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
