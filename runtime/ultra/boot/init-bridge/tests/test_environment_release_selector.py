"""Compile the real environment release selector with optional static facts."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
SOURCE = ROOT / 'jailbreak-providers/root-loader/module/maplesu_boot_sdk.c'


class EnvironmentReleaseSelector(unittest.TestCase):
    def test_optional_static_release_fact(self):
        source = Path(os.environ.get('MSU_RELEASE_SELECTOR_SOURCE', SOURCE)).read_text(encoding='utf-8')
        begin = source.index('#if MSU_BS_ENVIRONMENT\n    native_avc =')
        end = source.index('\n#undef RESOLVE', begin)
        block = source[begin:end]
        compiler = os.environ.get('BRIDGE_FIXTURE_CC') or shutil.which('clang') or shutil.which('gcc')
        if not compiler and os.name == 'nt':
            compiler = 'C:/msys64/ucrt64/bin/gcc.exe'
        self.assertIsNotNone(compiler)
        environment = dict(os.environ)
        environment['PATH'] = str(Path(compiler).parent) + os.pathsep + environment.get('PATH', '')
        for value, expected in ((None, 'module_memfree'), (0, 'module_memfree'), (1, 'execmem_free')):
            with self.subTest(value=value), tempfile.TemporaryDirectory(prefix='msu-release-selector-') as name:
                directory = Path(name)
                fixture = directory / 'fixture.c'
                fixture.write_text('''
#include <string.h>
static const char *first;
#define RESOLVE(destination, name) do { if (!first) first = name; destination = name; } while (0)
static const char *lookup_name(const char *name) { return name; }
int main(void) {
    const char *native_avc, *release_module = 0;
''' + block + '\n    (void)native_avc; return strcmp(first, "' + expected + '");\n}\n', encoding='utf-8')
                exe = directory / 'fixture.exe'
                argv = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wundef',
                    '-DMSU_BS_ENVIRONMENT=1', str(fixture), '-o', str(exe)]
                if value is not None:
                    argv.insert(1, '-DMSU_BS_EXECMEM_FREE=' + str(value))
                result = subprocess.run(argv, capture_output=True, text=True, env=environment, timeout=25)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = subprocess.run([str(exe)], capture_output=True, text=True, env=environment, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
