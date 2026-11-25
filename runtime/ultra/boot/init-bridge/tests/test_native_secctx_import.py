"""The real KSU SID call must use the bridge's typed native import path."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


BRIDGE = Path(__file__).resolve().parents[1]
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
NM = os.environ.get("BRIDGE_FIXTURE_NM", str(Path(CC).with_name("nm.exe")))
NAME = "security_secctx_to_secid"


class SecctxImportChecks(unittest.TestCase):
    def fixture(self, legacy, incompatible=False):
        header = (BRIDGE / "native_imports.h").read_text()
        source = (BRIDGE / "native_imports.c").read_text()
        declaration = re.search(r"^extern typeof\(&" + NAME + r"\) msu_native_" + NAME + r";$",
                                header, re.M)
        mapping = re.search(r"^#define " + NAME + r" \(\*msu_native_" + NAME + r"\)$", header, re.M)
        invocation = re.search(r"IMPORT_RETURN\(int, " + NAME + r",\s*"
                               r"\(const char \*\w+, u32 \w+, u32 \*\w+\),\s*"
                               r"\(\w+, \w+, \w+\)\)", source)
        self.assertIsNotNone(declaration, "native SID import declaration missing")
        self.assertIsNotNone(mapping, "selected host SID calls still emit a raw import")
        self.assertIsNotNone(invocation, "typed SID import thunk missing")
        macros = re.findall(r"^#define IMPORT_RETURN\([^\n]*\\\n(?:[^\n]*\\\n)*[^\n]*", source, re.M)
        self.assertEqual(len(macros), 2)
        caller = (BRIDGE.parents[1] / "identity/kernel/manager_ksu_compat.c").read_text()
        call = re.search(r"error = " + NAME + r"\(\"u:r:ksu:s0\"[^;]+;", caller)
        self.assertIsNotNone(call)
        length = "unsigned long" if incompatible else "u32"
        return "\n".join([
            "typedef unsigned int u32;",
            "#define noinline __attribute__((noinline))",
            "#define __used __attribute__((used))",
            "extern int " + NAME + "(const char *, " + length + ", u32 *);",
            declaration.group(), macros[0 if legacy else 1], invocation.group(),
            "static typeof(&" + NAME + ") fixture_reference __used = ref_" + NAME + ";",
            mapping.group(),
            "int actual_ksu_sid_call(void) { u32 root_sid = 0; int error;",
            call.group(), "return error; }",
        ])

    def compile_fixture(self, source, directory):
        path = directory / "secctx.c"
        path.write_text(source)
        obj = directory / "secctx.o"
        result = subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Werror",
                                 "-c", str(path), "-o", str(obj)],
                                capture_output=True, text=True, timeout=25)
        return result, obj

    def test_real_ksu_call_uses_only_the_selected_native_binding(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory(prefix="bridge-secctx-") as temp:
                result, obj = self.compile_fixture(self.fixture(legacy), Path(temp))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                symbols = subprocess.run([NM, "--undefined-only", str(obj)],
                                         check=True, capture_output=True, text=True, timeout=5)
                names = {line.split()[-1] for line in symbols.stdout.splitlines() if line.split()}
                self.assertNotIn(NAME, names)
                if legacy:
                    self.assertIn("msu_direct_target_" + NAME, names)

    def test_native_declaration_mismatch_is_rejected(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory(prefix="bridge-secctx-abi-") as temp:
                result, _ = self.compile_fixture(self.fixture(legacy, incompatible=True), Path(temp))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native host prototype", result.stderr)

    def test_initialization_and_legacy_pair_are_registered(self):
        source = (BRIDGE / "native_imports.c").read_text()
        initialize = source[source.index("int msu_init_bridge_imports_init(void)"):]
        self.assertIn("    IMPORT(" + NAME + ");", initialize)
        self.assertIn('"msu_direct_target_' + NAME + "\\0" + NAME + '\\0"', source)

    def test_python_consumer_accepts_only_the_exact_registered_pair(self):
        spec = importlib.util.spec_from_file_location("secctx_direct", BRIDGE / "legacy_direct.py")
        direct = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(direct)
        alias = direct.DIRECT_PREFIX + NAME
        marker = direct.DIRECT_V2_MAGIC + (alias + "\0" + NAME + "\0\0").encode()
        declared, pairs = direct.marker_imports(marker)
        self.assertEqual(declared, {alias: NAME})
        self.assertEqual(pairs, [{"alias": alias, "target": NAME}])
        for bad in (marker.replace(alias.encode(), b"wrong_alias"),
                    marker.replace(NAME.encode(), b"unknown_native_target")):
            with self.assertRaisesRegex(ValueError, "LEGACY_DIRECT_MARKER"):
                direct.marker_imports(bad)

    def test_pid1_consumer_accepts_the_exact_pair_with_matching_capacity(self):
        binder = BRIDGE.parent / "ultra-init"
        source = (binder / "legacy_direct_bind.c").read_text().split("static int inside(", 1)[0]
        source = source.replace("#include <elf.h>", "")
        source += r'''
int main(void) {
    const char *aliases[MSU_DIRECT_LIMIT], *targets[MSU_DIRECT_LIMIT];
    const unsigned char marker[] = "MAPLESU_DIRECT_V2\0"
        "msu_direct_target_security_secctx_to_secid\0security_secctx_to_secid\0";
    const unsigned char bad[] = "MAPLESU_DIRECT_V2\0"
        "wrong_alias\0security_secctx_to_secid\0";
    int version = 0;
    _Static_assert(sizeof(direct_targets_v2) / sizeof(direct_targets_v2[0]) == MSU_DIRECT_LIMIT,
        "native direct consumer capacity");
    if (parse_marker(marker, sizeof(marker), aliases, targets, &version) != 1 || !version ||
        strcmp(aliases[0], "msu_direct_target_security_secctx_to_secid") ||
        strcmp(targets[0], "security_secctx_to_secid")) return 1;
    if (parse_marker(bad, sizeof(bad), aliases, targets, &version) != -EINVAL) return 2;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="bridge-secctx-pid1-") as temp:
            path = Path(temp) / "pid1.c"
            path.write_text(source)
            binary = Path(temp) / "pid1.exe"
            result = subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                                     "-I" + str(binder), str(path), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            subprocess.run([str(binary)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
