"""Native DDK objects must not acquire an optional runtime BTF prerequisite.

Compile the unchanged production field/object resolver bodies at their actual
seam. The fake provider supplies only metadata; no target kernel is emulated.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")


def resolver_source():
    text = (BRIDGE / "native_layout.c").read_text(encoding="utf-8")
    begin = text.index("static int native_layout_field(")
    end = text.index("int msu_init_bridge_native_layout_init(", begin)
    return text[begin:end]


FIXTURE = r"""
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
struct msu_runtime_btf_field { u32 offset, bytes, owner_bytes; };
#define pr_err(...) ((void)0)
static unsigned int calls;
static int provider_error;
static int query(const char *owner, const char *member, struct msu_runtime_btf_field *out)
{
    (void)owner; (void)member; ++calls;
    if (provider_error) return provider_error;
    *out = (struct msu_runtime_btf_field){ 80, 8, 1024 };
    return 0;
}
"""

CASES = r"""
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "native API line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    u32 offset = 99, extent = 0;
    provider_error = -ENOENT;
    CHECK(native_layout_field(query, "task_struct", "cred", 8, &offset, &extent) == -ENOENT);
    CHECK(offset == 99 && extent == 0 && calls == 1);
    calls = 0;
#ifdef MODULE
    const int errors[] = { -EPROTO, -EIO, 0, -ENOENT };
    for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        provider_error = errors[i]; offset = 99; extent = 0;
        CHECK(native_layout_object(query, "kprobe", "addr", 8, 8, 32, &offset, &extent) == 0);
        CHECK(offset == 8 && extent == 32 && calls == 0);
    }
    CHECK(native_layout_object(query, "pt_regs", "pc", 256, 8, 288, &offset, &extent) == 0);
    CHECK(offset == 256 && extent == 288 && calls == 0);
#else
    CHECK(native_layout_object(query, "kprobe", "addr", 8, 8, 32, &offset, &extent) == -ENOENT);
    CHECK(offset == 99 && extent == 0 && calls == 1);
    provider_error = 0;
    CHECK(native_layout_object(query, "kprobe", "addr", 8, 8, 32, &offset, &extent) == 0);
    CHECK(offset == 80 && extent == 1024 && calls == 2);
#endif
    return 0;
}
"""


class NativeLayoutApiChecks(unittest.TestCase):
    def run_fixture(self, module):
        with tempfile.TemporaryDirectory(prefix="bridge-native-layout-api-") as directory:
            source = Path(directory) / "fixture.c"
            binary = Path(directory) / "fixture.exe"
            source.write_text(FIXTURE + resolver_source() + CASES, encoding="utf-8")
            argv = [CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]
            if module:
                argv.append("-DMODULE=1")
            subprocess.run(argv + [str(source), "-o", str(binary)], check=True, timeout=20)
            subprocess.run([str(binary)], check=True, timeout=5)

    def test_module_objects_follow_native_api_without_metadata_gate(self):
        self.run_fixture(True)

    def test_copied_payload_objects_keep_runtime_field_requirement(self):
        self.run_fixture(False)


if __name__ == "__main__":
    unittest.main()
