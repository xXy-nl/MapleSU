"""Mock lookup-branch behavior only; no target CFI/ABI/module qualification.

Windows uses LLP64, so only this host fixture translates unsigned-long pointer
carriers to uintptr_t. Actual ARM64 TU checks use the unchanged product source.
Run only through the central evidence executor.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
DEFINITIONS = r"""
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
#define CONFIG_ARM64 1
#define noinline __attribute__((noinline))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define KSYM_SYMBOL_LEN 256
struct kprobe { const char *symbol_name; void *addr; };
uintptr_t kallsyms_lookup_name(const char *name);
int kallsyms_lookup_size_offset(uintptr_t address, uintptr_t *bytes, uintptr_t *offset);
int task_ok = 1, atomic_context, irq_off, probe_error, probes, removed, calls;
int read_error, self_mismatch;
int fixture_size_mode;
uintptr_t probe_address;
unsigned int entry_instruction = 0xd503245f;
const char *symbol_text = "kallsyms_lookup_name+0/0x40";
int in_task(void) { return task_ok; }
int in_atomic(void) { return atomic_context; }
int irqs_disabled(void) { return irq_off; }
int register_kprobe(struct kprobe *p) {
    ++probes;
    if (strcmp(p->symbol_name, "kallsyms_lookup_name")) return -EINVAL;
    p->addr = (void *)probe_address;
    return probe_error;
}
void unregister_kprobe(struct kprobe *p) { (void)p; ++removed; }
int sprint_symbol(char *buffer, uintptr_t address) {
    (void)address; return sprintf(buffer, "%s", symbol_text);
}
long copy_from_kernel_nofault(void *to, const void *from, size_t bytes) {
    (void)from;
    if (read_error) return -EFAULT;
    if (bytes != sizeof entry_instruction) return -EINVAL;
    memcpy(to, &entry_instruction, bytes); return 0;
}
__attribute__((aligned(16),__noinline__)) int fixture_symbol_size(uintptr_t address, uintptr_t *bytes, uintptr_t *offset) {
    *bytes = fixture_size_mode == 1 ? 0 : fixture_size_mode == 3 ? UINTPTR_MAX : 64;
    *offset = fixture_size_mode == 2 ? 4 : 0;
    (void)address; return fixture_size_mode == 4 ? 0 : 1;
}
__attribute__((aligned(16),__noinline__)) uintptr_t fixture_lookup(const char *name) {
    ++calls;
    if (!strcmp(name, "kallsyms_lookup_size_offset")) return (uintptr_t)fixture_symbol_size;
    if (!strcmp(name, "missing")) return 0;
    return (uintptr_t)fixture_lookup + self_mismatch * 4;
}
"""
CASES = r"""
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "lookup fixture line %d\n", __LINE__); return 1; } } while (0)
void reset_fixture(void) {
    native_lookup = NULL; task_ok = 1; atomic_context = irq_off = probe_error = 0;
    probes = removed = calls = read_error = self_mismatch = fixture_size_mode = 0;
    probe_address = (uintptr_t)fixture_lookup; entry_instruction = 0xd503245f;
    symbol_text = "kallsyms_lookup_name+0/0x40";
}
int main(void) {
    uintptr_t resolved = 123;
    const void *reference = (const void *)fixture_lookup;
    reset_fixture();
#if MSU_INIT_BRIDGE_CFI_LEGACY
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !probes && !calls);
    CHECK(msu_init_bridge_resolve_cfi("callable", reference, &resolved) == -EOPNOTSUPP);
    CHECK(resolved == 123);
#else
    CHECK(MSU_INIT_BRIDGE_CFI_NONE && !MSU_INIT_BRIDGE_CFI_KCFI);
    CHECK(msu_init_bridge_resolve_cfi("callable", reference, &resolved) == -EAGAIN && resolved == 123);
    CHECK(msu_init_bridge_resolve_cfi(NULL, reference, &resolved) == -EINVAL);
    probe_error = -EPERM;
    CHECK(msu_init_bridge_lookup_init() == -EPERM && probes == 1 && !removed && !calls);
    reset_fixture(); task_ok = 0;
    CHECK(msu_init_bridge_lookup_init() == -EWOULDBLOCK && !probes);
    reset_fixture(); atomic_context = 1;
    CHECK(msu_init_bridge_lookup_init() == -EWOULDBLOCK && !probes);
    reset_fixture(); irq_off = 1;
    CHECK(msu_init_bridge_lookup_init() == -EWOULDBLOCK && !probes);
    reset_fixture();
    CHECK(msu_init_bridge_lookup_init() == 0 && probes == 1 && removed == 1 && calls == 1);
    CHECK(msu_init_bridge_lookup_init() == -EALREADY && probes == 1);
    CHECK(msu_init_bridge_resolve_cfi("callable", reference, &resolved) == 0 && resolved == (uintptr_t)fixture_lookup);
    {
        uintptr_t address = 123, bytes = 456;
        CHECK(msu_init_bridge_lookup_size("callable", &address, &bytes) == 0 &&
            address == (uintptr_t)fixture_lookup && bytes == 64);
        address = 123; bytes = 456;
        CHECK(msu_init_bridge_lookup_size("missing", &address, &bytes) == -ENOENT && address == 123 && bytes == 456);
        CHECK(msu_init_bridge_lookup_size(NULL, &address, &bytes) == -EINVAL && address == 123 && bytes == 456);
        for (fixture_size_mode = 1; fixture_size_mode <= 4; ++fixture_size_mode) {
            CHECK(msu_init_bridge_lookup_size("callable", &address, &bytes) == -EOPNOTSUPP && address == 123 && bytes == 456);
        }
    }
    reset_fixture(); probe_address += 4; symbol_text = "kallsyms_lookup_name+0x4/0x40";
    CHECK(msu_init_bridge_lookup_init() == 0 && calls == 1 && removed == 1);
    reset_fixture(); probe_address += 4; symbol_text = "kallsyms_lookup_name+0x4/0x40"; read_error = 1;
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !calls && !native_lookup && removed == 1);
    reset_fixture(); probe_address += 4; symbol_text = "kallsyms_lookup_name+0x4/0x40"; entry_instruction = 0xd503201f;
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !calls);
    const char *bad[] = { "0x1234", "other+0/0x40", "kallsyms_lookup_name+0x8/0x40",
        "kallsyms_lookup_name+0x4/0x4", "kallsyms_lookup_name+0/0x40 [module]" };
    for (unsigned int i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        reset_fixture(); symbol_text = bad[i];
        CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !calls && !native_lookup);
    }
    reset_fixture(); probe_address = 0;
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !calls);
    reset_fixture(); probe_address += 1;
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && !calls);
    reset_fixture(); self_mismatch = 1;
    CHECK(msu_init_bridge_lookup_init() == -EOPNOTSUPP && calls == 1 && !native_lookup);
#endif
    return 0;
}
"""


class CfiLookupChecks(unittest.TestCase):
    def run_fixture(self, legacy):
        originals = {name: (BRIDGE / name).read_bytes()
                     for name in ("native_lookup.c", "native_lookup.h", "native_cfi.h")}
        with tempfile.TemporaryDirectory(prefix="bridge-cfi-lookup-") as directory:
            output = Path(directory)
            for name in ("compiler", "errno", "irqflags", "kallsyms", "kernel", "kprobes", "preempt", "uaccess"):
                path = output / "linux" / (name + ".h")
                path.parent.mkdir(exist_ok=True)
                path.write_text("/* host fixture declarations are preincluded */\n")
            for name, data in originals.items():
                data = data.replace(b"unsigned long", b"uintptr_t")
                if name == "native_lookup.c":
                    data = data.replace(b'"kallsyms_lookup_name+%lx/%lx%c"',
                                        b'"kallsyms_lookup_name+%" SCNxPTR "/%" SCNxPTR "%c"')
                (output / name).write_bytes(data)
            source = output / "fixture.c"
            source.write_text(DEFINITIONS + '\n#include "native_lookup.c"\n' + CASES)
            binary = output / "fixture.exe"
            argv = [CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-UNDEBUG", "-I" + str(output)]
            if legacy:
                argv.append("-DCONFIG_CFI_CLANG=1")
            argv += [str(source), "-o", str(binary)]
            subprocess.run(argv, check=True, timeout=25)
            subprocess.run([str(binary)], check=True, timeout=5)
        for name, data in originals.items():
            self.assertEqual((BRIDGE / name).read_bytes(), data, "source changed: " + name)

    def test_natural_no_cfi_entry_and_errors(self):
        self.run_fixture(False)

    def test_legacy_cfi_stops_before_probe(self):
        self.run_fixture(True)


if __name__ == "__main__":
    unittest.main()
