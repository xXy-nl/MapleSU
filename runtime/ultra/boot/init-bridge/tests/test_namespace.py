"""Bridge namespace/config2 seam only, with real formally selected ABI headers.

The fixture replaces kernel/providers with mocks, never loads a module, emits no
ko and uses only a memory-only known credential for the bridge's shape check.
The actual host's copy/command27 path still needs its own owner validation.
Only the host LLP64 copy translates unsigned-long image carriers to uintptr_t;
actual ARM64 TU validation always uses original product bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
REPO = BRIDGE.parents[3]
SELECTION = REPO / ".tmp/p2-host-final-20261118/core-builder/deployment54/HOST-DEPLOYMENT-SOURCE-SELECTION.json"
SELECTION_SHA256 = "34058fd92ddd84a1a7f6d678fae4239f142c028fdc583dd56b78df2b38b671a1"
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
SHIMS = r"""
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#define __init
#define __exit
#define module_init(x)
#define module_exit(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 18, 21)
#define MODULE_IMPORT_NS(x) _Static_assert(sizeof(x) > 1, "module namespace literal")
#define module_param_string(name, value, length, permission) \
    _Static_assert(sizeof(value) == (length) && (permission) == 0, "module parameter shape/perm0")
#define THIS_MODULE ((void *)0)
#define WARN_ON_ONCE(x) ((void)(x))
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define READ_ONCE(value) (value)
#define MSU_DYN_FIELD(task, owner, member) fixture_pid
static int msu_runtime_layout_ready(void) { return 1; }
int msu_preinit_start(void) { return 0; }
void msu_preinit_release(void) {}
int fixture_pid = 1, pinned;
#define current ((void *)0)
int task_pid_nr(const void *task) { (void)task; return fixture_pid; }
void __module_get(const void *module) { (void)module; ++pinned; }
void memzero_explicit(void *value, size_t bytes) {
    volatile unsigned char *p = value;
    while (bytes--) *p++ = 0;
}
#define MSU_BOOT_SDK_KEY_BYTES 48
#define MSU_BOOT_SDK_ALLOCATOR_NOPROF 1
#define MSU_BOOT_SDK_ALLOCATOR_INNER 2
#define MSU_BOOT_SDK_ALLOCATOR_SEGMENTED 8
struct msu_boot_sdk_layout { unsigned int environment; };
int msu_init_bridge_imports_init(void);
int msu_init_bridge_lookup_init(void);
unsigned long msu_init_bridge_checked_lookup(const char *name);
int msu_init_bridge_native_layout(unsigned int flags, unsigned int execmem_free, struct msu_boot_sdk_layout *layout);
int msu_boot_sdk_native_start(const struct msu_boot_sdk_layout *layout, const char key[48]);
int msu_boot_sdk_native_abort(void);
"""
CASES = r"""
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "namespace fixture line %d\n", __LINE__); return 1; } } while (0)
int lookups, host_calls, provider_calls, config_version, host_error, provider_error, retained;
int host_invalid, environment_seen, event_calls, event_stops, event_error, event_retained;
int native_aborts, phase, cleanup_order, event_stop_order, native_abort_order, layout_error;
struct msu_deployment_namespace_record held;
static const char valid_namespace[] = "aB3dE6gH9jK2mN5p";
int msu_init_bridge_lookup_init(void) { ++lookups; return 0; }
int msu_init_bridge_imports_init(void) { return 0; }
unsigned long msu_init_bridge_checked_lookup(const char *name) { (void)name; return 1; }
int msu_init_bridge_native_layout(unsigned int flags, unsigned int execmem_free, struct msu_boot_sdk_layout *layout) {
    (void)flags; if (execmem_free != 0) host_invalid = 1; layout->environment = 1; phase = 1; return layout_error;
}
int msu_manager_resident_init(const struct msu_resident_config *config) {
    ++host_calls; config_version = config->version;
    if (config->version == 2) {
        const struct msu_resident_config_v2 *v2 = (const void *)config;
        if (v2->config_bytes != 48 || v2->namespace_record_bytes != 24 ||
            v2->image != (void *)0x1000 || v2->append != (void *)0x2000 ||
            v2->append_bytes != 48 || !v2->credential ||
            !msu_deployment_namespace_valid(v2->namespace_record)) host_invalid = 1;
        else held = *v2->namespace_record;
    } else if (config->version != 1 || config->image != (void *)0x1000 ||
            config->append != (void *)0x2000 || config->append_bytes != 48) host_invalid = 1;
    return host_error;
}
int msu_manager_resident_discard(void) { return 0; }
int msu_boot_events_start(const struct msu_deployment_namespace_record *record) {
    ++event_calls;
    if (phase != 1 || !msu_deployment_namespace_valid(record) ||
        memcmp(record->name, valid_namespace, 16)) host_invalid = 1;
    phase = 2;
    return event_error;
}
int msu_boot_events_stop(void) {
    ++event_stops; event_stop_order = ++cleanup_order;
    return event_retained;
}
int msu_boot_sdk_native_start(const struct msu_boot_sdk_layout *layout, const char key[48]) {
    ++provider_calls; environment_seen = layout->environment;
    if (phase != (deployment_namespace[0] ? 2 : 1)) host_invalid = 1;
    phase = 3;
    int error = msu_init_bridge_host_start(0x1000, (void *)0x2000, 48, key);
    return error ? error : provider_error;
}
int msu_boot_sdk_native_abort(void) {
    ++native_aborts; native_abort_order = ++cleanup_order;
    if (event_calls && (!event_stops || event_stop_order >= native_abort_order)) host_invalid = 1;
    for (unsigned int i = 0; i < sizeof credential; ++i) if (credential[i]) host_invalid = 1;
    return retained;
}
static void reset_fixture(void) {
    memset(credential, 'A', 48); credential[48] = 0;
    memcpy(deployment_namespace, valid_namespace, sizeof valid_namespace);
    fixture_pid = 1; host_attempted = false; bridge_first_error = 0;
    lookups = host_calls = provider_calls = config_version = 0;
    host_error = provider_error = retained = pinned = host_invalid = 0;
    environment_seen = -1; memset(&held, 0, sizeof held);
    event_calls = event_stops = event_error = event_retained = native_aborts = 0;
    phase = cleanup_order = event_stop_order = native_abort_order = layout_error = 0;
}
static int cleared(void) {
    for (unsigned int i = 0; i < sizeof credential; ++i) if (credential[i]) return 0;
    for (unsigned int i = 0; i < sizeof deployment_namespace; ++i) if (deployment_namespace[i]) return 0;
    return 1;
}
int main(void) {
    reset_fixture();
    CHECK(msu_init_bridge_start() == 0 && config_version == 2 && !host_invalid);
    CHECK(lookups == 1 && host_calls == 1 && provider_calls == 1 && environment_seen == 1);
    CHECK(event_calls == 1 && !event_stops && !native_aborts && pinned == 1);
    CHECK(cleared() && held.magic == MSU_DEPLOYMENT_NAMESPACE_MAGIC && held.schema == 1 && held.bytes == 24);
    CHECK(!memcmp(held.name, valid_namespace, 16) && msu_deployment_namespace_valid(&held));
    reset_fixture(); deployment_namespace[0] = 0;
    CHECK(msu_init_bridge_start() == 0 && config_version == 1 && !host_invalid && cleared());
    CHECK(!event_calls && !event_stops && !native_aborts);
    const char *bad[] = { "short", "aB3dE6gH9jK2mN5_", "aB3dE6gH9jK2mN5-", "aB3dE6gH9jK2mN5 " };
    for (unsigned int i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        reset_fixture(); memset(deployment_namespace, 0, sizeof deployment_namespace);
        memcpy(deployment_namespace, bad[i], strlen(bad[i]));
        CHECK(msu_init_bridge_start() == -EINVAL && !lookups && !host_calls && cleared());
    }
    reset_fixture(); memset(deployment_namespace, 'Z', sizeof deployment_namespace);
    CHECK(msu_init_bridge_start() == -EINVAL && !lookups && !host_calls && cleared());
    reset_fixture(); fixture_pid = 2;
    CHECK(msu_init_bridge_start() == -EPERM && !lookups && !host_calls && cleared());
    reset_fixture(); credential[0] = '!';
    CHECK(msu_init_bridge_start() == -EINVAL && !lookups && !host_calls && cleared());
    reset_fixture(); host_error = -EIO;
    CHECK(msu_init_bridge_start() == -EIO && config_version == 2 && cleared());
    CHECK(event_calls == 1 && event_stops == 1 && native_aborts == 1 && !host_invalid && !pinned);
    reset_fixture(); layout_error = -EOPNOTSUPP;
    CHECK(msu_init_bridge_start() == -EOPNOTSUPP && cleared() && !event_calls && !provider_calls);
    reset_fixture(); event_error = -EPERM;
    CHECK(msu_init_bridge_start() == -EPERM && event_calls == 1 && event_stops == 1 && !provider_calls);
    CHECK(!native_aborts && !pinned && cleared());
    reset_fixture(); event_error = -EPERM; event_retained = -EBUSY;
    CHECK(msu_init_bridge_start() == 0 && bridge_first_error == -EPERM && pinned == 1 && cleared());
    CHECK(event_stops == 1 && !native_aborts && !provider_calls);
    reset_fixture(); provider_error = -EIO; event_retained = -EBUSY;
    CHECK(msu_init_bridge_start() == 0 && bridge_first_error == -EIO && pinned == 1 && cleared());
    CHECK(event_stops == 1 && native_aborts == 1 && !host_invalid);
    reset_fixture(); provider_error = -EIO; event_retained = -EBUSY; retained = -EINPROGRESS;
    CHECK(msu_init_bridge_start() == 0 && bridge_first_error == -EIO && pinned == 1 && cleared());
    CHECK(event_stops == 1 && native_aborts == 1 && !host_invalid);
    reset_fixture(); deployment_namespace[0] = 0; provider_error = -EIO;
    CHECK(msu_init_bridge_start() == -EIO && !event_calls && !event_stops && native_aborts == 1 && cleared());
    reset_fixture(); provider_error = -EIO; retained = -EINPROGRESS;
    CHECK(msu_init_bridge_start() == 0 && bridge_first_error == -EIO && pinned == 1 && cleared());
    CHECK(msu_deployment_namespace_valid(&held) && !memcmp(held.name, valid_namespace, 16));
    CHECK(event_stops == 1 && native_aborts == 1 && !host_invalid);
    msu_init_bridge_exit();
    return 0;
}
"""


class NamespaceChecks(unittest.TestCase):
    def test_parameter_config2_record_and_cleanup(self):
        selection_data = SELECTION.read_bytes()
        self.assertEqual(hashlib.sha256(selection_data).hexdigest(), SELECTION_SHA256)
        selected = {row["logicalPath"]: row["after"] for row in json.loads(selection_data)["files"]}
        headers, originals = {}, {SELECTION: selection_data, BRIDGE / "bridge.c": (BRIDGE / "bridge.c").read_bytes(),
                                  BRIDGE / "boot_events.h": (BRIDGE / "boot_events.h").read_bytes()}
        for name in ("manager_claim_loader.h", "manager_deployment_namespace.h", "manager_resident_abi.h", "manager_resident_host.h"):
            row = selected["runtime/ultra/identity/kernel/" + name]
            path = Path(row["path"])
            data = path.read_bytes()
            self.assertEqual(len(data), row["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
            headers[name] = data
            originals[path] = data
        with tempfile.TemporaryDirectory(prefix="bridge-namespace-") as directory:
            output = Path(directory)
            for name in ("errno", "init", "module", "pid", "sched", "string", "version"):
                path = output / "linux" / (name + ".h")
                path.parent.mkdir(exist_ok=True)
                path.write_text("/* explicit host fixture kernel declarations */\n")
            for name in ("native_imports.h", "native_layout.h", "native_lookup.h", "native_sdk.h",
                         "manager_dynamic_layout.h", "preinit.h"):
                (output / name).write_text("/* fixture provider declarations are preincluded */\n")
            (output / "boot_events.h").write_bytes(originals[BRIDGE / "boot_events.h"])
            for name, data in headers.items():
                (output / name).write_bytes(data)
            (output / "bridge.c").write_bytes(originals[BRIDGE / "bridge.c"].replace(b"unsigned long", b"uintptr_t"))
            source = output / "fixture.c"
            source.write_text(SHIMS + '\n#include "bridge.c"\n' + CASES)
            binary = output / "fixture.exe"
            environment = dict(os.environ, PATH=str(Path(CC).parent) + os.pathsep + os.environ.get("PATH", ""))
            compiled = subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                                       "-I" + str(output), str(source), "-o", str(binary)],
                                      env=environment, capture_output=True, text=True, timeout=25)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            subprocess.run([str(binary)], check=True, env=environment, timeout=5)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data, "input changed: " + str(path))


if __name__ == "__main__":
    unittest.main()
