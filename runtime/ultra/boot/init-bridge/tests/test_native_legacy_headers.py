"""Normal loaded-module readiness, without a synthetic owner-workqueue gate.

The exact production readiness body executes with loader/context boundaries.
This does not emulate the target compiler's CFI or native module loader.
"""
import os
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BRIDGE = Path(__file__).parents[1]
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")

FIXTURE = r"""
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#ifndef ESTALE
#define ESTALE 116
#endif
typedef uint32_t u32;
enum { MODULE_STATE_COMING, MODULE_STATE_LIVE, MODULE_STATE_GOING };
struct module { int state; void *cfi_check; } owner;
#define THIS_MODULE (&owner)
#define READ_ONCE(value) (value)
static int task_context = 1, atomic_context, irq_off, work_calls;
static int in_task(void) { return task_context; }
static int in_atomic(void) { return atomic_context; }
static int irqs_disabled(void) { return irq_off; }
/* Old-source dependencies make its extra admission gate observable. */
struct msu_legacy_probe_work { int work; struct module *owner; int result; };
static __attribute__((unused)) int probe(struct module *value) { return value == THIS_MODULE ? 0 : -ESTALE; }
static __attribute__((unused)) int (*msu_legacy_probe)(struct module *) = probe;
static __attribute__((unused)) void __cfi_check(void) {}
static __attribute__((unused)) bool msu_legacy_module_text(const void *first, uintptr_t bytes)
{ (void)first; (void)bytes; return true; }
#define INIT_WORK_ONSTACK(work, handler) ((void)(work), ++work_calls)
#define schedule_work(work) ((void)(work), ++work_calls, false)
#define flush_work(work) ((void)(work), ++work_calls)
#define destroy_work_on_stack(work) ((void)(work), ++work_calls)
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "legacy readiness line %d: %s\n", __LINE__, #x); return 1; } } while (0)
"""

CASES = r"""
int main(void)
{
    owner.state = MODULE_STATE_COMING; owner.cfi_check = NULL;
    CHECK(msu_legacy_module_ready() == 0 && !work_calls);
    owner.state = MODULE_STATE_LIVE; owner.cfi_check = (void *)__cfi_check;
    CHECK(msu_legacy_module_ready() == 0 && !work_calls);
    owner.cfi_check = (void *)1;
    CHECK(msu_legacy_module_ready() == 0 && !work_calls);
    owner.state = MODULE_STATE_GOING;
    CHECK(msu_legacy_module_ready() == -ESTALE && !work_calls);
    owner.state = MODULE_STATE_COMING; task_context = 0;
    CHECK(msu_legacy_module_ready() == -EWOULDBLOCK && !work_calls);
    task_context = 1; atomic_context = 1;
    CHECK(msu_legacy_module_ready() == -EWOULDBLOCK && !work_calls);
    atomic_context = 0; irq_off = 1;
    CHECK(msu_legacy_module_ready() == -EWOULDBLOCK && !work_calls);
    return 0;
}
"""


class LegacyCfiHeaderChecks(unittest.TestCase):
    def test_module_declarations_precede_the_native_loader_header(self):
        source = (BRIDGE / "native_legacy_cfi.c").read_text(encoding="utf-8")
        self.assertLess(source.index("#include <linux/module.h>"),
                        source.index('#include "native_legacy_cfi.h"'))

    def test_readiness_uses_real_loader_lifecycle_without_workqueue_probe(self):
        source = (BRIDGE / "native_legacy_cfi.c").read_text(encoding="utf-8")
        start = source.index("int msu_legacy_module_ready(void)")
        end = source.index("\nstatic int msu_legacy_read_word(", start)
        body = source[start:end].replace("unsigned long", "uintptr_t")
        with tempfile.TemporaryDirectory(prefix="bridge-legacy-ready-") as directory:
            generated, binary = Path(directory) / "fixture.c", Path(directory) / "fixture.exe"
            generated.write_text(FIXTURE + body + CASES, encoding="utf-8")
            subprocess.run([CC, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O1",
                            str(generated), "-o", str(binary)], check=True, timeout=20)
            subprocess.run([str(binary)], check=True, timeout=5)

    def test_package_membership_uses_only_actual_native_consumers(self):
        spec = importlib.util.spec_from_file_location("native_legacy_contract_test", BRIDGE / "legacy_cfi_contract.py")
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)
        calls = []

        class Checker:
            def __init__(self, data):
                self.asserted_data = data

            def member(self, name, callsites):
                if name not in ("init_module", "actual_callback"):
                    raise ValueError("retired synthetic owner callback requested: " + name)
                calls.append((name, callsites))
                return {"symbol": name}

        target = {"mode": "legacy-lto-cfi", "initCallsites": [1],
                  "workCallsites": [2], "callbackCallsites": {"actual_callback": [3]}}
        with patch.object(contract, "ModuleChecker", Checker):
            result = contract.verify_module(b"actual-parser-boundary", target, ("actual_callback",))
        self.assertEqual([("init_module", [1]), ("actual_callback", [3])], calls)
        self.assertEqual([{"symbol": "init_module"}, {"symbol": "actual_callback"}], result["members"])
        self.assertFalse(result["moduleLoaded"])


if __name__ == "__main__":
    unittest.main()
