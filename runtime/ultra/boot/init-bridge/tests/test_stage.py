"""Memory-only staging and host execution of the real generated adapter with mocks."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bridge_stage", Path(__file__).parents[1] / "stage.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class StageChecks(unittest.TestCase):
    def setUp(self):
        root = (Path(__file__).parent / "memory-stage-fixture").resolve()
        self.candidate, self.repo = root / "candidate", root / "repo"
        self.host, self.core, self.su = root / "host", root / "revision3/source", root / "su"
        self.bridge = self.candidate / "runtime/ultra/boot/init-bridge"
        self.output = root / "out"
        self.reads = []
        self.files = {self.bridge / "bridge.c": b"/* memory-only caller */\n",
                      self.bridge / "native_sdk.h": b"/* no compiled credential */\n",
                      self.bridge / "preinit/runner.c": b"/* memory-only preinit caller */\n",
                      self.bridge / "Kbuild": (Path(__file__).parents[1] / "Kbuild").read_bytes()}
        self.private = "runtime/ultra/identity/kernel/"
        units = ("install_records", "protected_install_kernel", "manager_apk_identity", "manager_claim_entry",
                 "manager_owner", "manager_owner_watch", "manager_resident_host", "manager_management",
                 "manager_uid_gateway", "manager_uid_snapshot", "manager_task_state", "manager_credential_domain")
        for unit in units:
            for suffix in (".c", ".h"):
                relative = self.private + unit + suffix
                self.files[self.repo / relative] = ("original:" + relative).encode()
                if unit in ("manager_management", "manager_uid_snapshot", "manager_task_state", "manager_credential_domain"):
                    self.files[self.core / relative] = ("core:" + relative).encode()
        for name in ("manager_claim_abi.h", "manager_owner_claim.h", "manager_resident_abi.h", "manager_claim_loader.h"):
            self.files[self.repo / self.private / name] = ("original:" + name).encode()
        self.files[self.host / self.private / "manager_resident_abi.h"] = b"host overlay header"
        self.files[self.core / self.private / "manager_credential_profile.h"] = b"core profile header"
        self.files[self.core / self.private / "manager_deployment_namespace.h"] = b"core deployment record header"
        self.files[self.core / self.private / "manager_early_helper.h"] = b"core early helper header"
        self.files[self.core / self.private / "manager_legacy_hook.inc"] = b"core native legacy provider"
        for name in ("request_protocol.h", "execution_frame.h", "legacy_hook_private.h", "publication_return_private.h"):
            self.files[self.core / "runtime/ultra/authorization" / name] = ("core:" + name).encode()
        self.su_units = ("su_install_registry", "su_profile_apply", "su_profile_namespace",
                         "su_profile_execution", "su_profile_resolve")
        self.su_kernel = "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/"
        for unit in self.su_units:
            for suffix in (".c", ".h"):
                name = unit + suffix
                self.files[self.su / self.su_kernel / name] = name.encode()
        for name in ("module/maplesu_boot_sdk.c", "module/boot_sdk_call.S", "module/boot_sdk_protocol.h",
                     "module/boot_sdk_allocator.h", "boot_sdk_abi.h"):
            self.files[self.repo / "jailbreak-providers/root-loader" / name] = name.encode()
        self.files[root / "kernel/build/.config"] = b"CONFIG_ARM64_4K_PAGES=y\n"
        self.files[root / "kernel/source/include/linux/fs_struct.h"] = (
            b"struct fs_struct { seqlock_t seq; } __randomize_layout;\n")
        self.files[root / "kernel/source/include/linux/execmem.h"] = b"void *execmem_alloc_rw(enum execmem_type, size_t);\n"
        self.directories = {parent for path in self.files for parent in path.parents}
        self.argv = ["stage.py"]
        for name, path in (("repo-root", self.repo), ("host-overlay", self.host), ("core-overlay", self.core),
                           ("su-overlay", self.su), ("kernel-source", root / "kernel/source"),
                           ("kernel-build", root / "kernel/build"), ("out", self.output)):
            self.argv.extend(["--" + name, str(path)])

    def run_stage(self, replace_after_read=None, replace_during_write=None):
        def read(path):
            self.reads.append(path)
            if path not in self.files:
                raise FileNotFoundError(str(path))
            data = self.files[path]
            if path == replace_after_read:
                self.files[path] = data + b"changed"
            return data

        def mkdir(path, **kwargs):
            self.directories.add(path)

        def write(path, data):
            self.files[path] = data
            if replace_during_write is not None:
                self.files[replace_during_write] += b"changed"
            return len(data)

        with ExitStack() as stack:
            for name, replacement in (
                ("read_bytes", read), ("read_text", lambda p, **kw: read(p).decode("utf-8")),
                ("is_file", lambda p: p in self.files),
                ("exists", lambda p: p in self.files or p in self.directories),
                ("iterdir", lambda p: iter([f for f in self.files if f.parent == p])),
                ("mkdir", mkdir), ("write_bytes", write),
                ("write_text", lambda p, text, **kw: write(p, text.encode("utf-8")))):
                stack.enter_context(patch.object(Path, name, replacement))
            stack.enter_context(patch.object(stage, "__file__", str(self.bridge / "stage.py")))
            stack.enter_context(patch.object(sys, "argv", self.argv))
            stage.main()
        return json.loads(self.files[self.output / "SOURCE-SELECTION.json"])

    def test_stage_needs_no_credential_and_generates_none(self):
        receipt = self.run_stage()
        self.assertNotIn(self.output / "bridge_credential.c", self.files)
        self.assertNotIn(self.output / "bridge_credential.h", self.files)
        self.assertNotIn(b"bridge_credential.o", self.files[self.output / "Kbuild"])
        self.assertEqual(receipt["credentialMode"], "module-parameter")
        self.assertNotIn("credentialSha256", receipt)
        self.assertFalse(any("credential" in path.name and not path.name.startswith("manager_") for path in self.reads))
        self.assertFalse(any(path.suffix == ".ko" for path in self.files))
        self.assertFalse(receipt["compiled"])

    def test_current_producer_copies_its_legacy_scope_header_from_core(self):
        producer = "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"
        header = "runtime/ultra/authorization/legacy_hook_private.h"
        self.files[self.candidate / producer] = b'#include "legacy_hook_private.h"\n'
        self.files[self.core / header] = b"core same-generation legacy scope header"
        self.files[self.repo / header] = b"old fallback header"
        receipt = self.run_stage()
        selected = {row["staged"]: Path(row["selected"]["path"]) for row in receipt["inputs"]}
        self.assertEqual(selected["legacy_hook_private.h"], self.core / header)
        self.assertEqual(self.files[self.output / "legacy_hook_private.h"], self.files[self.core / header])

    def test_current_producer_missing_legacy_scope_header_has_no_success_receipt(self):
        producer = "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"
        self.files[self.candidate / producer] = b'#include "legacy_hook_private.h"\n'
        del self.files[self.core / "runtime/ultra/authorization/legacy_hook_private.h"]
        with self.assertRaisesRegex(ValueError, "SOURCE_MISSING:runtime/ultra/authorization/legacy_hook_private.h"):
            self.run_stage()
        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def private_management_includes(self):
        self.files[self.core / self.private / "manager_management.c"] = (
            b'#include "publication_return_private.h"\n#include "manager_legacy_provider.inc"\n'
            b'#include "manager_legacy_hook.inc"\n'
            b'#if defined(MSU_MANAGEMENT_NATIVE_TEXT_OWNER) && MSU_MANAGEMENT_NATIVE_TEXT_OWNER\n'
            b'#include "native-text/kprobe_text_owner.h"\n#endif\n')
        dependencies = {
            "runtime/ultra/authorization/publication_return_private.h":
                b'#include "request_protocol.h"\n',
            self.private + "manager_legacy_provider.inc": b"/* actual CORE resident registry */\n",
            self.private + "manager_legacy_hook.inc": b"/* actual CORE companion */\n",
            self.private + "native-text/kprobe_text_owner.h":
                b'#include <linux/types.h>\n#include <linux/maplesu/legacy_hook_private.h>\n',
            "runtime/ultra/authorization/legacy_hook_private.h": b'#include "request_protocol.h"\n',
        }
        for relative, data in dependencies.items():
            self.files[self.core / relative] = data
            self.files[self.repo / relative] = b"old fallback dependency"
        return dependencies

    def test_selected_management_private_include_closure_uses_exact_core_inputs(self):
        self.private_management_includes()
        receipt = self.run_stage()
        selected = {row["staged"]: row for row in receipt["selectedCorePrivateIncludes"]}
        expected = {
            "publication_return_private.h": "runtime/ultra/authorization/publication_return_private.h",
            "host/manager_legacy_provider.inc": self.private + "manager_legacy_provider.inc",
            "host/manager_legacy_hook.inc": self.private + "manager_legacy_hook.inc",
            "host/native-text/kprobe_text_owner.h": self.private + "native-text/kprobe_text_owner.h",
            "linux/maplesu/legacy_hook_private.h": "runtime/ultra/authorization/legacy_hook_private.h",
        }
        self.assertEqual(set(selected), set(expected))
        for staged, relative in expected.items():
            source = self.core / relative
            self.assertEqual(selected[staged]["selected"], stage.identity(source, self.files[source]))
            self.assertEqual(self.files[self.output / staged], self.files[source])
            self.assertEqual(selected[staged]["selection"], "core-private-include")
        self.assertEqual(selected["linux/maplesu/legacy_hook_private.h"]["includedBy"],
                         "host/native-text/kprobe_text_owner.h")
        self.assertFalse(receipt["targetQualified"])
        self.assertNotIn(b"-DMSU_MANAGEMENT_NATIVE_TEXT_OWNER=1", self.files[self.output / "selected-core.mk"])
        self.assertNotIn(b"-DMSU_MANAGEMENT_RESIDENT_TEXT_OWNER=1", self.files[self.output / "selected-core.mk"])

    def test_formal_runtime_follows_selected_management_private_includes(self):
        self.private_management_includes()
        self.runtime_selections()
        receipt = self.run_stage()
        selected = {row["staged"]: row for row in receipt["inputs"]}
        self.assertEqual(selected["host/manager_management.c"]["selected"],
                         self.runtime_members["manager_management.c"])
        companion = selected["host/manager_legacy_hook.inc"]
        self.assertEqual(companion["selected"], self.runtime_members["manager_legacy_hook.inc"])
        self.assertEqual(companion["selection"], "host-runtime-frozen")
        self.assertEqual(companion["includedBy"], "host/manager_management.c")
        provider = selected["host/manager_legacy_provider.inc"]
        self.assertEqual(provider["selected"], self.runtime_members["manager_legacy_provider.inc"])
        self.assertEqual(provider["selection"], "host-runtime-frozen")
        self.assertEqual(provider["includedBy"], "host/manager_management.c")
        declaration = selected["host/native-text/kprobe_text_owner.h"]
        self.assertEqual(declaration["selection"], "core-private-include")
        self.assertEqual(declaration["includedBy"], "host/manager_management.c")
        self.assertFalse(receipt["wholeCoreSnapshotSelected"])

    def test_formal_runtime_legacy_companion_drift_keeps_identity_failure(self):
        self.runtime_selections()
        member = Path(self.runtime_members["manager_legacy_hook.inc"]["path"])
        self.files[member] += b"changed after formal freeze"
        with self.assertRaisesRegex(ValueError, "IDENTITY:.*manager_legacy_hook.inc"):
            self.run_stage()
        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_formal_runtime_resident_provider_drift_keeps_identity_failure(self):
        self.private_management_includes()
        self.runtime_selections()
        member = Path(self.runtime_members["manager_legacy_provider.inc"]["path"])
        self.files[member] += b"changed after formal freeze"
        with self.assertRaisesRegex(ValueError, "IDENTITY:.*manager_legacy_provider.inc"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)
        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_resident_provider_change_during_selection_has_no_success_receipt(self):
        self.private_management_includes()
        member = self.core / self.private / "manager_legacy_provider.inc"
        original, directories = dict(self.files), set(self.directories)
        for mutation in ("replace_after_read", "replace_during_write"):
            with self.subTest(mutation=mutation):
                self.files, self.directories = dict(original), set(directories)
                with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED_DURING_SELECTION:.*manager_legacy_provider.inc"):
                    self.run_stage(**{mutation: member})
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_missing_management_private_include_leaves_no_success_receipt(self):
        dependencies = self.private_management_includes()
        original, directories = dict(self.files), set(self.directories)
        for relative in dependencies:
            with self.subTest(input=relative):
                self.files, self.directories = dict(original), set(directories)
                for root in (self.core, self.repo):
                    del self.files[root / relative]
                with self.assertRaisesRegex(ValueError, "SOURCE_MISSING:" + relative):
                    self.run_stage()
                self.assertNotIn(self.output, self.directories)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_unreferenced_optional_native_include_is_not_staged(self):
        self.private_management_includes()
        self.files[self.core / self.private / "manager_management.c"] = b"/* preceding CORE */\n"
        receipt = self.run_stage()
        self.assertEqual(receipt["selectedCorePrivateIncludes"], [])
        self.assertNotIn(self.output / "host/manager_legacy_provider.inc", self.files)
        self.assertNotIn(self.output / "host/manager_legacy_hook.inc", self.files)
        self.assertNotIn(self.output / "host/native-text/kprobe_text_owner.h", self.files)

    def test_identity_uses_captured_bytes_without_another_read(self):
        path = self.bridge / "bridge.c"
        with patch.object(Path, "read_bytes", side_effect=AssertionError("identity reread")):
            captured = stage.identity(path, b"captured source")
        self.assertEqual(captured["bytes"], len(b"captured source"))
        self.assertEqual(captured["sha256"], stage.hashlib.sha256(b"captured source").hexdigest())

    def test_core_domain_profile_and_members_use_selected_overlay(self):
        receipt = self.run_stage()
        selected = {row["staged"]: Path(row["selected"]["path"]) for row in receipt["inputs"]}
        for name in ("manager_credential_domain.c", "manager_credential_domain.h", "manager_credential_profile.h",
                     "manager_management.c", "manager_uid_snapshot.c", "manager_task_state.c"):
            source = self.core / self.private / name
            self.assertEqual(selected["host/" + name], source)
            self.assertEqual(self.files[self.output / "host" / name], self.files[source])
        self.assertEqual(selected["host/install_records.c"], self.repo / self.private / "install_records.c")
        self.assertEqual(selected["host/manager_resident_abi.h"], self.host / self.private / "manager_resident_abi.h")
        objects = ["host/manager_task_state.o", "host/manager_credential_domain.o"]
        self.assertEqual(receipt["selectedCoreDependencyObjects"], objects)
        self.assertIn(("maplesu_ultra_bridge-y += " + " ".join(objects)).encode(), self.files[self.output / "selected-core.mk"])
        self.assertFalse(receipt["wholeCoreSnapshotSelected"])

    def test_missing_core_domain_or_profile_is_not_fabricated(self):
        for name in ("manager_credential_domain.c", "manager_credential_domain.h", "manager_credential_profile.h"):
            with self.subTest(input=name):
                removed = {path: self.files.pop(path) for path in
                           [root / self.private / name for root in (self.core, self.host, self.repo)] if path in self.files}
                try:
                    with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SOURCE_MISSING:.*" + name):
                        self.run_stage()
                    self.assertNotIn(self.output, self.directories)
                    self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)
                finally:
                    self.files.update(removed)

    def test_captured_source_and_generation_inputs_must_remain_unchanged(self):
        source = self.core / self.private / "manager_management.c"
        config = next(path for path in self.files if path.name == ".config")
        fs = next(path for path in self.files if path.name == "fs_struct.h")
        execmem = next(path for path in self.files if path.name == "execmem.h")
        original = dict(self.files)
        original_directories = set(self.directories)
        for changed in (source, config, fs, execmem):
            with self.subTest(input=str(changed)):
                self.files = dict(original)
                self.directories = set(original_directories)
                if changed == source:
                    expected = "ULTRA_BRIDGE_SOURCE_CHANGED_DURING_SELECTION:.*manager_management.c"
                    kwargs = {"replace_after_read": changed}
                else:
                    expected = "ULTRA_BRIDGE_GENERATION_INPUT_CHANGED:.*" + changed.name
                    kwargs = {"replace_during_write": changed}
                with self.assertRaisesRegex(ValueError, expected):
                    self.run_stage(**kwargs)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_formal_five_su_units_headers_and_kbuild_are_selected_together(self):
        receipt = self.run_stage()
        selected = {row["staged"]: row for row in receipt["inputs"]}
        expected = {"host/" + unit + suffix for unit in self.su_units for suffix in (".c", ".h")}
        self.assertEqual({name for name in selected if name.startswith("host/su_")}, expected)
        for name in expected:
            source = self.su / self.su_kernel / Path(name).name
            self.assertEqual(Path(selected[name]["selected"]["path"]), source)
            self.assertEqual(self.files[self.output / name], self.files[source])
        objects = ["host/" + unit + ".o" for unit in self.su_units]
        self.assertEqual(receipt["selectedSuComponentObjects"], objects)
        kbuild = self.files[self.output / "Kbuild"].decode()
        for obj in objects:
            self.assertEqual(kbuild.split().count(obj), 1)
        for name in ("manager_management.h", "manager_uid_gateway.h", "manager_uid_snapshot.h",
                     "manager_task_state.h", "manager_credential_profile.h"):
            self.assertIn("host/" + name, selected)
        self.assertIn("request_protocol.h", selected)
        self.assertNotIn("-DMSU_MANAGEMENT_PROFILE_DOMAIN_VERIFIED=1", kbuild)
        self.assertNotIn("-DMSU_SU_NAMESPACE_NATIVE_VERIFIED=1", kbuild)
        self.assertNotIn("MSU_MANAGEMENT_PUBLICATION_GATE_VERIFIED", kbuild)
        self.assertFalse(any("su_native_reader_abi.h" in name for name in selected))
        self.assertEqual(receipt["credentialMode"], "module-parameter")

    def test_missing_any_formal_su_member_leaves_no_success_receipt(self):
        for unit in self.su_units:
            for suffix in (".c", ".h"):
                with self.subTest(input=unit + suffix):
                    path = self.su / self.su_kernel / (unit + suffix)
                    data = self.files.pop(path)
                    try:
                        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SOURCE_MISSING:.*" + unit):
                            self.run_stage()
                        self.assertNotIn(self.output, self.directories)
                        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)
                    finally:
                        self.files[path] = data

    def test_management_provider_dependencies_are_staged_with_exact_identity(self):
        self.private_management_includes()
        receipt = self.run_stage()
        rows = {row["staged"]: row for row in receipt["inputs"]}
        for source, destination in (
                (self.core / self.private / "manager_legacy_hook.inc", "host/manager_legacy_hook.inc"),
                (self.core / self.private / "manager_early_helper.h", "host/manager_early_helper.h"),
                (self.core / "runtime/ultra/authorization/legacy_hook_private.h", "legacy_hook_private.h"),
                (self.core / "runtime/ultra/authorization/publication_return_private.h", "publication_return_private.h")):
            self.assertEqual(rows[destination]["selected"], stage.identity(source, self.files[source]))
            self.assertEqual(self.files[self.output / destination], self.files[source])


    def deployment_selections(self):
        self.core_selection = self.repo / "core-selection.json"
        self.host_selection = self.repo / "host-selection.json"
        self.freeze = self.repo / "core54-freeze.json"
        resident = self.core / self.private / "manager_resident_host.c"
        self.files[resident] = b"core54 resident baseline"
        corrected = self.host / "host-correction/manager_resident_host.c"
        self.files[corrected] = b"final host config2 correction over core54"
        flat = self.host / "selected-native/manager_resident_abi.h"
        self.files[flat] = b"formally mapped flat ABI header"
        self.files[self.freeze] = json.dumps({"sourceRoot": str(self.core)}).encode()
        def selected(path):
            return stage.identity(path, self.files[path])
        paths = [resident, self.core / self.private / "manager_deployment_namespace.h",
                 self.core / "runtime/ultra/authorization/request_protocol.h"]
        core = {"ownerFreezeIdentity": selected(self.freeze),
                "files": [{"logicalPath": str(path.relative_to(self.core)).replace(chr(92), "/"),
                           "ownerSelected": selected(path)} for path in paths],
                "nativeInputs": [{"logicalPath": self.private + "manager_resident_abi.h",
                                  "snapshotIdentity": selected(flat)}], "supportInputs": []}
        self.files[self.core_selection] = json.dumps(core).encode()
        host = {"corePredecessor": selected(self.core_selection), "files": [
            {"logicalPath": self.private + "manager_resident_host.c", "after": selected(corrected)},
            {"logicalPath": self.private + "manager_resident_abi.h", "after": selected(flat)}]}
        self.files[self.host_selection] = json.dumps(host).encode()
        self.argv += ["--core-selection", str(self.core_selection), "--host-selection", str(self.host_selection)]
        self.directories.update(parent for path in self.files for parent in path.parents)
        return corrected, flat

    def test_deployment54_host_after_overrides_core_and_selects_namespace_protocol(self):
        corrected, flat = self.deployment_selections()
        receipt = self.run_stage()
        rows = {row["staged"]: row for row in receipt["inputs"]}
        self.assertEqual(Path(rows["host/manager_resident_host.c"]["selected"]["path"]), corrected)
        self.assertEqual(Path(rows["host/manager_resident_abi.h"]["selected"]["path"]), flat)
        self.assertEqual(rows["host/manager_resident_host.c"]["selection"], "host-final-after")
        for name in ("host/manager_deployment_namespace.h", "request_protocol.h"):
            self.assertEqual(rows[name]["selection"], "core-owner-freeze")
            self.assertEqual(self.files[self.output / name], self.files[Path(rows[name]["selected"]["path"])])
        self.assertEqual(self.files[self.output / "host/manager_resident_host.c"], self.files[corrected])
        captured = {Path(row["path"]) for row in receipt["generatedFrom"]}
        self.assertTrue({self.core_selection, self.host_selection, self.freeze}.issubset(captured))
        self.assertTrue(receipt["formalDeploymentSelections"])
        self.assertFalse(receipt["compiled"])

    def test_deployment54_missing_or_mismatched_formal_source_has_no_receipt(self):
        corrected, _ = self.deployment_selections()
        original, directories = dict(self.files), set(self.directories)
        namespace = self.core / self.private / "manager_deployment_namespace.h"
        protocol = self.core / "runtime/ultra/authorization/request_protocol.h"
        for target, missing in ((corrected, True), (namespace, False), (protocol, False)):
            with self.subTest(input=str(target)):
                self.files, self.directories = dict(original), set(directories)
                if missing:
                    self.files.pop(target)
                    expected = "ULTRA_BRIDGE_SOURCE_MISSING:.*manager_resident_host.c"
                else:
                    self.files[target] += b"changed after formal freeze"
                    expected = "ULTRA_BRIDGE_FORMAL_SOURCE_IDENTITY:"
                with self.assertRaisesRegex(ValueError, expected):
                    self.run_stage()
                self.assertNotIn(self.output, self.directories)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_deployment54_selection_capture_and_generation_must_stay_bound(self):
        self.deployment_selections()
        original, directories = dict(self.files), set(self.directories)
        for target in (self.core_selection, self.host_selection, self.freeze):
            with self.subTest(input=str(target)):
                self.files, self.directories = dict(original), set(directories)
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_GENERATION_INPUT_CHANGED:"):
                    self.run_stage(replace_after_read=target)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)
        self.files, self.directories = dict(original), set(directories)
        host = json.loads(self.files[self.host_selection])
        host["corePredecessor"]["sha256"] = "0" * 64
        self.files[self.host_selection] = json.dumps(host).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_HOST_CORE_GENERATION"):
            self.run_stage()
        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)



    def runtime_selections(self):
        self.deployment_selections()
        self.runtime_candidate = self.repo / "runtime/CANDIDATE.json"
        self.runtime_freeze = self.repo / "runtime/SOURCE-FREEZE.json"
        self.runtime_emission = self.repo / "runtime/SOURCE-EMISSION.json"
        self.su_selection = self.repo / "su-selection.json"

        def selected(path):
            return stage.identity(path, self.files[path])

        native = {}
        for root in (self.repo, self.host, self.core):
            for path, data in list(self.files.items()):
                if path.parent == root / self.private:
                    native[path.name] = data
        native["manager_resident_host.c"] = b"frozen config2 -> msu_su_runtime_init; retained factory owner"
        native["manager_bytes.c"] = b"freestanding helpers are staged but not linked into normal LKM"
        for unit in stage.HOST_RUNTIME_UNITS:
            native[unit + ".c"] = ("frozen actual owner member:" + unit).encode()
            if unit != "manager_su_runtime_target":
                native[unit + ".h"] = ("frozen header:" + unit).encode()
        self.runtime_members = {}
        for name, data in sorted(native.items()):
            path = self.host / "runtime/frozen-native" / name
            self.files[path] = data
            self.runtime_members[name] = selected(path)
        host = json.loads(self.files[self.host_selection])
        host["runtimeChannel"] = "authenticated-installation-r02-20261119"
        for row in host["files"]:
            row["after"] = self.runtime_members[Path(row["logicalPath"]).name]
        protocol = self.core / "runtime/ultra/authorization/request_protocol.h"
        host["protocolInput"] = {"logicalPath": "runtime/ultra/authorization/request_protocol.h",
                                 "after": selected(protocol)}
        self.files[self.host_selection] = json.dumps(host).encode()
        emission = {"sourceSelection": selected(self.host_selection),
                    "selectedNativeInputs": list(self.runtime_members.values()),
                    "protocol": selected(protocol), "runtimeObjects": list(stage.HOST_RUNTIME_UNITS)}
        self.files[self.runtime_emission] = json.dumps(emission).encode()
        self.files[self.runtime_freeze] = json.dumps({"files": [selected(self.host_selection),
            selected(self.runtime_emission)] + list(self.runtime_members.values())}).encode()
        self.files[self.runtime_candidate] = json.dumps({"selection": selected(self.host_selection),
            "sourceEmission": selected(self.runtime_emission), "sourceFreeze": selected(self.runtime_freeze)}).encode()
        self.files[self.su_selection] = json.dumps({"files": [
            {"logicalPath": self.su_kernel + unit + suffix,
             "source": selected(self.su / self.su_kernel / (unit + suffix))}
            for unit in self.su_units for suffix in (".c", ".h")]}).encode()
        self.argv += ["--runtime-candidate", str(self.runtime_candidate), "--su-selection", str(self.su_selection)]
        self.directories.update(parent for path in self.files for parent in path.parents)

    def test_runtime_frozen_constructor_provider_objects_and_su_selection(self):
        self.runtime_selections()
        live = self.core / self.private / "manager_resident_host.c"
        self.files[live] = b"new unrelated work must not override selected frozen runtime cohort"
        receipt = self.run_stage()
        rows = {row["staged"]: row for row in receipt["inputs"]}
        for unit in stage.HOST_RUNTIME_UNITS:
            name = unit + ".c"
            self.assertEqual(rows["host/" + name]["selected"], self.runtime_members[name])
            self.assertEqual(rows["host/" + name]["selection"], "host-runtime-frozen")
        self.assertEqual(self.files[self.output / "host/manager_resident_host.c"],
                         b"frozen config2 -> msu_su_runtime_init; retained factory owner")
        objects = ["host/" + unit + ".o" for unit in stage.HOST_RUNTIME_UNITS]
        makefile = self.files[self.output / "selected-runtime.mk"].decode()
        self.assertEqual(receipt["selectedHostRuntimeObjects"], objects)
        for obj in objects:
            self.assertEqual(makefile.split().count(obj), 1)
        self.assertIn("include $(src)/selected-runtime.mk", self.files[self.output / "Kbuild"].decode())
        self.assertNotIn("host/manager_bytes.o", makefile)
        self.assertTrue(receipt["formalRuntimeSelections"])
        self.assertEqual(len(receipt["formalSuSelections"]), 1)
        self.assertFalse(receipt["factoryInstalled"])
        self.assertFalse(receipt["targetQualified"])
        self.assertIn(b"#define MSU_BS_ENVIRONMENT 1", self.files[self.output / "boot_sdk_layout.h"])

    def test_runtime_missing_or_changed_frozen_input_has_no_receipt(self):
        self.runtime_selections()
        original, directories = dict(self.files), set(self.directories)
        member = Path(self.runtime_members["su_durable_modern.h"]["path"])
        for missing in (True, False):
            self.files, self.directories = dict(original), set(directories)
            if missing:
                del self.files[member]
            else:
                self.files[member] += b"changed"
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.run_stage()
            self.assertNotIn(self.output, self.directories)
            self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_runtime_manifest_generation_change_has_no_receipt(self):
        self.runtime_selections()
        original, directories = dict(self.files), set(self.directories)
        for changed in (self.runtime_candidate, self.runtime_freeze, self.runtime_emission, self.su_selection):
            with self.subTest(input=str(changed)):
                self.files, self.directories = dict(original), set(directories)
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_GENERATION_INPUT_CHANGED:"):
                    self.run_stage(replace_during_write=changed)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)
        self.files, self.directories = dict(original), set(directories)
        host = json.loads(self.files[self.host_selection])
        host["corePredecessor"]["sha256"] = "0" * 64
        self.files[self.host_selection] = json.dumps(host).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_HOST_CORE_GENERATION"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)

    def test_runtime_without_candidate_or_complete_formal_su_has_no_receipt(self):
        self.runtime_selections()
        original, argv = dict(self.files), list(self.argv)
        index = self.argv.index("--runtime-candidate")
        del self.argv[index:index + 2]
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_RUNTIME_CANDIDATE_REQUIRED"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)
        self.argv = argv
        selection = json.loads(original[self.su_selection])
        selection["files"] = selection["files"][:-1]
        self.files[self.su_selection] = json.dumps(selection).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SU_MEMBER_MISSING:"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)

    def test_su_formal_successors_use_frozen_bytes_and_exact_predecessor(self):
        self.runtime_selections()
        header = self.su_kernel + "su_install_registry.h"
        source = self.su_kernel + "su_install_registry.c"
        provider = self.repo / "provider-selection.json"
        adoption = self.repo / "su-provider-adoption.json"
        profile = self.repo / "su-profile-selection.json"
        owned = self.host / "provider/su_install_registry.h"
        self.files[owned] = b"provider comment-only successor"
        selected = lambda path: stage.identity(path, self.files[path])
        self.files[provider] = json.dumps({"files": [{"logicalPath": header, "after": selected(owned)}]}).encode()
        self.files[adoption] = json.dumps({"logicalPath": header, "providerSelection": selected(provider),
            "before": selected(self.su / header), "candidate": selected(owned)}).encode()
        changes = []
        for relative in (header, source):
            path = self.host / "su-profile-frozen" / Path(relative).name
            self.files[path] = ("full saved profile:" + relative).encode()
            changes.append({"logicalPath": relative, "before": selected(owned if relative == header else self.su / relative),
                            "frozen": selected(path)})
        self.files[profile] = json.dumps({"files": changes}).encode()
        self.argv += ["--su-selection", str(adoption), "--su-selection", str(profile)]
        # Live registry drift is irrelevant: only formally frozen successors enter output.
        self.files[self.su / header] = b"live header changed again"
        self.files[self.su / source] = b"live implementation changed again"
        original, directories = dict(self.files), set(self.directories)
        receipt = self.run_stage()
        rows = {row["repositoryPath"]: row for row in receipt["inputs"]}
        for row in changes:
            self.assertEqual(rows[row["logicalPath"]]["selected"], row["frozen"])
        self.assertEqual(len(receipt["formalSuSelections"]), 3)
        self.files, self.directories = dict(original), set(directories)
        value = json.loads(self.files[profile])
        value["files"][0]["before"]["sha256"] = "0" * 64
        self.files[profile] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SU_PREDECESSOR:"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)



    def test_core73_preserves_helper_host_and_binds_real_factory_at_typed_call(self):
        self.runtime_selections()
        selected = lambda path: stage.identity(path, self.files[path])
        core73 = self.repo / "core73-selection.json"
        freeze73 = self.repo / "core73-freeze.json"
        resident = self.core / self.private / "manager_resident_host.c"
        self.files[resident] = (b"/* selected helper metadata/session implementation */\n"
            b"msu_installation_init(&host.metadata.host, deployment->name);\n"
            b"msu_management_discard_unpublished();\n")
        self.files[self.core / self.private / "manager_resident_host.h"] = b"typed helper metadata declaration"
        self.files[self.core / self.private / "manager_early_helper.h"] = b"real opaque lease five-argument declaration"
        protocol = self.core / "runtime/ultra/authorization/request_protocol.h"
        self.files[protocol] = b"CORE73 same-R02 helper/status protocol"
        rows = [{"logicalPath": str(path.relative_to(self.core)).replace(chr(92), "/"),
                 "selected": selected(path)} for path in self.files if self.core in path.parents]
        self.files[freeze73] = json.dumps({"sourceRoot": str(self.core), "files": [
            dict(row["selected"], path=row["logicalPath"]) for row in rows]}).encode()
        self.files[core73] = json.dumps({"sourceFreeze": selected(freeze73), "files": rows}).encode()
        self.argv[self.argv.index("--core-selection") + 1] = str(core73)
        # Do not rewrite the old HOST checkpoint's predecessor or protocol to
        # pretend it was emitted from CORE73; selected per-path ownership wins.
        successor = self.repo / "durable-v3-selection.json"
        modern = self.host / "durable-v3-frozen/su_durable_modern.c"
        self.files[modern] = b"formally frozen v3 durable decoder"
        before = self.runtime_members["su_durable_modern.c"]
        self.files[successor] = json.dumps({"files": [{"logicalPath": self.private + modern.name,
            "before": before, "after": selected(modern)}]}).encode()
        self.argv += ["--runtime-successor", str(successor)]
        original, directories = dict(self.files), set(self.directories)
        receipt = self.run_stage()
        emitted = {row["staged"]: row for row in receipt["inputs"]}
        self.assertEqual(emitted["host/manager_resident_host.c"]["selected"], selected(resident))
        self.assertEqual(self.files[self.output / "host/manager_resident_host.c"], self.files[resident])
        self.assertEqual(emitted["request_protocol.h"]["selected"], selected(protocol))
        self.assertEqual(emitted["host/su_durable_modern.c"]["selected"], selected(modern))
        self.assertIn("host/manager_early_helper.h", emitted)
        self.assertTrue(receipt["coreFactoryCallBindingGenerated"])
        self.assertEqual(len(receipt["generatedFactoryBinding"]), 2)
        binding = self.files[self.output / "native_factory_bind.c"].decode()
        self.assertIn("msu_su_runtime_init(host, &deployment)", binding)
        self.assertIn("memcpy(deployment.name, name", binding)
        self.assertLess(binding.index("msu_su_runtime_close()"),
                        binding.index("error = msu_management_discard_unpublished()"))
        self.assertLess(binding.index("error = msu_management_discard_unpublished()"),
                        binding.index("msu_su_runtime_discarded()"))
        kbuild = self.files[self.output / "selected-runtime.mk"].decode()
        self.assertIn("-DMSU_INIT_BRIDGE_RESIDENT_FACTORY=1", kbuild)
        self.assertIn("-include $(src)/native_factory_bind.h", kbuild)
        self.assertIn("native_factory_bind.o", kbuild)
        self.assertNotIn("MSU_SU_TARGET_EXECVE_COMMON_VERIFIED=1", kbuild)
        self.assertFalse(receipt["factoryInstalled"])
        self.files, self.directories = dict(original), set(directories)
        value = json.loads(self.files[successor])
        value["files"][0]["before"]["sha256"] = "0" * 64
        self.files[successor] = json.dumps(value).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_RUNTIME_SUCCESSOR_PREDECESSOR:"):
            self.run_stage()
        self.assertNotIn(self.output, self.directories)

    def formal_target_child(self):
        self.runtime_selections()
        selected = lambda path: stage.identity(path, self.files[path])
        resident = Path(self.runtime_members["manager_resident_host.c"]["path"])
        self.files[resident] = b"""int selected_resident_init(const maplesu_host_instance *host, const unsigned char name[16])
{
    int error = msu_installation_init(host, name);
    if (error) return error;
    return msu_su_runtime_init(host, name);
}
int selected_resident_discard(void)
{
    int error = msu_su_runtime_close();
    if (error) return error;
    error = msu_management_discard_unpublished();
    if (error) return error;
    return msu_su_runtime_discarded();
}
"""
        self.runtime_members[resident.name] = selected(resident)
        profile = self.host / "runtime/frozen-native/manager_su_runtime_target_profile.h"
        self.files[profile] = b"/* exact provider-owned entry profiles, never synthesized by stage */\n"
        self.runtime_members[profile.name] = selected(profile)
        builder = self.repo / "runtime/builder.py"
        effective = self.repo / "runtime/EFFECTIVE-SOURCE-SELECTION.json"
        final_emission = self.repo / "runtime/SOURCE-EMISSION-FINAL.json"
        self.files[builder] = b"formal final builder"
        protocol = self.core / "runtime/ultra/authorization/request_protocol.h"
        su = [selected(self.su / self.su_kernel / (unit + suffix))
              for unit in self.su_units for suffix in (".c", ".h")]
        self.files[effective] = json.dumps({"builder": selected(builder),
            "layers": [{"selector": "select_host_deployment_sources", "selection": selected(self.host_selection)}],
            "native": list(self.runtime_members.values()), "su": su, "protocol": selected(protocol)}).encode()
        self.files[final_emission] = json.dumps({"builder": selected(builder),
            "sourceFiles": len(self.runtime_members), "actualBuildPrefixExecuted": True}).encode()
        frozen = {"sourceInputs": list(self.runtime_members.values()) + su + [selected(protocol), selected(builder)],
                  "localReceipts": [selected(effective), selected(final_emission)]}
        self.files[self.runtime_freeze] = json.dumps(frozen).encode()
        candidate = {"schema": "maplesu-host-runtime-successor-candidate/1", "freeze": selected(self.runtime_freeze),
            "builder": selected(builder), "effectiveSelection": selected(effective), "finalEmission": selected(final_emission),
            "sourceIntegrationComplete": True}
        self.files[self.runtime_candidate] = json.dumps(candidate).encode()
        original, directories = dict(self.files), set(self.directories)
        for field in ("sourceIntegrationComplete", "freeze"):
            self.files, self.directories = dict(original), set(directories)
            value = dict(candidate)
            if field == "freeze":
                value[field] = dict(value[field], sha256="0" * 64)
            else:
                value[field] = False
            self.files[self.runtime_candidate] = json.dumps(value).encode()
            with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_(SELECTION_REFERENCE_IDENTITY|RUNTIME_SUCCESSOR_NOT_READY)"):
                self.run_stage()
            self.assertNotIn(self.output, self.directories)
        self.files, self.directories = dict(original), set(directories)
        parent_candidate = self.repo / "runtime/PARENT-CANDIDATE.json"
        child_freeze = self.repo / "runtime/CHILD-FREEZE.json"
        initialization = self.repo / "runtime/INITIALIZATION-SELECTION.json"
        status = self.repo / "runtime/STATUS.json"
        self.files[parent_candidate] = self.files[self.runtime_candidate]
        target_config = self.repo / "runtime/target.config"
        actual_config = next(path for path in self.files if path.name == ".config")
        self.files[target_config] = self.files[actual_config]
        target_sources = []
        for relative in stage.TARGET_PROFILE_SOURCES:
            frozen_source = self.repo / "runtime/target-source" / relative
            self.files[frozen_source] = ("selected target source:" + relative).encode()
            self.files[actual_config.parent.parent / "source" / relative] = self.files[frozen_source]
            target_sources.append(selected(frozen_source))
        self.files[initialization] = json.dumps({"parentCandidate": selected(parent_candidate),
            "parentSourceSelection": selected(effective), "kernelFiles": [],
            "kernelProfile": "fixture-exact-target", "targetConfig": selected(target_config),
            "targetSourceFiles": target_sources}).encode()
        self.files[status] = json.dumps({"parentAllFrozenInputsStable": True,
            "nativeSuStartupCallerImplemented": True}).encode()
        self.files[child_freeze] = json.dumps({"parentFreeze": selected(self.runtime_freeze), "ownedSources": [],
            "receipts": [selected(parent_candidate), selected(effective), selected(final_emission),
                         selected(initialization), selected(status)]}).encode()
        self.files[self.runtime_candidate] = json.dumps({"schema": "maplesu-host-initialization-child-candidate/1",
            "parentCandidate": selected(parent_candidate), "sourceFreeze": selected(child_freeze),
            "builder": selected(builder), "initializationSelection": selected(initialization),
            "sourceEmission": selected(final_emission), "status": selected(status)}).encode()
        self.directories.update(parent for path in self.files for parent in path.parents)
        return resident, profile

    def publication_builder_child(self, wrong_before=False, wrong_parent_freeze=False):
        self.formal_target_child()
        selected = lambda path: stage.identity(path, self.files[path])
        put = lambda path, value: self.files.__setitem__(path, json.dumps(value).encode())
        parent_path = self.runtime_candidate
        parent = json.loads(self.files[parent_path])
        initial = parent["initializationSelection"]
        effective = json.loads(self.files[self.repo / "runtime/EFFECTIVE-SOURCE-SELECTION.json"])
        for revision in (4, 5):
            root = self.repo / "runtime" / ("revision" + str(revision))
            path, freeze = root / "CANDIDATE.json", root / "SOURCE-FREEZE.json"
            builder, effective_path = root / "builder.py", root / "EFFECTIVE-SOURCE-SELECTION.json"
            emission, status = root / "SOURCE-EMISSION-FINAL.json", root / "STATUS.json"
            self.files[builder] = ("real frozen successor builder:" + str(revision)).encode()
            effective = json.loads(json.dumps(effective))
            effective["builder"] = selected(builder)
            if revision == 4:
                inventory, selection = root / "SDK-SOURCE-SELECTION.json", root / "current-task.json"
                sdk = root / "task_struct.cpp"
                self.files[sdk] = b"SDK-only current-task successor; never a native kernel object"
                put(inventory, {"files": [{"logicalPath": "runtime/maplesu-sdk/sdk/src/kernel_offsets/task_struct.cpp",
                                            "selected": selected(sdk)}]})
                put(selection, {"files": [{"logicalPath": "runtime/maplesu-sdk/sdk/src/kernel_offsets/task_struct.cpp",
                                           "after": selected(sdk)}]})
                effective["sdkCurrentTaskSourceEvolution"] = {"identity": selected(selection)}
                effective["layers"] += [{"selector": "select_host_initialization_sources", "selection": initial}]
                schema, field = "maplesu-host-sdk-current-task-intake-candidate/1", "sdkCurrentTaskSelection"
            else:
                selection, factory_freeze = root / "publication.json", root / "FACTORY-FREEZE.json"
                factory = root / "manager_su_runtime_factory.c"
                self.files[factory] = b"frozen publication successor with the real final commit boundary"
                before = next(row for row in effective["native"] if Path(row["path"]).name == factory.name)
                if wrong_before:
                    before = dict(before, sha256="0" * 64)
                put(selection, {"parentCandidate": selected(parent_path),
                    "parentEffectiveSelection": selected(previous_effective), "initializationSelection": initial,
                    "files": [{"logicalPath": self.private + factory.name, "before": before,
                               "after": selected(factory)}]})
                effective["native"] = [selected(factory) if Path(row["path"]).name == factory.name else row
                                       for row in effective["native"]]
                effective["hostPublicationSourceEvolution"] = {"identity": selected(selection)}
                put(factory_freeze, {"parentCandidate": selected(parent_path),
                                     "files": [selected(selection), selected(factory)]})
                schema, field = "maplesu-host-publication-builder-candidate/1", "publicationSelection"
            put(effective_path, effective)
            put(emission, {"builder": selected(builder), "sourceFiles": len(effective["native"]),
                           "actualBuildPrefixExecuted": True})
            put(status, {"targetQualified": False, "fullInitializationComplete": False})
            members = [selected(member) for member in (builder, effective_path, emission, status)]
            if revision == 4:
                members += [selected(inventory), selected(selection)]
            frozen = {"parentCandidate": selected(parent_path), "parentFreeze": parent["sourceFreeze"], "files": members}
            if revision == 5:
                frozen["factoryFreeze"] = selected(factory_freeze)
                if wrong_parent_freeze:
                    frozen["parentFreeze"] = dict(frozen["parentFreeze"], sha256="0" * 64)
            put(freeze, frozen)
            parent = {"schema": schema, "parentCandidate": selected(parent_path), "sourceFreeze": selected(freeze),
                "builder": selected(builder), "sourceEmission": selected(emission), "status": selected(status),
                "sdkOwnedInventory": selected(inventory), field: selected(selection)}
            if revision == 5:
                parent["effectiveSelection"] = selected(effective_path)
            put(path, parent)
            parent_path, previous_effective = path, effective_path
        self.argv[self.argv.index("--runtime-candidate") + 1] = str(parent_path)
        self.directories.update(parent for path in self.files for parent in path.parents)
        return parent_path, factory, inventory

    def late_builder_child(self):
        parent_path, _, inventory = self.publication_builder_child()
        selected = lambda path: stage.identity(path, self.files[path])
        put = lambda path, value: self.files.__setitem__(path, json.dumps(value).encode())
        for revision in (6, 7):
            parent = json.loads(self.files[parent_path])
            previous = parent["effectiveSelection"]
            effective = json.loads(self.files[Path(previous["path"])])
            root = self.repo / "runtime" / ("revision" + str(revision))
            builder, path, selection = root / "builder.py", root / "CANDIDATE.json", root / "selection.json"
            self.files[builder] = ("frozen later builder:" + str(revision)).encode()
            effective["builder"] = selected(builder)
            name = "manager_su_runtime_factory.c" if revision == 6 else "manager_resident_host.h"
            before = next(row for row in effective["native"] if Path(row["path"]).name == name)
            after = root / name
            self.files[after] = ("frozen exact later native:" + name).encode()
            rows = [{"logicalPath": self.private + name, "before": before, "after": selected(after)}]
            effective["native"] = [selected(after) if Path(row["path"]).name == name else row for row in effective["native"]]
            source = {"parentCandidate": selected(parent_path), "parentEffectiveSelection": previous, "files": rows}
            if revision == 6:
                source["parentSdkInventory"] = parent["sdkOwnedInventory"]
                sdk = json.loads(self.files[inventory])
                old_sdk = sdk["files"][0]
                sdk_after, inventory = root / "task_struct.cpp", root / "SDK-SOURCE-SELECTION.json"
                self.files[sdk_after] = b"exact synchronized SDK child"
                rows.append({"logicalPath": old_sdk["logicalPath"], "before": old_sdk["selected"], "after": selected(sdk_after)})
                sdk["files"][0]["selected"] = selected(sdk_after)
                put(inventory, sdk)
                effective["sdkInventory"] = selected(inventory)
                protocol = root / "request_protocol.h"
                self.files[protocol] = b"exact synchronized protocol"
                rows.append({"logicalPath": "runtime/ultra/authorization/request_protocol.h",
                             "before": effective["protocol"], "after": selected(protocol)})
                effective["protocol"] = selected(protocol)
            put(selection, source)
            evolution = "hostSyncSourceEvolution" if revision == 6 else "hostRetirementSourceEvolution"
            effective[evolution] = {"identity": selected(selection)}
            effective_path, emission, status = (root / name for name in ("EFFECTIVE-SOURCE-SELECTION.json", "SOURCE-EMISSION-FINAL.json", "STATUS.json"))
            put(effective_path, effective)
            put(emission, {"builder": selected(builder), "actualBuildPrefixExecuted": True})
            put(status, {"targetQualified": False})
            candidate = {"schema": "maplesu-host-sync-builder-candidate/1" if revision == 6 else "maplesu-host-retirement-candidate/1",
                "parentCandidate": selected(parent_path), "builder": selected(builder), "sourceSelection": selected(selection),
                "effectiveSelection": selected(effective_path), "sourceEmission": selected(emission), "status": selected(status),
                "sourceSelectedInIsolatedBuilder": True}
            if revision == 6:
                candidate["sdkInventory"] = selected(inventory)
            else:
                freeze = root / "SOURCE-FREEZE.json"
                put(freeze, {"builder": selected(builder), "selection": selected(selection), "effective": selected(effective_path),
                             "files": [row["after"] for row in rows]})
                candidate["sourceFreeze"] = selected(freeze)
            put(path, candidate)
            parent_path = path
        parent = candidate
        root = self.repo / "runtime/revision8"
        builder, before, collector_path = root / "builder.py", root / "before-builder.py", root / "collector.json"
        self.files[builder], self.files[before] = b"exact BTF VAR builder", b"exact MAIN collector builder"
        collector_refs = {}
        for name in ("candidateCollector", "validationExecution", "actualEvidence", "sourceDiff", "completeR7Delta"):
            p = root / name
            self.files[p] = ("inert producer receipt:" + name).encode()
            collector_refs[name] = selected(p)
        put(collector_path, {"owner": parent["builder"], "candidateBuilder": selected(before),
            "candidateCollector": collector_refs["candidateCollector"], "validationExecution": collector_refs["validationExecution"],
            "status": "PASS_ACTUAL_R7_DEPENDENCIES"})
        validation, status = root / "SOURCE-VALIDATION.json", root / "STATUS.json"
        put(validation, {"descriptorAbiAstUnchanged": True})
        put(status, {"sourcePrepared": True, "sourceValidationPassed": True})
        effective["builder"] = selected(builder)
        effective["hostProducerEvolution"] = {"parentCandidate": selected(parent_path),
            "dependencyCollectorSuccessor": selected(collector_path), "sourceValidation": selected(validation)}
        effective_path = root / "EFFECTIVE-SOURCE-SELECTION.json"
        put(effective_path, effective)
        freeze = root / "SOURCE-FREEZE.json"
        put(freeze, {"parentCandidate": selected(parent_path), "mainCollectorCandidate": selected(collector_path),
            "beforeBuilder": selected(before), "archivedBefore": selected(before), "afterBuilder": selected(builder),
            "effectiveSelection": selected(effective_path), "validation": selected(validation),
            **{key: collector_refs[key] for key in ("actualEvidence", "sourceDiff", "completeR7Delta")}, "nativeSourcesChanged": False})
        path = root / "CANDIDATE.json"
        put(path, {"schema": "maplesu-host-btf-variable-producer-candidate/1", "parentCandidate": selected(parent_path),
            "mainCollectorSuccessor": selected(collector_path), "builder": selected(builder), "sourceFreeze": selected(freeze),
            "sourceValidation": selected(validation), "effectiveSelection": selected(effective_path), "status": selected(status)})
        self.argv[self.argv.index("--runtime-candidate") + 1] = str(path)
        self.directories.update(parent for p in self.files for parent in p.parents)
        return path, collector_path, emission

    def test_r8_exact_parent_chain_preserves_r6_sync_r7_retirement_and_actual_emission(self):
        path, _, emission = self.late_builder_child()
        receipt = self.run_stage()
        runtime = receipt["formalRuntimeSelections"]
        self.assertEqual(runtime["candidate"], stage.identity(path, self.files[path]))
        self.assertEqual(runtime["emission"], stage.identity(emission, self.files[emission]))
        self.assertEqual(len(runtime["laterSourceSelections"]), 2)
        self.assertTrue(runtime["sourceOnlyProducerSuccessor"])
        self.assertIn(b"frozen exact later native:manager_su_runtime_factory.c", self.files[self.output / "host/manager_su_runtime_factory.c"])
        self.assertEqual(self.files[self.output / "host/manager_resident_host.h"], b"frozen exact later native:manager_resident_host.h")
        self.assertEqual(self.files[self.output / "request_protocol.h"], b"exact synchronized protocol")

    def test_r8_collector_or_native_drift_keeps_first_identity_error(self):
        _, collector, _ = self.late_builder_child()
        self.files[collector] += b"changed"
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SELECTION_REFERENCE_IDENTITY"):
            self.run_stage()
        self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_r8_protocol_successor_requires_exact_selected_predecessor(self):
        self.late_builder_child()
        selected = lambda path: stage.identity(path, self.files[path])
        parent_path = Path(self.argv[self.argv.index("--runtime-candidate") + 1])
        parent = json.loads(self.files[parent_path])
        effective = json.loads(self.files[Path(parent["effectiveSelection"]["path"])])
        path, protocol = self.repo / "protocol-successor.json", self.repo / "current-protocol.h"
        self.files[protocol] = b"frozen reviewed protocol successor"
        successor = {"schema": "maplesu-init-bridge-runtime-source-successor/1", "priorSelection": parent["effectiveSelection"], "files": [{
            "logicalPath": "runtime/ultra/authorization/request_protocol.h",
            "before": effective["protocol"], "after": selected(protocol)}]}
        self.files[path] = json.dumps(successor).encode()
        self.argv += ["--runtime-successor", str(path)]
        original, directories = dict(self.files), set(self.directories)
        self.run_stage()
        self.assertEqual(self.files[self.output / "request_protocol.h"], self.files[protocol])
        for mutation in ("before", "unrelated", "parent", "wrong-parent"):
            with self.subTest(mutation=mutation):
                self.files, self.directories = dict(original), set(directories)
                changed = json.loads(json.dumps(successor))
                if mutation == "before":
                    changed["files"][0]["before"]["sha256"] = "0" * 64
                elif mutation == "unrelated":
                    changed["files"][0]["logicalPath"] = "runtime/ultra/authorization/unrelated.h"
                elif mutation == "wrong-parent":
                    changed["priorSelection"] = selected(parent_path)
                else:
                    del changed["priorSelection"]
                self.files[path] = json.dumps(changed).encode()
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_RUNTIME_SUCCESSOR_(PREDECESSOR|PARENT)"):
                    self.run_stage()
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_management_cred_flag_follows_actual_field_and_helper_pair(self):
        management = self.core / self.private / "manager_management.c"
        self.files[management] = b"#ifndef MSU_MANAGEMENT_CRED_UCOUNTS\n#error target selection required\n#endif\n"
        cred = self.repo.parent / "kernel/source/include/linux/cred.h"
        original, directories = dict(self.files), set(self.directories)
        for enabled, data in ((True, b"struct cred { union { int private; }; struct ucounts *ucounts; };\nextern int set_cred_ucounts(struct cred *);\n"),
                              (False, b"struct cred { int usage; };\n/* struct ucounts *ucounts; extern int set_cred_ucounts(struct cred *); */\n")):
            with self.subTest(enabled=enabled):
                self.files, self.directories = dict(original), set(directories)
                self.files[cred] = data
                receipt = self.run_stage()
                self.assertIn(("#define MSU_MANAGEMENT_CRED_UCOUNTS %d\n" % enabled).encode(),
                              self.files[self.output / "host/msu_resolver_build_config.h"])
                self.assertTrue(any(row["path"] == str(cred) for row in receipt["generatedFrom"]))

    def test_management_cred_partial_ambiguous_or_malformed_contract_keeps_first_error(self):
        self.files[self.core / self.private / "manager_management.c"] = b"MSU_MANAGEMENT_CRED_UCOUNTS\n"
        cred = self.repo.parent / "kernel/source/include/linux/cred.h"
        original, directories = dict(self.files), set(self.directories)
        for data in (b"struct cred { struct ucounts *ucounts; };", b"struct cred { int usage; }; extern int set_cred_ucounts(struct cred *);",
                     b"struct cred { struct ucounts *ucounts; struct ucounts *ucounts; }; extern int set_cred_ucounts(struct cred *);",
                     b"struct cred { void *ucounts; }; extern int set_cred_ucounts(struct cred *);", b"struct cred { int usage; "):
            with self.subTest(data=data):
                self.files, self.directories = dict(original), set(directories)
                self.files[cred] = data
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_CRED_(DECLARATION|UCOUNTS_CONTRACT)"):
                    self.run_stage()
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_publication_builder_successor_selects_one_native_change_and_retains_target_adapter(self):
        candidate, factory, inventory = self.publication_builder_child()
        receipt = self.run_stage()
        emitted = {row["staged"]: row for row in receipt["inputs"]}
        self.assertEqual(emitted["host/manager_su_runtime_factory.c"]["selected"], stage.identity(factory, self.files[factory]))
        self.assertEqual(receipt["formalRuntimeSelections"]["candidate"], stage.identity(candidate, self.files[candidate]))
        self.assertEqual(receipt["formalRuntimeSelections"]["sdkOwnedInventory"], stage.identity(inventory, self.files[inventory]))
        self.assertEqual(len(receipt["formalRuntimeSelections"]["builderSuccessors"]), 2)
        self.assertTrue(receipt["runtimeTargetBindGenerated"])
        self.assertTrue(receipt["residentOwnsRuntimeLifecycle"])
        self.assertEqual(receipt["targetBinding"]["ownerSelection"]["repositoryPath"], "runtime/INITIALIZATION-SELECTION.json")
        self.assertEqual(self.files[self.output / "native_factory_bind.c"].count(b"msu_su_runtime_target_bind("), 1)
        self.assertFalse(any(name.endswith(".cpp") or "task_struct.o" in name for name in emitted))
        self.assertFalse(receipt["targetQualified"])

    def test_publication_builder_wrong_parent_or_native_predecessor_has_no_receipt(self):
        original, directories, argv = dict(self.files), set(self.directories), list(self.argv)
        for field, expected in (("wrong_before", "ULTRA_BRIDGE_RUNTIME_PUBLICATION_PREDECESSOR"),
                                ("wrong_parent_freeze", "ULTRA_BRIDGE_RUNTIME_BUILDER_PARENT_FREEZE")):
            with self.subTest(field=field):
                self.files, self.directories, self.argv = dict(original), set(directories), list(argv)
                self.publication_builder_child(**{field: True})
                with self.assertRaisesRegex(ValueError, expected):
                    self.run_stage()
                self.assertNotIn(self.output, self.directories)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_formal_target_source_contract_binds_config_and_all_six_sources(self):
        self.formal_target_child()
        receipt = self.run_stage()
        binding = receipt["targetBinding"]
        self.assertEqual(binding["kernelProfile"], "fixture-exact-target")
        self.assertEqual(binding["ownerSelection"]["repositoryPath"], "runtime/INITIALIZATION-SELECTION.json")
        self.assertEqual(binding["pageBytes"], 4096)
        self.assertFalse(binding["kernelImageIdentityEstablished"])
        self.assertEqual([row["repositoryPath"] for row in binding["sourceFiles"]], list(stage.TARGET_PROFILE_SOURCES))
        for row in binding["sourceFiles"]:
            for field in ("bytes", "sha256"):
                self.assertEqual(row["declared"][field], row["actual"][field])
            path = Path(row["actual"]["path"])
            self.assertEqual(row["actual"], stage.identity(path, self.files[path]))

    def test_kmi_target_profile_reaches_generated_factory_and_kbuild_consumer(self):
        self.formal_target_child()
        selected = lambda path: stage.identity(path, self.files[path])
        root = self.repo.parent
        build = root / "kernel/build"
        real_generator = Path(__file__).parents[1] / "target_kmi.py"
        generator_data = real_generator.read_bytes()
        generator = self.bridge / "target_kmi.py"
        self.files[generator] = generator_data
        self.files[build / "Module.symvers"] = b"DDK exports\n"
        self.files[build / "include/generated/utsrelease.h"] = b'#define UTS_RELEASE "real-ddk"\n'
        target_config, symvers, profile = (self.repo / name for name in ("target.config", "target.symvers", "target-profile.h"))
        self.files[target_config] = b"# distinct actual target config\nCONFIG_ARM64_4K_PAGES=y\n"
        self.files[symvers] = b"target exports\n"
        self.files[profile] = b'_Static_assert(sizeof(struct pt_regs) == 336, "target BTF ABI");\n'
        contract = {"schema": "maplesu-init-bridge-kmi-target/1", "generator": selected(generator),
            "sameMagic": {"policy": "skip-release-word-only-with-actual-crcs"}, "kernelProfile": "android15-6.6",
            "inputs": {"targetConfig": selected(target_config), "buildConfig": selected(build / ".config"),
                "buildSymvers": selected(build / "Module.symvers"),
                "buildRelease": selected(build / "include/generated/utsrelease.h")},
            "profile": selected(profile), "targetSymvers": selected(symvers)}
        contract_path = self.repo / "target-contract.json"
        self.files[contract_path] = json.dumps(contract).encode()
        self.argv += ["--target-kmi", str(contract_path)]
        self.directories.update(parent for path in self.files for parent in path.parents)
        original_spec = stage.importlib.util.spec_from_file_location
        with patch.object(stage.importlib.util, "spec_from_file_location",
                          side_effect=lambda name, path: original_spec(name, real_generator)):
            receipt = self.run_stage()
        self.assertEqual(self.files[self.output / "host/manager_su_runtime_target_profile.h"], self.files[profile])
        self.assertEqual(receipt["targetBinding"]["kind"], contract["schema"])
        self.assertNotEqual(receipt["targetBinding"]["targetConfig"]["sha256"], receipt["targetBinding"]["buildConfig"]["sha256"])
        self.assertIn(b"msu_su_runtime_target_bind", self.files[self.output / "native_factory_bind.c"])
        self.assertIn(b"host/manager_su_runtime_target.o", self.files[self.output / "selected-runtime.mk"])
        self.assertTrue(receipt["runtimeTargetBindGenerated"])
        self.assertFalse(receipt["targetQualified"])

    def early_runtime_addition(self):
        self.formal_target_child()
        rows = []
        for unit in stage.EARLY_RUNTIME_UNITS:
            for suffix in (".c", ".h"):
                relative = self.private + unit + suffix
                path = self.host / "early-runtime" / (unit + suffix)
                self.files[path] = ("inert selected early runtime source:" + relative).encode()
                rows.append({"logicalPath": relative, "after": stage.identity(path, self.files[path])})
        manifest = self.repo / "early-runtime-successor.json"
        self.files[manifest] = json.dumps({"priorSelection": stage.identity(self.runtime_candidate, self.files[self.runtime_candidate]),
                                          "files": [], "addedFiles": rows}).encode()
        self.argv += ["--runtime-successor", str(manifest)]
        self.directories.update(parent for path in self.files for parent in path.parents)
        return manifest

    def test_early_runtime_added_cohort_reaches_boot_and_native_kbuild_once(self):
        self.early_runtime_addition()
        receipt = self.run_stage()
        generated = self.files[self.output / "native_factory_bind.c"]
        self.assertEqual(generated.count(b"msu_early_runtime_target_bind("), 1)
        self.assertNotIn(b"msu_early_runtime_close", generated)
        self.assertNotIn(b"msu_early_runtime_discarded", generated)
        self.assertTrue(receipt["earlyRuntimeTargetBindGenerated"])
        for unit in stage.EARLY_RUNTIME_UNITS:
            self.assertIn(("host/" + unit + ".o").encode(), self.files[self.output / "selected-runtime.mk"])
            self.assertIn(self.output / ("host/" + unit + ".c"), self.files)
            self.assertIn(self.output / ("host/" + unit + ".h"), self.files)

    def test_early_runtime_incomplete_or_unrelated_addition_has_no_success_receipt(self):
        manifest = self.early_runtime_addition()
        original, directories = dict(self.files), set(self.directories)
        selection = json.loads(self.files[manifest])
        for mutation in ("incomplete", "unrelated", "parent"):
            with self.subTest(mutation=mutation):
                self.files, self.directories = dict(original), set(directories)
                changed = json.loads(json.dumps(selection))
                if mutation == "incomplete":
                    changed["addedFiles"].pop()
                elif mutation == "unrelated":
                    changed["addedFiles"][0]["logicalPath"] = self.private + "unrelated.c"
                else:
                    del changed["priorSelection"]
                self.files[manifest] = json.dumps(changed).encode()
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_(EARLY_RUNTIME_SOURCE_SET|RUNTIME_ADDITION_CONTRACT)"):
                    self.run_stage()
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_formal_target_config_or_source_mismatch_leaves_no_success_receipt(self):
        self.formal_target_child()
        original, directories = dict(self.files), set(self.directories)
        config = next(path for path in self.files if path.name == ".config")
        source = config.parent.parent / "source"
        targets = [(config, "ULTRA_BRIDGE_TARGET_PROFILE_CONFIG_MISMATCH")]
        targets += [(source / relative, "ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + relative)
                    for relative in stage.TARGET_PROFILE_SOURCES]
        for path, expected in targets:
            with self.subTest(input=str(path)):
                self.files, self.directories = dict(original), set(directories)
                self.files[path] += b"different target input"
                with self.assertRaisesRegex(ValueError, expected):
                    self.run_stage()
                self.assertNotIn(self.output, self.directories)
                self.assertNotIn(self.output / "SOURCE-SELECTION.json", self.files)

    def test_formal_target_successor_binds_before_install_without_duplicate_lifecycle(self):
        resident, profile = self.formal_target_child()
        selected = lambda path: stage.identity(path, self.files[path])
        receipt = self.run_stage()
        emitted = {row["staged"]: row for row in receipt["inputs"]}
        self.assertEqual(emitted["host/manager_su_runtime_target_profile.h"]["selected"], selected(profile))
        self.assertEqual(self.files[self.output / "host/manager_resident_host.c"], self.files[resident])
        self.assertTrue(receipt["runtimeTargetBindGenerated"])
        self.assertTrue(receipt["residentOwnsRuntimeLifecycle"])
        self.assertFalse(receipt["targetQualified"])
        generated = {name: self.files[self.output / name] for name in ("native_factory_bind.c", "native_factory_bind.h")}
        # Compile the actual emitted adapter and selected resident in separate
        # TUs: only resident gets the Kbuild macro, as in the real product.
        declarations = r"""#ifndef BRIDGE_ADAPTER_FIXTURE_H
#define BRIDGE_ADAPTER_FIXTURE_H
#include <errno.h>
typedef struct { unsigned long low, high; } maplesu_host_instance;
int msu_installation_init(const maplesu_host_instance *, const unsigned char[16]);
int msu_management_discard_unpublished(void);
int msu_su_runtime_init(const maplesu_host_instance *, const void *);
int msu_su_runtime_close(void);
int msu_su_runtime_discarded(void);
unsigned long msu_init_bridge_lookup(const char *);
int msu_init_bridge_resolve_cfi(const char *, const void *, unsigned long *);
int msu_su_runtime_target_bind(unsigned long (*)(const char *), int (*)(const char *, const void *, unsigned long *));
int selected_resident_init(const maplesu_host_instance *, const unsigned char[16]);
int selected_resident_discard(void);
#endif
"""
        cases = r"""#include <assert.h>
#include "fixture.h"
static int phase, bind_error, install_error, runtime_error, installs, starts, closed, discarded;
unsigned long msu_init_bridge_lookup(const char *name) { (void)name; return 0; }
int msu_init_bridge_resolve_cfi(const char *name, const void *reference, unsigned long *address)
{ (void)name; (void)reference; (void)address; return 0; }
int msu_su_runtime_target_bind(unsigned long (*lookup)(const char *), int (*resolve)(const char *, const void *, unsigned long *))
{ assert(!phase && lookup == msu_init_bridge_lookup && resolve == msu_init_bridge_resolve_cfi); phase = 1; return bind_error; }
int msu_installation_init(const maplesu_host_instance *host, const unsigned char name[16])
{ assert(phase == 1 && host && name); phase = 2; ++installs; return install_error; }
int msu_su_runtime_init(const maplesu_host_instance *host, const void *name)
{ assert(phase == 2 && host && name); phase = 3; ++starts; return runtime_error; }
int msu_su_runtime_close(void) { assert(!closed++); return 0; }
int msu_management_discard_unpublished(void) { assert(closed == 1 && !discarded); return 0; }
int msu_su_runtime_discarded(void) { assert(closed == 1 && !discarded++); return 0; }
int main(void)
{
    maplesu_host_instance host = {1, 2};
    unsigned char name[16] = {0};
    bind_error = -EACCES;
    assert(selected_resident_init(&host, name) == -EACCES && !installs && !starts);
    phase = bind_error = 0; install_error = -EINVAL;
    assert(selected_resident_init(&host, name) == -EINVAL && installs == 1 && !starts);
    phase = install_error = installs = 0; runtime_error = -ENOMEM;
    assert(selected_resident_init(&host, name) == -ENOMEM && installs == 1 && starts == 1);
    phase = runtime_error = installs = starts = 0;
    assert(!selected_resident_init(&host, name) && phase == 3 && installs == 1 && starts == 1);
    assert(!selected_resident_discard() && closed == 1 && discarded == 1);
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="bridge-target-bind-") as directory:
            output = Path(directory)
            for name, data in generated.items():
                (output / name).write_bytes(data)
            (output / "fixture.h").write_text(declarations)
            for name in ("manager_installation_state.h", "manager_management.h", "manager_su_runtime_factory.h", "native_lookup.h"):
                (output / name).write_text('#include "fixture.h"\n')
            (output / "resident.c").write_bytes(b'#define MSU_INIT_BRIDGE_RESIDENT_FACTORY 1\n#include "native_factory_bind.h"\n' + self.files[resident])
            (output / "fixture.c").write_text(cases)
            cc = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
            environment = dict(os.environ, PATH=str(Path(cc).parent) + os.pathsep + os.environ.get("PATH", ""))
            binary = output / "fixture.exe"
            compiled = subprocess.run([cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                "-I" + str(output), str(output / "native_factory_bind.c"), str(output / "resident.c"),
                str(output / "fixture.c"), "-o", str(binary)], env=environment, capture_output=True, text=True, timeout=25)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            subprocess.run([str(binary)], env=environment, check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
