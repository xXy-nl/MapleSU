"""Build invocation fixtures; no compiler runs and no module bytes are created."""
from contextlib import ExitStack
import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bridge_build_target", Path(__file__).parents[1] / "build_target.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class IdentityChecks(unittest.TestCase):
    def test_streamed_identity_matches_exact_bytes_across_read_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="maplesu-identity-") as temporary:
            path = Path(temporary) / "input"
            for data in (b"", b"exact input", bytes(range(256)) * 8193):
                with self.subTest(bytes=len(data)):
                    path.write_bytes(data)
                    self.assertEqual(builder.identity(path), {"path": str(path.resolve()),
                        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def test_large_input_requires_only_bounded_reads(self):
        data, requests = bytes(range(256)) * 12289, []
        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 8 * 1024 * 1024:
                    raise AssertionError("unbounded identity read")
                requests.append(size)
                return super().read(size)
        path = Path("identity-bounded-input").resolve()
        with patch.object(Path, "open", return_value=BoundedReader(data)):
            result = builder.identity(path)
        self.assertEqual(result, {"path": str(path), "bytes": len(data),
                                 "sha256": hashlib.sha256(data).hexdigest()})
        self.assertGreater(len(requests), 1)

    def test_open_failure_propagates_without_identity(self):
        failure = OSError("fixture open failure")
        with patch.object(Path, "open", side_effect=failure):
            with self.assertRaises(OSError) as caught:
                builder.identity(Path("identity-open-failure"))
        self.assertIs(caught.exception, failure)

    def test_partial_read_failure_propagates_without_identity(self):
        failure = OSError("fixture interrupted read")
        class InterruptedReader(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise failure
                return super().read(size)
        with patch.object(Path, "open", return_value=InterruptedReader(b"partial input")):
            with self.assertRaises(OSError) as caught:
                builder.identity(Path("identity-read-failure"))
        self.assertIs(caught.exception, failure)


class TargetBindingChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maplesu-bridge-inputs-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.source, self.kdir = self.repo / "module", self.repo / "kernel-build"
        self.kernel_source = self.repo / "kernel-source"
        self.profile = self.source / "host/manager_su_runtime_target_profile.h"
        self.profile.parent.mkdir(parents=True)
        self.profile.write_text("/* exact owner target profile */\n", encoding="utf-8")
        self.kdir.mkdir()
        (self.kdir / ".config").write_text("CONFIG_ARM64_4K_PAGES=y\n", encoding="utf-8")
        self.owner_path, self.receipt_path = self.repo / "owner.json", self.source / "SOURCE-SELECTION.json"
        sources = []
        for relative in builder.TARGET_PROFILE_SOURCES:
            path = self.kernel_source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("exact target source:" + relative, encoding="utf-8")
            sources.append({"repositoryPath": relative, "declared": dict(builder.identity(path),
                            path="C:\\original-target\\" + relative.replace("/", "\\")),
                            "actual": builder.identity(path)})
        self.owner = {"kernelProfile": "fixture-exact-target", "targetConfig": builder.identity(self.kdir / ".config"),
            "kernelFiles": [{"logicalPath": "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h",
                             "after": builder.identity(self.profile)}],
            "targetSourceFiles": [row["declared"] for row in sources]}
        self.owner_path.write_text(json.dumps(self.owner), encoding="utf-8")
        self.binding = {"ownerSelection": dict(builder.identity(self.owner_path),
                        path="C:\\original-workspace\\owner.json", repositoryPath="owner.json"),
            "kernelProfile": self.owner["kernelProfile"], "profile": builder.identity(self.profile),
            "targetConfig": self.owner["targetConfig"], "sourceFiles": sources}
        self.write_binding(self.binding)

    def write_binding(self, value):
        self.receipt_path.write_text(json.dumps({"targetBinding": value}), encoding="utf-8")

    def target_inputs(self):
        return builder.staged_target_inputs(self.source, self.kdir, self.repo, self.kernel_source)

    def test_exact_owner_config_profile_and_six_sources_survive_workspace_relocation(self):
        self.assertEqual(self.target_inputs(), [self.receipt_path, self.owner_path, self.profile,
                         *[self.kernel_source / relative for relative in builder.TARGET_PROFILE_SOURCES]])

    def test_no_profile_uses_existing_non_target_path(self):
        self.profile.unlink()
        self.assertEqual(builder.staged_target_inputs(self.source, self.kdir, self.repo), [])

    def test_target_profile_requires_automatic_source_contract(self):
        self.write_binding({})
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT_REQUIRED"):
            self.target_inputs()

    def test_target_profile_requires_current_kernel_source_root(self):
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_ROOT_REQUIRED"):
            builder.staged_target_inputs(self.source, self.kdir, self.repo)

    def test_actual_kernel_source_drift_after_stage_is_rejected(self):
        for relative in builder.TARGET_PROFILE_SOURCES:
            with self.subTest(input=relative):
                path = self.kernel_source / relative
                before = path.read_bytes()
                path.write_bytes(before + b"changed after stage")
                try:
                    with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + relative):
                        self.target_inputs()
                finally:
                    path.write_bytes(before)

    def test_owner_config_or_profile_drift_stops_before_build(self):
        for path, expected in ((self.owner_path, "OWNER_IDENTITY"), (self.kdir / ".config", "CONFIG_MISMATCH"),
                               (self.profile, "PROFILE_IDENTITY")):
            with self.subTest(input=str(path)):
                before = path.read_bytes()
                path.write_bytes(before + b"changed")
                try:
                    with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_.*" + expected):
                        self.target_inputs()
                finally:
                    path.write_bytes(before)

    def test_source_proof_must_contain_all_six_members_once(self):
        rows = self.binding["sourceFiles"]
        for invalid in ([], rows[:-1], rows + [rows[0]], rows[1:] + [rows[1]]):
            with self.subTest(members=[row["repositoryPath"] for row in invalid]):
                self.write_binding(dict(self.binding, sourceFiles=invalid))
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT"):
                    self.target_inputs()

    def test_changed_proof_or_owner_generation_stops_before_build(self):
        for field in ("actual", "declared", "targetConfig", "profile", "kernelProfile"):
            with self.subTest(field=field):
                binding = json.loads(json.dumps(self.binding))
                if field in ("actual", "declared"):
                    binding["sourceFiles"][0][field]["sha256"] = "0" * 64
                    expected = "SOURCE_MISMATCH"
                elif field == "kernelProfile":
                    binding[field] = "different-target-generation"
                    expected = "GENERATION"
                else:
                    binding[field]["sha256"] = "0" * 64
                    expected = "CONFIG_MISMATCH" if field == "targetConfig" else "PROFILE_IDENTITY"
                self.write_binding(binding)
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_.*" + expected):
                    self.target_inputs()


class KmiTargetBindingChecks(unittest.TestCase):
    """Only receipt/profile validation executes; these files are never compiled."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maplesu-kmi-inputs-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.source, self.kdir = self.repo / "module", self.repo / "ddk"
        self.profile = self.source / "host/manager_su_runtime_target_profile.h"
        self.profile.parent.mkdir(parents=True)
        self.kdir.mkdir()
        (self.kdir / "include/generated").mkdir(parents=True)
        inputs = {}
        for name, path, data in (
                ("buildConfig", self.kdir / ".config", b"CONFIG_ARM64=y\n"),
                ("buildSymvers", self.kdir / "Module.symvers", b"DDK exports\n"),
                ("buildRelease", self.kdir / "include/generated/utsrelease.h", b'#define UTS_RELEASE "real-ddk"\n'),
                ("targetConfig", self.repo / "target.config", b"# distinct target config\nCONFIG_ARM64=y\n"),
                ("kernelImage", self.repo / "target.input", b"inert input identity fixture")):
            path.write_bytes(data)
            inputs[name] = builder.identity(path)
        expected = self.repo / "frozen-profile.h"
        expected.write_bytes(b'_Static_assert(sizeof(struct pt_regs) == 336, "target BTF ABI");\n')
        self.profile.write_bytes(expected.read_bytes())
        symvers = self.repo / "target.symvers"
        symvers.write_bytes(b"target exports\n")
        self.contract = {"schema": "maplesu-init-bridge-kmi-target/1", "inputs": inputs,
                         "generator": builder.identity(Path(__file__).parents[1] / "target_kmi.py"),
                         "sameMagic": {"policy": "skip-release-word-only-with-actual-crcs"},
                         "profile": builder.identity(expected), "targetSymvers": builder.identity(symvers)}
        self.contract_path = self.repo / "target-contract.json"
        self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        self.binding = {"kind": self.contract["schema"], "contract": builder.identity(self.contract_path),
                        "profile": self.contract["profile"], "buildConfig": inputs["buildConfig"],
                        "targetConfig": inputs["targetConfig"]}
        (self.source / "SOURCE-SELECTION.json").write_text(json.dumps({"targetBinding": self.binding}), encoding="utf-8")

    def target_inputs(self):
        return builder.staged_target_inputs(self.source, self.kdir, self.repo)

    def test_ddk_build_and_actual_target_config_stay_distinct_without_exact_target_source(self):
        result = self.target_inputs()
        self.assertIn(self.profile, result)
        self.assertIn(self.contract_path, result)
        self.assertIn(self.repo / "target.config", result)

    def test_wrong_618_pt_regs_profile_is_rejected_before_kbuild(self):
        self.profile.write_bytes(self.profile.read_bytes().replace(b"336", b"320"))
        with self.assertRaisesRegex(ValueError, "TARGET_PROFILE_IDENTITY"):
            self.target_inputs()

    def test_target_evidence_drift_is_rejected_before_kbuild(self):
        (self.repo / "target.config").write_bytes(b"changed target input")
        with self.assertRaisesRegex(ValueError, "KMI_INPUT_CHANGED"):
            self.target_inputs()

    def test_actual_ddk_config_drift_is_rejected_before_kbuild(self):
        (self.kdir / ".config").write_bytes(b"changed actual DDK")
        with self.assertRaisesRegex(ValueError, "KMI_INPUT_CHANGED|KMI_BUILD_INPUT"):
            self.target_inputs()


class ModuleInputChecks(unittest.TestCase):
    def test_optional_vmlinux_is_captured_without_becoming_a_bare_link_requirement(self):
        root = (Path(__file__).parent / "memory-build-fixture").resolve()
        for present, after in ((False, False), (True, True), (False, True)):
            with self.subTest(before=present, after=after):
                checks, receipts = [], []

                def is_file(path):
                    if path == root / "kernel/vmlinux":
                        checks.append(path)
                        return present if len(checks) == 1 else after
                    return path.name == "maplesu_ultra_bridge.ko"

                argv = ["build_target.py", "--repo-root", str(root), "--kernel-build", str(root / "kernel"),
                        "--llvm-bin", str(root / "llvm"), "--module-source", str(root / "module"),
                        "--evidence", str(root / "evidence"), "--source", str(root / "module/bridge.c")]
                with ExitStack() as stack:
                    stack.enter_context(patch.object(builder, "strip_module_debug", return_value=({"fixture": True}, 0)))
                    stack.enter_context(patch.object(sys, "argv", argv))
                    stack.enter_context(patch.object(Path, "exists", return_value=False))
                    stack.enter_context(patch.object(Path, "is_file", is_file))
                    stack.enter_context(patch.object(Path, "read_text", return_value="obj-m += maplesu_ultra_bridge.o\n"))
                    stack.enter_context(patch.object(Path, "mkdir"))
                    stack.enter_context(patch.object(Path, "open", side_effect=lambda *a, **kw: io.BytesIO()))
                    stack.enter_context(patch.object(Path, "write_text", lambda p, text, **kw: receipts.append(json.loads(text))))
                    stack.enter_context(patch.object(builder, "identity", side_effect=lambda p: {"path": str(p)}))
                    run = stack.enter_context(patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0)))
                    if present != after:
                        with self.assertRaisesRegex(ValueError, "BUILD_INPUT_CHANGED"):
                            builder.main()
                    else:
                        builder.main()
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(run.call_args.args[0][-1], "modules")
                self.assertEqual(len(receipts), 1)
                receipt = receipts[0]
                self.assertEqual(receipt["targetVmlinuxCaptured"], present)
                self.assertEqual(receipt["inputsUnchanged"], present == after)
                self.assertEqual(str(root / "kernel/vmlinux") in [s["path"] for s in receipt["sources"]], present)
                self.assertIn(str(root / "kernel/Module.symvers"), [s["path"] for s in receipt["sources"]])
                self.assertFalse(receipt["targetQualified"])
                self.assertFalse(receipt["targetBtfQualified"])


class ModpostOverrideChecks(unittest.TestCase):
    def run_build(self, mode):
        with tempfile.TemporaryDirectory(prefix="maplesu-modpost-input-") as temporary:
            root = Path(temporary).resolve()
            modpost = root / "modpost"
            tracked_source = root / "module/bridge.c"
            tracked_source.parent.mkdir()
            tracked_source.write_bytes(b"fixture source\n")
            if mode != "missing":
                modpost.write_bytes(b"inert host-tool identity fixture")
            real_identity, real_open = builder.identity, Path.open
            expected = real_identity(modpost) if mode != "missing" else None
            receipts = []
            argv = ["build_target.py", "--repo-root", str(root), "--kernel-build", str(root / "kernel"),
                    "--llvm-bin", str(root / "llvm"), "--module-source", str(root / "module"),
                    "--evidence", str(root / "evidence"), "--source", str(root / "module/bridge.c"),
                    "--modpost", str(modpost)]

            def run(command, **kwargs):
                if mode == "changed":
                    modpost.write_bytes(b"changed while Kbuild ran")
                return SimpleNamespace(returncode=2 if mode == "failed" else 0)

            def strip(*args):
                if mode == "strip-tool-changed":
                    modpost.write_bytes(b"changed while strip ran")
                elif mode == "strip-source-changed":
                    tracked_source.write_bytes(b"changed while strip ran")
                return {"fixture": True}, 7 if mode == "strip-failed" else 0

            with ExitStack() as stack:
                stack.enter_context(patch.object(builder, "strip_module_debug", side_effect=strip))
                stack.enter_context(patch.object(sys, "argv", argv))
                stack.enter_context(patch.object(Path, "exists", return_value=False))
                stack.enter_context(patch.object(Path, "is_file", lambda p: p.name == "maplesu_ultra_bridge.ko"))
                stack.enter_context(patch.object(Path, "read_text", return_value="obj-m += maplesu_ultra_bridge.o\n"))
                stack.enter_context(patch.object(Path, "mkdir"))
                stack.enter_context(patch.object(Path, "open", side_effect=lambda p, *a, **kw:
                    io.BytesIO() if p.suffix == ".log" else real_open(p, *a, **kw), autospec=True))
                stack.enter_context(patch.object(Path, "write_text", lambda p, text, **kw: receipts.append(json.loads(text))))
                stack.enter_context(patch.object(builder, "identity", side_effect=lambda p:
                    real_identity(p) if p in (modpost, tracked_source) else {"path": str(p)}))
                invoked = stack.enter_context(patch.object(builder.subprocess, "run", side_effect=run))
                if mode == "missing":
                    with self.assertRaises(FileNotFoundError):
                        builder.main()
                    invoked.assert_not_called()
                    self.assertEqual(receipts, [])
                    return
                if mode in ("changed", "strip-tool-changed", "strip-source-changed"):
                    with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_BUILD_INPUT_CHANGED"):
                        builder.main()
                elif mode in ("failed", "strip-failed"):
                    with self.assertRaises(SystemExit) as failure:
                        builder.main()
                    self.assertEqual(failure.exception.code, 7 if mode == "strip-failed" else 2)
                else:
                    builder.main()
                invoked.assert_called_once()
                command = invoked.call_args.args[0]
                self.assertIn("MODPOST=" + str(modpost), command)
                self.assertIn("KBUILD_MODPOST_WARN=", command)
                self.assertEqual(command[-1], "modules")
            self.assertEqual(len(receipts), 1)
            receipt = receipts[0]
            self.assertEqual(receipt["tools"][-1], expected)
            drifted = mode in ("changed", "strip-tool-changed", "strip-source-changed")
            self.assertEqual(receipt["inputsUnchanged"], not drifted)
            self.assertEqual(receipt["exitCode"], 7 if mode == "strip-failed" else 2 if mode == "failed" else 0)
            self.assertEqual("artifacts" in receipt, not drifted and mode not in ("failed", "strip-failed"))

    def test_explicit_modpost_is_hashed_and_passed_to_strict_make(self):
        self.run_build("stable")

    def test_modpost_drift_is_rejected_after_build(self):
        self.run_build("changed")

    def test_real_modpost_exit_code_is_preserved(self):
        self.run_build("failed")

    def test_strip_failure_has_no_publishable_artifact_and_preserves_exit(self):
        self.run_build("strip-failed")

    def test_tool_drift_during_strip_has_no_publishable_artifact(self):
        self.run_build("strip-tool-changed")

    def test_source_drift_during_strip_has_no_publishable_artifact(self):
        self.run_build("strip-source-changed")

    def test_missing_explicit_modpost_stops_before_make(self):
        self.run_build("missing")


class DirectStrictModpostChecks(unittest.TestCase):
    """Real main wiring with explicit helper/Kbuild/ELF-validation fixture ports."""
    def run_direct(self, change_tool):
        with tempfile.TemporaryDirectory(prefix="maplesu-direct-tool-") as temporary:
            root = Path(temporary).resolve()
            source, kdir, kernel, llvm = (root / name for name in ("module", "kernel-build", "kernel-source", "llvm"))
            evidence, original = root / "evidence", root / "original-modpost"
            files = {source / "Kbuild": b"obj-m += maplesu_ultra_bridge.o\n", source / "bridge.c": b"fixture source\n",
                kdir / ".config": b"CONFIG_MODVERSIONS=y\n", kdir / "include/generated/utsrelease.h": b'#define UTS_RELEASE "fixture"\n',
                kdir / "Module.symvers": b"fixture symbol versions\n", kernel / "Makefile": b"kernel fixture\n",
                kernel / "scripts/Makefile.modpost": b"fixed rule fixture\n", kernel / "scripts/mod/modpost.c": b"fixed modpost fixture\n",
                root / "direct.py": b"direct fixture\n", root / "dependency": b"dependency fixture\n",
                root / "dependency-manifest.json": b"manifest fixture\n", original: b"original tool fixture\n",
                llvm / "clang": b"host compiler fixture\n", llvm / "ld.lld": b"linker fixture\n", llvm / "llvm-nm": b"nm fixture\n", llvm / "llvm-strip": b"strip fixture\n",
                root / "host-ld": b"host linker fixture\n"}
            for path, data in files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            family = "fixture-family"
            direct = SimpleNamespace(__file__=str(root / "direct.py"),
                dependency=lambda *args: [root / "dependency"], rule_expression=lambda path: "fixture-rule-expression",
                RULE_HASHES={builder.identity(kernel / "scripts/Makefile.modpost")["sha256"]: family},
                MODPOST_SOURCE_HASHES={family: builder.identity(kernel / "scripts/mod/modpost.c")["sha256"]},
                staged_sources=lambda path: [], make_command=lambda *args: "fixture-direct-command",
                checked=lambda row: Path(row["path"]), load_parser=lambda path: None,
                final_module=lambda *args: {"explicitElfValidationFixture": True})
            generated = {}

            def prepare(actual_source, actual_build, actual_original, actual_compiler, actual_family, output):
                self.assertEqual((actual_source, actual_build, actual_original, actual_compiler, actual_family),
                                 (kernel, kdir, original, llvm / "clang", family))
                output.mkdir()
                for name in ("modpost", "DERIVATION.json", "restored-source.c"):
                    (output / name).write_bytes(("generated fixture " + name).encode())
                generated.update(tool=output / "modpost", receipt=output / "DERIVATION.json",
                    inputs=[output / name for name in ("modpost", "DERIVATION.json", "restored-source.c")],
                    tools=[llvm / "clang", root / "host-ld"])
                return generated

            strict = SimpleNamespace(prepare=prepare)

            def spec(name, path):
                return SimpleNamespace(name=name, loader=SimpleNamespace(exec_module=lambda module: None))

            def run(command, **kwargs):
                self.assertIn("MODPOST=fixture-direct-command", command)
                request = json.loads((evidence / "DIRECT-MODPOST-REQUEST.json").read_bytes())
                self.assertEqual(request["modpost"], builder.identity(generated["tool"]))
                self.assertEqual(request["strictModpost"], builder.identity(generated["receipt"]))
                for path in [*generated["inputs"], *generated["tools"]]:
                    self.assertIn(builder.identity(path), request["inputs"])
                (source / "maplesu_ultra_bridge.ko").write_bytes(b"inert Kbuild output fixture")
                (evidence / "DIRECT-MODPOST.json").write_text(json.dumps(dict(exitCode=0, inputsUnchanged=True,
                    onlyExactAliasDiagnostics=True, symvers=[builder.identity(kdir / "Module.symvers")])))
                if change_tool:
                    generated["tool"].write_bytes(b"changed during Kbuild")
                return SimpleNamespace(returncode=0)

            argv = ["build_target.py", "--repo-root", str(root), "--kernel-build", str(kdir), "--llvm-bin", str(llvm),
                "--module-source", str(source), "--evidence", str(evidence), "--source", str(source / "bridge.c"),
                "--modpost", str(original), "--kernel-source", str(kernel), "--legacy-direct-v2",
                "--python-dependency-root", str(root), "--python-dependency-manifest", str(root / "dependency-manifest.json"),
                "--python-dependency-manifest-sha256", "fixture-sha"]
            with ExitStack() as stack:
                stack.enter_context(patch.object(builder, "strip_module_debug", return_value=({"fixture": True}, 0)))
                stack.enter_context(patch.object(sys, "argv", argv))
                stack.enter_context(patch.object(builder.importlib.util, "spec_from_file_location", side_effect=spec))
                stack.enter_context(patch.object(builder.importlib.util, "module_from_spec", side_effect=lambda item:
                    direct if item.name == "bridge_direct_modpost" else strict))
                called = stack.enter_context(patch.object(builder.subprocess, "run", side_effect=run))
                if change_tool:
                    with self.assertRaisesRegex(ValueError, "BUILD_INPUT_CHANGED"):
                        builder.main()
                else:
                    builder.main()
                called.assert_called_once()
            receipt = json.loads((evidence / "BUILD.json").read_bytes())
            self.assertEqual(receipt["inputsUnchanged"], not change_tool)
            self.assertEqual("artifacts" in receipt, not change_tool)
            self.assertEqual(receipt["legacyDirectV2"]["strictModpost"], builder.identity(generated["receipt"]))
            for path in generated["inputs"]:
                self.assertIn(str(path), [row["path"] for row in receipt["sources"]])
            for path in [*generated["tools"], generated["tool"]]:
                self.assertIn(str(path), [row["path"] for row in receipt["tools"]])

    def test_derived_tool_receipt_sources_and_tools_reach_real_main_receipts(self):
        self.run_direct(False)

    def test_derived_tool_drift_is_rejected_by_real_main_after_kbuild(self):
        self.run_direct(True)


if __name__ == "__main__":
    unittest.main()
