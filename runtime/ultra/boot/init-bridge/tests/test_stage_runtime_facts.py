"""Current stage/runtime-facts selection and pre-build identity fences only."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import test_stage


BASE = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("runtime_facts_build_target_test", BASE / "build_target.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RuntimeFactsStageChecks(unittest.TestCase):
    def fixture(self):
        case = test_stage.StageChecks()
        case.setUp()
        case.formal_target_child()
        prefix = "runtime/ultra/identity/kernel/"
        rows = []
        names = [unit + suffix for unit in ("manager_dynamic_layout", "manager_runtime_btf",
                                           "manager_runtime_accessor", "manager_task_profile_runtime") for suffix in (".c", ".h")]
        names += ["manager_task_profile_workbit.h", "manager_su_runtime_target_profile.h"]
        for name in names:
            path = case.host / "runtime-facts" / name
            case.files[path] = ("/* runtime fact fixture " + name + " */\n").encode()
            if name == "manager_task_profile_runtime.c":
                case.files[path] += b'#include "manager_task_profile_workbit.h"\n'
            before = case.runtime_members[name] if name == "manager_su_runtime_target_profile.h" else None
            rows.append(dict(logicalPath=prefix+name, before=before,
                             after=test_stage.stage.identity(path, case.files[path])))
        selection = case.repo / "runtime-facts-selection.json"
        case.files[selection] = json.dumps(dict(schema="maplesu-claim-runtime-layout-source-selection/1",
                                               files=rows)).encode()
        case.argv += ["--runtime-facts", "--runtime-layout-source-selection", str(selection),
                      "--runtime-layout-source-selection-sha256", test_stage.stage.identity(selection, case.files[selection])["sha256"]]
        case.directories.update(parent for path in case.files for parent in path.parents)
        return case, selection

    def test_fact_producers_workbit_and_runtime_profile_reach_real_stage(self):
        case, _ = self.fixture()
        receipt = case.run_stage()
        self.assertTrue(receipt["runtimeFactsSelected"])
        self.assertEqual(receipt["targetBinding"]["kind"], "runtime-kmi-component")
        self.assertFalse(receipt["targetBinding"]["kernelImageIdentityEstablished"])
        self.assertFalse(receipt["targetQualified"])
        rows = {row["staged"]: row for row in receipt["inputs"]}
        for name in ("manager_runtime_btf.c", "manager_runtime_btf.h", "manager_runtime_accessor.c",
                     "manager_runtime_accessor.h", "manager_task_profile_runtime.c",
                     "manager_task_profile_runtime.h", "manager_task_profile_workbit.h",
                     "manager_su_runtime_target_profile.h"):
            self.assertEqual(rows["host/"+name]["selection"], "runtime-layout-source-successor")
        flags = case.files[case.output / "selected-core.mk"].decode()
        self.assertIn("-DMSU_INIT_BRIDGE_RUNTIME_FACTS=1", flags)
        for unit in ("manager_runtime_btf", "manager_runtime_accessor", "manager_task_profile_runtime"):
            self.assertEqual(receipt["selectedCoreDependencyObjects"].count("host/"+unit+".o"), 1)

    def test_runtime_su_target_uses_typed_host_imports_without_duplicate_object(self):
        case, _ = self.fixture()
        case.run_stage()
        flags = case.files[case.output / "selected-core.mk"].decode()
        binding = ("CFLAGS_host/manager_su_runtime_target.o += "
                   "-DMSU_INIT_BRIDGE_HOST_IMPORTS=1 -include $(src)/native_imports.h\n")
        self.assertEqual(flags.count(binding), 1)
        runtime = case.files[case.output / "selected-runtime.mk"].decode()
        self.assertEqual(runtime.split("\n")[1].split().count("host/manager_su_runtime_target.o"), 1)

    def test_exact_su_target_preserves_existing_import_selection(self):
        case = test_stage.StageChecks()
        case.setUp()
        case.formal_target_child()
        case.run_stage()
        flags = case.files[case.output / "selected-core.mk"].decode()
        self.assertNotIn("CFLAGS_host/manager_su_runtime_target.o", flags)

    def test_missing_fact_source_has_no_success_receipt(self):
        for missing in ("manager_runtime_btf.h", "manager_runtime_accessor.c"):
            with self.subTest(missing=missing):
                case, selection = self.fixture()
                value = json.loads(case.files[selection])
                value["files"] = [x for x in value["files"] if not x["logicalPath"].endswith(missing)]
                case.files[selection] = json.dumps(value).encode()
                case.argv[-1] = test_stage.stage.identity(selection, case.files[selection])["sha256"]
                with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_SOURCE_CLOSURE"):
                    case.run_stage()
                self.assertNotIn(case.output / "SOURCE-SELECTION.json", case.files)

    def test_exact_target_contract_cannot_mix_with_runtime_fact_mode(self):
        case, _ = self.fixture()
        case.argv += ["--target-kmi", str(case.repo / "old-exact-target.json")]
        with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_EXACT_TARGET_CONFLICT"):
            case.run_stage()


class RuntimeFactsBuildInputChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="maplesu-facts-build-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.source, self.kdir = self.repo / "module", self.repo / "kernel"
        (self.source / "host").mkdir(parents=True)
        self.kdir.mkdir()
        (self.kdir / ".config").write_text("CONFIG_ARM64_4K_PAGES=y\n")
        self.names = ["manager_su_runtime_target_profile.h", "manager_task_profile_workbit.h",
                      "manager_runtime_btf.c", "manager_runtime_btf.h", "manager_runtime_accessor.c", "manager_runtime_accessor.h",
                      "manager_task_profile_runtime.c", "manager_task_profile_runtime.h"]
        layout, inputs = [], []
        for name in self.names:
            path = self.source / "host" / name
            path.write_text("runtime-selected fixture:"+name)
            logical = "runtime/ultra/identity/kernel/"+name
            identity = builder.identity(path)
            layout.append(dict(logicalPath=logical, after=identity))
            inputs.append(dict(repositoryPath=logical, staged="host/"+name,
                               selection="runtime-layout-source-successor", selected=identity))
        self.layout = self.repo / "layout.json"
        self.layout.write_text(json.dumps(dict(schema="maplesu-claim-runtime-layout-source-selection/1", files=layout)))
        reference = dict(builder.identity(self.layout), repositoryPath="layout.json")
        self.receipt = dict(runtimeFactsSelected=True, formalRuntimeSuccessors=[reference], inputs=inputs,
                            targetBinding=dict(kind="runtime-kmi-component", runtimeLayoutProfile=reference,
                                               buildConfig=builder.identity(self.kdir / ".config")))
        self.receipt_file = self.source / "SOURCE-SELECTION.json"
        self.write_receipt()
        (self.source / "selected-core.mk").write_text("ccflags-y += -DMSU_INIT_BRIDGE_RUNTIME_FACTS=1\n"
                                                     "objects += host/manager_runtime_btf.o host/manager_runtime_accessor.o host/manager_task_profile_runtime.o\n")

    def write_receipt(self):
        self.receipt_file.write_text(json.dumps(self.receipt))

    def inputs(self):
        return builder.staged_target_inputs(self.source, self.kdir, self.repo)

    def test_runtime_branch_requires_no_old_target_image_or_kernel_source(self):
        selected = self.inputs()
        self.assertEqual(set(selected), {self.receipt_file, self.layout,
                                        *(self.source / "host" / name for name in self.names)})

    def test_missing_or_changed_selected_producer_stops_before_build(self):
        for name in self.names:
            with self.subTest(name=name):
                path = self.source / "host" / name
                old = path.read_bytes()
                path.write_bytes(old+b"changed")
                try:
                    with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_SOURCE_IDENTITY:"+name):
                        self.inputs()
                finally:
                    path.write_bytes(old)

    def test_config_and_kbuild_flags_are_bound(self):
        config = self.kdir / ".config"
        old = config.read_bytes()
        config.write_bytes(old+b"# other build\n")
        with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_BUILD_CONFIG"):
            self.inputs()
        config.write_bytes(old)
        flags = self.source / "selected-core.mk"
        old_flags = flags.read_bytes()
        for missing in (b"-DMSU_INIT_BRIDGE_RUNTIME_FACTS=1", b"host/manager_runtime_btf.o",
                        b"host/manager_runtime_accessor.o", b"host/manager_task_profile_runtime.o"):
            with self.subTest(missing=missing):
                flags.write_bytes(old_flags.replace(missing, b""))
                with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_KBUILD"):
                    self.inputs()

    def test_old_selection_fact_or_different_layout_generation_is_rejected(self):
        self.receipt["runtimeFactsSelected"] = False
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_SELECTION_REQUIRED"):
            self.inputs()
        self.receipt["runtimeFactsSelected"] = True
        self.write_receipt()
        self.layout.write_bytes(self.layout.read_bytes()+b" ")
        with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_SELECTION_IDENTITY"):
            self.inputs()


if __name__ == "__main__":
    unittest.main()
