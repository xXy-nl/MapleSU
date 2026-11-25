"""Real source-stage selection with memory-only manifests; no ELF qualification."""
import json
from pathlib import Path
import unittest

import test_stage


class KsuCompatStageChecks(unittest.TestCase):
    def refresh(self, case):
        emission = json.loads(case.files[case.runtime_emission])
        frozen = json.loads(case.files[case.runtime_freeze])
        paths = {Path(row["path"]) for row in frozen["files"] + emission["selectedNativeInputs"]}
        frozen["files"] = [test_stage.stage.identity(path, case.files[path]) for path in sorted(paths)]
        case.files[case.runtime_freeze] = json.dumps(frozen).encode()
        candidate = json.loads(case.files[case.runtime_candidate])
        candidate["sourceEmission"] = test_stage.stage.identity(case.runtime_emission, case.files[case.runtime_emission])
        candidate["sourceFreeze"] = test_stage.stage.identity(case.runtime_freeze, case.files[case.runtime_freeze])
        case.files[case.runtime_candidate] = json.dumps(candidate).encode()

    def fixture(self, members=(".c", ".h")):
        case = test_stage.StageChecks()
        case.setUp()
        case.runtime_selections()
        emission = json.loads(case.files[case.runtime_emission])
        for suffix in members:
            name = "manager_ksu_compat" + suffix
            path = case.host / "runtime/frozen-native" / name
            case.files[path] = ("exact selected KSU compat " + suffix).encode()
            emission["selectedNativeInputs"].append(test_stage.stage.identity(path, case.files[path]))
        case.files[case.runtime_emission] = json.dumps(emission).encode()
        self.refresh(case)
        return case

    def test_complete_selected_compat_cohort_is_staged_and_linked_once(self):
        case = self.fixture()
        receipt = case.run_stage()
        rows = {row["staged"]: row for row in receipt["inputs"]}
        for suffix in (".c", ".h"):
            key = "host/manager_ksu_compat" + suffix
            self.assertEqual(case.files[case.output / key], ("exact selected KSU compat " + suffix).encode())
            self.assertEqual(rows[key]["selection"], "host-runtime-frozen")
        self.assertEqual(receipt["selectedHostRuntimeObjects"].count("host/manager_ksu_compat.o"), 1)
        makefile = case.files[case.output / "selected-runtime.mk"].decode()
        self.assertEqual(makefile.split().count("host/manager_ksu_compat.o"), 1)
        self.assertIn("host_tus += manager_ksu_compat", makefile)
        self.assertNotIn("MSU_KSU_COMPAT_RAW_RESIDENT", makefile)
        self.assertFalse(receipt["targetQualified"])

    def test_partial_compat_cohort_has_no_success_receipt(self):
        for members in ((".c",), (".h",)):
            case = self.fixture(members)
            with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_KSU_COMPAT_SOURCE_SET"):
                case.run_stage()
            self.assertNotIn(case.output / "SOURCE-SELECTION.json", case.files)

    def test_selected_compat_source_drift_has_no_success_receipt(self):
        case = self.fixture()
        path = case.host / "runtime/frozen-native/manager_ksu_compat.c"
        case.files[path] += b"changed"
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SELECTION_REFERENCE_IDENTITY"):
            case.run_stage()
        self.assertNotIn(case.output / "SOURCE-SELECTION.json", case.files)

    def test_factory_reference_without_compat_selection_is_rejected(self):
        case = self.fixture(())
        path = Path(case.runtime_members["manager_su_runtime_factory.c"]["path"])
        case.files[path] += b" msu_ksu_compat_open();"
        reference = test_stage.stage.identity(path, case.files[path])
        emission = json.loads(case.files[case.runtime_emission])
        emission["selectedNativeInputs"] = [reference if row["path"] == str(path) else row
            for row in emission["selectedNativeInputs"]]
        case.files[case.runtime_emission] = json.dumps(emission).encode()
        self.refresh(case)
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_KSU_COMPAT_SELECTION_REQUIRED"):
            case.run_stage()
        self.assertNotIn(case.output / "SOURCE-SELECTION.json", case.files)


if __name__ == "__main__":
    unittest.main()
