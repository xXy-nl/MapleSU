"""Real ELF/parser and filesystem checks for the independent KMI publication path.

The in-memory AArch64 ET_REL fixture is not a loadable production module. Only
the executable handoff verifier is an explicit boundary substitute.
"""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch


BASE = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    return api


package = load("component_package_test", BASE / "package.py")
catalog = load("component_catalog_test", BASE / "package_catalog.py")
RELEASE = "6.6.93-android15-8-fixture"
KMI = "android15-6.6"
CONFIG = b"CONFIG_ARM64=y\nCONFIG_MODULES=y\nCONFIG_ARM64_4K_PAGES=y\n"
PRODUCERS = ("init_module", "msu_boot_sdk_init", "msu_manager_resident_init",
             "msu_management_init", "msu_runtime_service_register", "msu_su_registry_create",
             "msu_runtime_btf_init", "msu_runtime_accessor_init", "msu_task_profile_runtime_produce")
COMMON_SOURCES = ("runtime/ultra/identity/kernel/manager_management.c",
                  "runtime/ultra/identity/kernel/manager_resident_host.c",
                  "runtime/ultra/identity/kernel/manager_task_state.c",
                  "runtime/ultra/identity/kernel/manager_su_runtime_target.c",
                  "jailbreak-providers/root-loader/module/maplesu_boot_sdk.c")


def module_bytes(*, release=RELEASE, producers=PRODUCERS, marker=True, namespace=True):
    tags = ["vermagic=" + release + " SMP modversions", "parmtype=credential:string"]
    if marker:
        tags.append("maplesu_runtime_facts=1")
    if namespace:
        tags.append("parmtype=deployment_namespace:string")
    names = b"\0"
    symbols = bytes(24)
    for name in (*producers, "msu_sdk_call_prefix", "msu_sdk_call_blr"):
        offset = len(names)
        names += name.encode() + b"\0"
        value = 32 if name == "msu_sdk_call_blr" else 0
        symbols += struct.pack("<IBBHQQ", offset, 0x12, 0, 1, value, 4)
    strings = b"\0.text\0.strtab\0.symtab\0.modinfo\0.shstrtab\0"
    sections = [(".text", bytes(64), 1, 6, 0, 0, 4, 0),
                (".strtab", names, 3, 0, 0, 0, 1, 0),
                (".symtab", symbols, 2, 0, 2, 1, 8, 24),
                (".modinfo", ("\0".join(tags) + "\0").encode(), 1, 2, 0, 0, 1, 0),
                (".shstrtab", strings, 3, 0, 0, 0, 1, 0)]
    body, headers = bytearray(64), [bytes(64)]
    for name, data, kind, flags, link, info, align, entry in sections:
        body += bytes((-len(body)) % align)
        at = len(body)
        body += data
        headers.append(struct.pack("<IIQQQQIIQQ", strings.index(name.encode()), kind,
                                   flags, 0, at, len(data), link, info, align, entry))
    body += bytes((-len(body)) % 8)
    section_at = len(body)
    body += b"".join(headers)
    body[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            1, 183, 1, 0, 0, section_at, 0, 64, 0, 0, 64, len(headers), 5)
    return bytes(body)


class Inputs:
    def __init__(self, root):
        self.root = root
        self.build = root / "build"
        (self.build / "include/generated").mkdir(parents=True)
        (self.build / ".config").write_bytes(CONFIG)
        (self.build / "include/generated/utsrelease.h").write_bytes(('#define UTS_RELEASE "' + RELEASE + '"\n').encode())
        self.source = root / "manager_runtime_btf.c"
        self.source.write_bytes(b"/* same-generation production-source boundary fixture */\n")
        self.bridge, self.handoff, self.verifier = (root / x for x in ("module.ko", "ultra-init", "verifier.py"))
        self.bridge.write_bytes(module_bytes())
        self.handoff.write_bytes(b"\x7fELF executable verifier fixture")
        self.verifier.write_text("def verify_static_executable(data):\n    assert data.startswith(b'\\x7fELF'), 'HANDOFF_FIXTURE'\n")
        self.selection = root / "SOURCE-SELECTION.json"
        self.strict = root / "STRICT-BUILD.json"
        self.select = {"runtimeFactsSelected": True, "targetBinding": {"kind": "runtime-kmi-component"},
                       "inputs": [{"repositoryPath": "runtime/ultra/identity/kernel/manager_runtime_btf.c",
                                   "selected": package.file_identity(self.source)}]}
        for index, logical in enumerate(COMMON_SOURCES):
            path = root / ("common-source-" + str(index))
            path.write_bytes(("same-generation:" + logical).encode())
            self.select["inputs"].append(dict(repositoryPath=logical, selected=package.file_identity(path)))
        self.rebind()

    def rebind(self):
        self.selection.write_bytes(catalog.encoded(self.select))
        self.receipt = {"exitCode": 0, "inputsUnchanged": True,
                        "sources": [package.file_identity(x) for x in
                                    (self.selection, self.build / ".config", self.build / "include/generated/utsrelease.h")],
                        "artifacts": [package.file_identity(self.bridge)]}
        self.strict.write_bytes(catalog.encoded(self.receipt))

    def publish(self, output=None, kmi=KMI, cfi="none"):
        output = output or self.root / "bundle"
        args = ["package.py", "component", "--kernel-build", str(self.build), "--bridge", str(self.bridge),
                "--handoff", str(self.handoff), "--handoff-verifier", str(self.verifier),
                "--source-selection", str(self.selection), "--strict-build", str(self.strict),
                "--kmi", kmi, "--cfi-mode", cfi, "--output", str(output)]
        with patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
            package.component_main()
        return output

    def row(self, bundle):
        return {"bundle": str(bundle), "sourceSelection": str(self.selection), "strictBuild": str(self.strict)}


class ComponentModuleChecks(unittest.TestCase):
    def inspect(self, blob=None, config=None, cfi="none"):
        return package.inspect_component_module(blob or module_bytes(), RELEASE,
                                                 config or package.config_values(CONFIG), cfi)

    def test_actual_elf_parsing_binds_metadata_without_target_claim(self):
        facts = self.inspect()
        self.assertEqual((facts["pageBytes"], facts["metadataDisplacement"]), (4096, 4064))
        self.assertFalse(facts["targetQualified"])
        self.assertFalse(facts["deviceQualified"])

    def test_runtime_producers_and_marker_are_actual_module_requirements(self):
        for name in ("msu_runtime_btf_init", "msu_runtime_accessor_init", "msu_task_profile_runtime_produce"):
            with self.subTest(symbol=name), self.assertRaisesRegex(ValueError, "RUNTIME_PRODUCERS:" + name):
                self.inspect(module_bytes(producers=tuple(x for x in PRODUCERS if x != name)))
        with self.assertRaisesRegex(ValueError, "RUNTIME_FACTS_REQUIRED"):
            self.inspect(module_bytes(marker=False))

    def test_namespace_parameter_release_and_cfi_are_not_inferred(self):
        with self.assertRaisesRegex(ValueError, "PARAMETER:deployment_namespace"):
            self.inspect(module_bytes(namespace=False))
        with self.assertRaisesRegex(ValueError, "BUILD_RELEASE"):
            self.inspect(module_bytes(release="6.6.94-android15-8-other"))
        facts = self.inspect(cfi="kcfi")
        self.assertEqual((facts["cfiMode"], facts["requestedCfiMode"]), ("none", "kcfi"))
        with self.assertRaisesRegex(ValueError, "TARGET_PAGE_CONFIG"):
            self.inspect(config={"CONFIG_ARM64": "y", "CONFIG_MODULES": "y"})

    def test_kcfi_symbols_classify_actual_module_without_trap_config(self):
        facts = self.inspect(module_bytes(producers=(*PRODUCERS, "__kcfi_typeid_init_module")))
        self.assertEqual((facts["cfiMode"], facts["requestedCfiMode"]), ("kcfi", "none"))

    def test_61_and_612_kcfi_without_traps_is_not_legacy_cfi(self):
        # Both DDKs use CONFIG_CFI_CLANG for -fsanitize=kcfi, without the trap symbol.
        for release in ("6.1.160-fixture", "6.12.82-4k-fixture"):
            for traps in (b"", b"# CONFIG_ARCH_USES_CFI_TRAPS is not set\n"):
                with self.subTest(release=release, traps=bool(traps)):
                    config = package.config_values(CONFIG + b"CONFIG_CFI_CLANG=y\n" + traps)
                    blob = module_bytes(release=release, producers=(*PRODUCERS, "__kcfi_typeid_init_module"))
                    self.assertIsNone(package.ELFFile(io.BytesIO(blob)).get_section_by_name(".kcfi_traps"))
                    facts = package.inspect_component_module(blob, release, config, "legacy-lto-cfi")
                    self.assertEqual((facts["cfiMode"], facts["requestedCfiMode"]), ("kcfi", "legacy-lto-cfi"))

    def test_three_cfi_categories_follow_elf_not_configuration_or_hint(self):
        for actual, symbols in (("none", ()), ("kcfi", ("__kcfi_typeid_init_module",)),
                                ("legacy-lto-cfi", ("__cfi_check",))):
            for hint in ("none", "kcfi", "legacy-lto-cfi"):
                with self.subTest(actual=actual, hint=hint):
                    config = package.config_values(CONFIG + b"CONFIG_CFI_CLANG=y\n")
                    facts = self.inspect(module_bytes(producers=(*PRODUCERS, *symbols)), config, hint)
                    self.assertEqual((facts["cfiMode"], facts["requestedCfiMode"]), (actual, hint))
                    self.assertFalse(facts["targetQualified"])

    def test_build_cohort_sources_and_unknown_cohort_tag_fallback(self):
        release = "6.1.160-android14-9-fixture"
        rows = (({}, {"command": ["make", "-C", "/opt/ddk/kdir/android16-6.12"]}, "android16-6.12"),
                ({}, {"command": ["make", "O=C:\\ddk\\android15-6.6\\"]}, "android15-6.6"),
                ({"selectedNativePrivateHeaders": [{"kernelBuild": "/opt/ddk/kdir/android16-6.12"}]}, {}, "android16-6.12"),
                ({}, {"command": ["make", "-C", "/work/unclassified-build", "O=/tmp/object"]}, "android14-6.1"),
                ({}, {}, "android14-6.1"))
        for selection, build, expected in rows:
            with self.subTest(selection=selection, build=build):
                self.assertEqual(package.component_kmi(release, selection, build), expected)
        self.assertIsNone(package.component_kmi("6.1.160-fixture", {}, {"command": ["make", "-C", "/work/build"]}))


class ComponentFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="maplesu-component-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = Inputs(self.root)


class ComponentPublicationChecks(ComponentFixture):
    def test_strict_bound_actual_module_publishes_without_target_image(self):
        bundle = self.inputs.publish()
        manifest = catalog.read_json(bundle / "manifest.json")
        self.assertEqual(manifest["kmi"], KMI)
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual((bundle / manifest["bridge"]).read_bytes(), self.inputs.bridge.read_bytes())
        self.assertNotIn("targetBoot", manifest)
        proof = catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]
        self.assertFalse(proof["artifactQualified"])
        self.assertFalse(proof["deviceQualified"])

    def test_requested_kmi_does_not_override_actual_build_classification(self):
        for index, kmi in enumerate(("android15-6.12", "android16-6.6")):
            with self.subTest(kmi=kmi):
                bundle = self.inputs.publish(self.root / ("bundle-" + str(index)), kmi=kmi)
                manifest = catalog.read_json(bundle / "manifest.json")
                classification = catalog.read_json(bundle / "BUNDLE-SOURCES.json")["buildClassification"]
                self.assertEqual(manifest["kmi"], KMI)
                self.assertEqual(classification["requestedKmi"], kmi)
                self.assertFalse(catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]["deviceQualified"])

    def test_untagged_ddk_release_publishes_and_catalogs_with_build_cohort(self):
        release = "6.6.127-4k-g46a034eca005-dirty"
        self.inputs.bridge.write_bytes(module_bytes(release=release))
        (self.inputs.build / "include/generated/utsrelease.h").write_bytes(
            ('#define UTS_RELEASE "' + release + '"\n').encode())
        self.inputs.rebind()
        self.inputs.receipt["command"] = ["make", "-C", "/opt/ddk/kdir/android15-6.6", "modules"]
        self.inputs.strict.write_bytes(catalog.encoded(self.inputs.receipt))
        bundle = self.inputs.publish(kmi="android16-6.12")
        manifest = catalog.read_json(bundle / "manifest.json")
        self.assertEqual((manifest["kmi"], manifest["kernelRelease"]), (KMI, release))
        proof = catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]
        self.assertEqual(proof["kmi"], KMI)
        self.assertFalse(proof["artifactQualified"])
        self.assertIsNone(package.component_kmi(release))

    def test_untagged_unknown_cohort_uses_explicit_asset_classification(self):
        release = "6.12.82-4k-fixture"
        self.inputs.bridge.write_bytes(module_bytes(release=release))
        (self.inputs.build / "include/generated/utsrelease.h").write_bytes(
            ('#define UTS_RELEASE "' + release + '"\n').encode())
        self.inputs.rebind()
        self.inputs.receipt["command"] = ["make", "-C", "/work/unclassified-build"]
        self.inputs.strict.write_bytes(catalog.encoded(self.inputs.receipt))
        bundle = self.inputs.publish(kmi="android16-6.12")
        manifest = catalog.read_json(bundle / "manifest.json")
        classification = catalog.read_json(bundle / "BUNDLE-SOURCES.json")["buildClassification"]
        self.assertEqual((manifest["kmi"], manifest["kernelRelease"]), ("android16-6.12", release))
        self.assertIsNone(classification["kmi"])
        self.assertEqual(classification["requestedKmi"], "android16-6.12")
        self.assertFalse(catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]["deviceQualified"])

    def test_published_cfi_is_actual_elf_category_even_when_hint_differs(self):
        for index, (actual, symbols, hint) in enumerate((
                ("none", (), "kcfi"), ("kcfi", ("__kcfi_typeid_init_module",), "legacy-lto-cfi"),
                ("legacy-lto-cfi", ("__cfi_check",), "none"))):
            with self.subTest(actual=actual, hint=hint):
                self.inputs.bridge.write_bytes(module_bytes(producers=(*PRODUCERS, *symbols)))
                (self.inputs.build / ".config").write_bytes(CONFIG + b"CONFIG_CFI_CLANG=y\n")
                self.inputs.rebind()
                bundle = self.inputs.publish(self.root / ("cfi-bundle-" + str(index)), cfi=hint)
                manifest = catalog.read_json(bundle / "manifest.json")
                classification = catalog.read_json(bundle / "BUNDLE-SOURCES.json")["buildClassification"]
                self.assertEqual(manifest["cfiMode"], actual)
                self.assertEqual((classification["cfiMode"], classification["requestedCfiMode"]), (actual, hint))
                self.assertEqual(catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]["cfiMode"], actual)

    def test_failed_build_wrong_selection_and_wrong_module_have_no_manifest(self):
        original = dict(self.inputs.receipt)
        variants = [dict(original, exitCode=1), dict(original, inputsUnchanged=False),
                    dict(original, artifacts=[{"bytes": 1, "sha256": "0" * 64}]),
                    dict(original, sources=original["sources"][1:])]
        for index, receipt in enumerate(variants):
            with self.subTest(index=index):
                self.inputs.strict.write_bytes(catalog.encoded(receipt))
                output = self.root / ("failed-" + str(index))
                with self.assertRaisesRegex(ValueError, "STRICT_"):
                    self.inputs.publish(output)
                self.assertFalse((output / "manifest.json").exists())

    def test_exact_target_selection_is_not_a_runtime_component(self):
        self.inputs.select["targetBinding"]["kind"] = "maplesu-init-bridge-kmi-target/1"
        self.inputs.rebind()
        with self.assertRaisesRegex(ValueError, "RUNTIME_SOURCE_SELECTION"):
            self.inputs.publish()

    def test_selected_source_drift_does_not_publish_success(self):
        self.inputs.source.write_bytes(b"changed selected source")
        with self.assertRaisesRegex(ValueError, "SELECTED_SOURCE_CHANGED"):
            self.inputs.publish()
        self.assertFalse((self.root / "bundle").exists())

    def test_existing_bundle_is_preserved(self):
        bundle = self.inputs.publish()
        old = (bundle / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "OUTPUT_NOT_FRESH"):
            self.inputs.publish()
        self.assertEqual((bundle / "manifest.json").read_bytes(), old)


class ComponentCatalogChecks(ComponentFixture):
    def rewrite_source_proof(self, bundle):
        """Rebind deliberately edited receipts so catalog must inspect their content."""
        path = bundle / "BUNDLE-SOURCES.json"
        proof = catalog.read_json(path)
        proof["strictBuild"] = package.file_identity(self.inputs.strict)
        for name in ("strict_build", "release"):
            item = proof["inputs"][name]
            actual = package.file_identity(Path(item["path"]))
            item.update(actual, bundledBytes=actual["bytes"], bundledSha256=actual["sha256"])
        raw = catalog.encoded(proof)
        path.write_bytes(raw)
        manifest = catalog.read_json(bundle / "manifest.json")
        manifest["bundleSourcesSha256"] = catalog.sha(raw)
        (bundle / "manifest.json").write_bytes(catalog.encoded(manifest))

    def plan(self, bundles):
        plan = self.root / "PLAN.json"
        plan.write_bytes(catalog.encoded({"schema": "maplesu-init-bridge-catalog-plan/2",
                                         "components": [self.inputs.row(x) for x in bundles]}))
        return plan

    def publish_catalog(self, bundles, output=None, append=False):
        return catalog.package(self.plan(bundles), output or self.root / "assets", append)

    def legacy_index(self, output, *, changed_common=False, changed_handoff=False):
        output.mkdir()
        sources, _ = catalog.selection_sources(self.inputs.select)
        del sources["runtime/ultra/identity/kernel/manager_runtime_btf.c"]
        if changed_common:
            key = next(iter(sources))
            sources[key] = dict(bytes=123, sha256="f" * 64)
        # Exact-target-only TU: accepted when common inputs remain identical.
        sources["runtime/ultra/identity/kernel/manager_target_only.c"] = dict(bytes=7, sha256="a" * 64)
        generation_inputs = dict(moduleSources=sources, handoffSha256=("b" * 64 if changed_handoff else
                                                                    catalog.sha(self.inputs.handoff.read_bytes())))
        generation = catalog.sha(catalog.encoded(generation_inputs))
        manifest_sha = "c" * 64
        proof = dict(schema="maplesu-init-bridge-variant/1", manifestSha256=manifest_sha,
                     sourceGenerationSha256=generation, generationInputs=generation_inputs)
        raw = catalog.encoded(proof)
        proof_name = "catalog-proofs/" + manifest_sha + ".json"
        (output / "catalog-proofs").mkdir()
        (output / proof_name).write_bytes(raw)
        index = dict(schema="maplesu-init-bridge-catalog/1", sourceGenerationSha256=generation,
                     defaultManifestSha256=manifest_sha,
                     variants=[dict(manifestSha256=manifest_sha, proof=proof_name,
                                    proofSha256=catalog.sha(raw), sourceGenerationSha256=generation)])
        (output / "catalog.json").write_bytes(catalog.encoded(index))
        return (output / "catalog.json").read_bytes()

    def test_actual_component_is_copied_and_indexed_last(self):
        bundle = self.inputs.publish()
        index = self.publish_catalog([bundle])
        entry = index["components"][0]
        self.assertEqual(entry["kmi"], KMI)
        root = self.root / "assets" / entry["prefix"]
        self.assertEqual(catalog.sha((root / "manifest.json").read_bytes()), entry["manifestSha256"])
        self.assertEqual((root / "bridge.ko").read_bytes(), self.inputs.bridge.read_bytes())

    def test_changed_module_or_old_target_fact_never_publishes_catalog(self):
        bundle = self.inputs.publish()
        (bundle / "bridge.ko").write_bytes(b"changed module")
        with self.assertRaisesRegex(ValueError, "COMPONENT_HASH:bridge"):
            self.publish_catalog([bundle])
        self.assertFalse((self.root / "assets/catalog-kmi.json").exists())
        (bundle / "bridge.ko").write_bytes(self.inputs.bridge.read_bytes())
        manifest = catalog.read_json(bundle / "manifest.json")
        manifest["targetBootSha256"] = "f" * 64
        (bundle / "manifest.json").write_bytes(catalog.encoded(manifest))
        with self.assertRaisesRegex(ValueError, "COMPONENT_SCHEMA"):
            self.publish_catalog([bundle])

    def test_manifest_kmi_matches_known_build_or_selected_ddk_cohort(self):
        for origin in ("build-command", "selected-ddk"):
            with self.subTest(origin=origin):
                self.inputs.select.pop("selectedNativePrivateHeaders", None)
                if origin == "selected-ddk":
                    self.inputs.select["selectedNativePrivateHeaders"] = [{"kernelBuild": "/opt/ddk/kdir/android16-6.12"}]
                self.inputs.rebind()
                if origin == "build-command":
                    self.inputs.receipt["command"] = ["make", "-C", "/opt/ddk/kdir/android16-6.12"]
                    self.inputs.strict.write_bytes(catalog.encoded(self.inputs.receipt))
                bundle = self.inputs.publish(self.root / ("bundle-" + origin), kmi="android15-6.6")
                path = bundle / "manifest.json"
                manifest = catalog.read_json(path)
                self.assertEqual(manifest["kmi"], "android16-6.12")
                self.assertEqual(catalog.inspect_component(self.inputs.row(bundle), self.root)["proof"]["kmi"], "android16-6.12")
                manifest["kmi"] = "android15-6.6"
                path.write_bytes(catalog.encoded(manifest))
                output = self.root / ("assets-" + origin)
                with self.assertRaisesRegex(ValueError, "KMI_CLASSIFICATION"):
                    self.publish_catalog([bundle], output)
                self.assertFalse((output / "catalog-kmi.json").exists())

    def test_manifest_cfi_matches_actual_elf_category(self):
        for index, (actual, symbols, mislabeled) in enumerate((
                ("none", (), "kcfi"), ("kcfi", ("__kcfi_typeid_init_module",), "legacy-lto-cfi"),
                ("legacy-lto-cfi", ("__cfi_check",), "none"))):
            with self.subTest(actual=actual, mislabeled=mislabeled):
                self.inputs.bridge.write_bytes(module_bytes(producers=(*PRODUCERS, *symbols)))
                self.inputs.rebind()
                bundle = self.inputs.publish(self.root / ("bundle-cfi-" + str(index)), cfi=mislabeled)
                path = bundle / "manifest.json"
                manifest = catalog.read_json(path)
                self.assertEqual(manifest["cfiMode"], actual)
                manifest["cfiMode"] = mislabeled
                path.write_bytes(catalog.encoded(manifest))
                output = self.root / ("assets-cfi-" + str(index))
                with self.assertRaisesRegex(ValueError, "CFI_CLASSIFICATION"):
                    self.publish_catalog([bundle], output)
                self.assertFalse((output / "catalog-kmi.json").exists())

    def test_catalog_independently_requires_strict_config_and_release_inputs(self):
        for name, filename in (("config", ".config"), ("release", "include/generated/utsrelease.h")):
            with self.subTest(name=name):
                self.inputs.rebind()
                bundle = self.inputs.publish(self.root / ("bundle-"+name))
                excluded = str((self.inputs.build / filename).resolve())
                receipt = dict(self.inputs.receipt)
                receipt["sources"] = [row for row in receipt["sources"] if row["path"] != excluded]
                self.inputs.strict.write_bytes(catalog.encoded(receipt))
                self.rewrite_source_proof(bundle)
                with self.assertRaisesRegex(ValueError, "BUILD_INPUT|STRICT_.*(?:CONFIG|RELEASE|INPUT)"):
                    catalog.inspect_component(self.inputs.row(bundle), self.root)

    def test_catalog_binds_actual_uts_release_to_manifest(self):
        bundle = self.inputs.publish()
        header = self.inputs.build / "include/generated/utsrelease.h"
        header.write_bytes(b'#define UTS_RELEASE "6.6.94-android15-8-other"\n')
        self.inputs.rebind()
        self.rewrite_source_proof(bundle)
        with self.assertRaisesRegex(ValueError, "BUILD_RELEASE|UTS_RELEASE"):
            catalog.inspect_component(self.inputs.row(bundle), self.root)

    def test_duplicate_component_key_is_rejected_before_copy(self):
        bundle = self.inputs.publish()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_COMPONENT"):
            self.publish_catalog([bundle, bundle])
        self.assertFalse((self.root / "assets").exists())

    def test_dual_indexes_allow_target_specific_source_set_and_preserve_catalog1(self):
        bundle = self.inputs.publish()
        output = self.root / "assets"
        before = self.legacy_index(output)
        result = self.publish_catalog([bundle], output, append=True)
        self.assertEqual(result["schema"], "maplesu-init-bridge-catalog/2")
        self.assertEqual((output / "catalog.json").read_bytes(), before)
        self.assertTrue((output / "catalog-kmi.json").is_file())

    def test_dual_indexes_reject_changed_common_source_before_copy(self):
        bundle = self.inputs.publish()
        output = self.root / "assets"
        self.legacy_index(output, changed_common=True)
        with self.assertRaisesRegex(ValueError, "GENERATION|COHORT|SOURCE"):
            self.publish_catalog([bundle], output, append=True)
        self.assertFalse((output / "catalog-kmi.json").exists())

    def test_dual_indexes_reject_different_handoff(self):
        bundle = self.inputs.publish()
        output = self.root / "assets"
        self.legacy_index(output, changed_handoff=True)
        with self.assertRaisesRegex(ValueError, "GENERATION|COHORT|HANDOFF"):
            self.publish_catalog([bundle], output, append=True)
        self.assertFalse((output / "catalog-kmi.json").exists())

    def test_catalog1_append_after_catalog2_is_rejected_without_writing(self):
        # This test owns only the append-order boundary. The variant inspector
        # is an explicit substitute; no legacy module is qualified here.
        output = self.root / "assets"
        output.mkdir()
        manifest = output / "manifest.json"
        manifest.write_bytes(b"legacy-default fixture\n")
        before = b'{"schema":"maplesu-init-bridge-catalog/2","components":[]}\n'
        (output / "catalog-kmi.json").write_bytes(before)
        digest = catalog.identity(manifest)["sha256"]
        plan = self.root / "reverse-plan.json"
        plan.write_bytes(catalog.encoded(dict(schema="maplesu-init-bridge-catalog-plan/1",
                                              variants=[{}], defaultManifestSha256=digest)))
        variant = dict(generation="a"*64, proof=dict(manifestSha256=digest),
                       files={"manifest.json": catalog.identity(manifest)}, dependencies=[])
        with patch.object(catalog, "inspect_variant", return_value=variant):
            with self.assertRaisesRegex(ValueError, "PUBLISH_EXACT_BEFORE_COMPONENTS"):
                catalog.package(plan, output, append=True)
        self.assertFalse((output / "catalog.json").exists())
        self.assertFalse((output / "catalog-proofs").exists())
        self.assertEqual((output / "catalog-kmi.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
