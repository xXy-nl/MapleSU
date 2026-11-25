"""In-memory structural checks only; these fixtures never become bridge files."""
import importlib.util
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import struct
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("bridge_package", Path(__file__).parents[1] / "package.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def module_without_direct_calls():
    # The independent direct-call parser consumes these real ELF bytes while
    # the existing structural tests supply their own symbol/config facts.
    strings = b"\0.shstrtab\0"
    sections = (64 + len(strings) + 7) & ~7
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
        1, 183, 1, 0, 0, sections, 0, 64, 0, 0, 64, 2, 1)
    names = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 64, len(strings), 0, 0, 1, 0)
    return header + strings + bytes(sections - 64 - len(strings)) + bytes(64) + names


NO_DIRECT_MODULE = module_without_direct_calls()


class Section:
    def __init__(self, data):
        self.raw = data

    def data(self):
        return self.raw


class Symbol(dict):
    def __init__(self, name, defined):
        super().__init__(st_shndx=1 if defined else "SHN_UNDEF", st_info={"bind": "STB_GLOBAL"})
        self.name = name


class Elf(dict):
    elfclass, little_endian = 64, True

    def __init__(self):
        super().__init__(e_type="ET_REL", e_machine="EM_AARCH64")
        self.names = ["init_module", "msu_boot_sdk_init", "msu_manager_resident_init",
                      "msu_management_init", "msu_runtime_service_register",
                      "msu_su_registry_create", "msu_su_read_current"]
        self.tags = b"vermagic=6.18.21-4k SMP modversions\0license=GPL\0import_ns=TEST\0"
        self.versions = b"".join(crc.to_bytes(8, "little") + name.encode().ljust(56, b"\0")
                                 for name, crc in (("register_kprobe", 1), ("module_layout", 2)))

    def iter_symbols(self):
        return iter([*[Symbol(name, True) for name in self.names], Symbol("register_kprobe", False)])

    def get_section_by_name(self, name):
        return {".symtab": self, ".modinfo": Section(self.tags),
                "__versions": Section(self.versions)}.get(name)


class PackagingChecks(unittest.TestCase):
    def setUp(self):
        self.elf = Elf()
        self.config = {"CONFIG_ARM64": "y", "CONFIG_MODULES": "y", "CONFIG_MODVERSIONS": "y"}
        self.symvers = b"0x00000001\tregister_kprobe\tvmlinux\tEXPORT_SYMBOL_GPL\tTEST\n0x00000002\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\n"

    def inspect(self, data=NO_DIRECT_MODULE):
        with patch.object(package, "ELFFile", return_value=self.elf):
            return package.inspect_module(data, "6.18.21-4k", self.config, self.symvers)

    def test_structural_success_does_not_claim_su(self):
        self.assertFalse(self.inspect()["coldBootOrSuQualified"])

    def test_existing_ksu_or_wrapper_is_not_a_bridge(self):
        self.elf.names = ["init_module"]
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_PROVIDERS_MISSING"):
            self.inspect()

    def test_private_import_reports_exact_symbol(self):
        self.symvers = self.symvers.splitlines(keepends=True)[1]
        with self.assertRaisesRegex(ValueError, "IMPORT_NOT_EXPORTED:register_kprobe"):
            self.inspect()

    def test_namespace_is_required(self):
        self.elf.tags = self.elf.tags.replace(b"import_ns=TEST\0", b"")
        with self.assertRaisesRegex(ValueError, "IMPORT_NAMESPACE:register_kprobe:TEST"):
            self.inspect()

    def test_crc_is_not_inferred_from_release(self):
        self.symvers = self.symvers.replace(b"0x00000001", b"0x12345678")
        with self.assertRaisesRegex(ValueError, "IMPORT_CRC:register_kprobe"):
            self.inspect()

    def test_module_layout_pin_is_required(self):
        self.elf.versions = self.elf.versions[:64]
        with self.assertRaisesRegex(ValueError, "IMPORT_CRC:module_layout"):
            self.inspect()

    def test_another_module_is_not_a_first_stage_dependency(self):
        self.symvers = self.symvers.replace(b"register_kprobe\tvmlinux", b"register_kprobe\tvendor/module")
        with self.assertRaisesRegex(ValueError, "EXTERNAL_MODULE_DEPENDENCY:register_kprobe"):
            self.inspect()

    def test_truncated_versions_are_rejected(self):
        self.elf.versions = self.elf.versions[:-1]
        with self.assertRaisesRegex(ValueError, "MODVERSIONS_FORMAT"):
            self.inspect()

    def test_crlf_config_preserves_actual_required_options(self):
        config = b"CONFIG_ARM64=y\r\nCONFIG_MODULES=y\r\nCONFIG_MODVERSIONS=y\r\n"
        self.assertEqual(package.config_values(config), self.config)
        with self.assertRaisesRegex(ValueError, "TARGET_CONFIG_DUPLICATE:CONFIG_MODULES"):
            package.config_values(config + b"CONFIG_MODULES=n\r\n")

    def test_module_config_and_forced_signature_apply_to_all_credential_modes(self):
        self.config["CONFIG_MODULES"] = "n"
        with self.assertRaisesRegex(ValueError, "TARGET_MODULE_CONFIG"):
            self.inspect()
        self.config["CONFIG_MODULES"] = "y"
        self.config["CONFIG_MODULE_SIG_FORCE"] = "y"
        with self.assertRaisesRegex(ValueError, "TARGET_MODULE_SIGNATURE_REQUIRED"):
            self.inspect()
        self.assertFalse(self.inspect(NO_DIRECT_MODULE + b"~Module signature appended~\n")["coldBootOrSuQualified"])

    def test_duplicate_symvers_or_module_versions_are_not_silently_replaced(self):
        self.symvers += self.symvers.splitlines(keepends=True)[0]
        with self.assertRaisesRegex(ValueError, "SYMVERS_DUPLICATE:register_kprobe"):
            self.inspect()
        self.symvers = b"".join(self.symvers.splitlines(keepends=True)[:2])
        self.elf.versions += self.elf.versions[:64]
        with self.assertRaisesRegex(ValueError, "MODVERSIONS_FORMAT"):
            self.inspect()

    def test_empty_export_contract_is_rejected_without_modversions_or_imports(self):
        self.config.pop("CONFIG_MODVERSIONS")
        self.elf.iter_symbols = lambda: iter(Symbol(name, True) for name in self.elf.names)
        for symvers in (b"", b"\n", b" \n\t"):
            with self.subTest(symvers=symvers):
                self.symvers = symvers
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_SYMVERS_EMPTY"):
                    self.inspect()

    def test_malformed_symvers_is_not_ignored(self):
        for row in (b"0x1 short vmlinux EXPORT_SYMBOL\n", b"truncated\n"):
            with self.subTest(row=row):
                self.symvers += row
                try:
                    with self.assertRaisesRegex(ValueError, "SYMVERS_FORMAT"):
                        self.inspect()
                finally:
                    self.symvers = self.symvers[:-len(row)]


class ExtendedVersionChecks(unittest.TestCase):
    def versions(self, names, crcs):
        elf = Mock()
        sections = {"__version_ext_names": Section(names) if names is not None else None,
                    "__version_ext_crcs": Section(crcs) if crcs is not None else None}
        elf.get_section_by_name.side_effect = sections.get
        return package.module_versions(elf)

    def test_complete_extended_versions(self):
        self.assertEqual(self.versions(b"register_kprobe\0module_layout\0", b"\1\0\0\0\2\0\0\0"),
                         {"register_kprobe": 1, "module_layout": 2})
        self.assertEqual(self.versions(b"", b""), {})

    def test_missing_pair_truncation_duplicate_and_empty_name(self):
        for names, crcs in ((b"a\0", None), (None, b"\1\0\0\0"), (b"a", b"\1\0\0\0"),
                            (b"a\0", b"\1\0"), (b"a\0a\0", b"\1\0\0\0\2\0\0\0"),
                            (b"a\0\0", b"\1\0\0\0\2\0\0\0")):
            with self.subTest(names=names, crcs=crcs):
                with self.assertRaisesRegex(ValueError, "MODVERSIONS_FORMAT"):
                    self.versions(names, crcs)


class KmiPackagingChecks(PackagingChecks):
    def setUp(self):
        super().setUp()
        self.contract = {"targetVermagic": "6.6.89-target SMP modversions",
                         "unprotectedSymbols": ["register_kprobe"], "initKcfi": 0x36b1c5a6}
        self.elf.tags = self.elf.tags.replace(b"6.18.21-4k", b"6.6.127-real-ddk")

    def inspect(self, data=NO_DIRECT_MODULE):
        with patch.object(package, "ELFFile", return_value=self.elf):
            return package.inspect_module(data, "6.6.89-target", self.config, self.symvers, self.contract)

    def test_real_versions_enable_only_release_word_exception(self):
        self.assertEqual(self.inspect()["vermagic"], "6.6.127-real-ddk SMP modversions")
        for magic in (b"6.6.127-real-ddk SMP", b"6.6.127-real-ddk  SMP modversions",
                      b"6.6.127-real-ddk SMP modversions ", b"6.6.127-real-ddk SMP preempt modversions"):
            with self.subTest(magic=magic):
                original = self.elf.tags
                self.elf.tags = b"vermagic=" + magic + b"\0license=GPL\0import_ns=TEST\0"
                with self.assertRaisesRegex(ValueError, "VERMAGIC_TARGET"):
                    self.inspect()
                self.elf.tags = original

    def test_missing_versions_keeps_complete_vermagic_check(self):
        self.elf.versions = b""
        with self.assertRaisesRegex(ValueError, "VERMAGIC_TARGET"):
            self.inspect()
        # The config flag alone does not grant the same_magic exception.
        self.config.pop("CONFIG_MODVERSIONS")
        with self.assertRaisesRegex(ValueError, "VERMAGIC_TARGET"):
            self.inspect()
        self.elf.tags = self.elf.tags.replace(b"6.6.127-real-ddk", b"6.6.89-target")
        self.assertFalse(self.inspect()["coldBootOrSuQualified"])

    def test_signature_trailer_does_not_bypass_target_sig_protect(self):
        self.config["CONFIG_MODULE_SIG_PROTECT"] = "y"
        self.assertFalse(self.inspect()["coldBootOrSuQualified"])
        self.contract["unprotectedSymbols"] = []
        for data in (NO_DIRECT_MODULE, NO_DIRECT_MODULE + b"~Module signature appended~\n"):
            with self.assertRaisesRegex(ValueError, "IMPORT_SIG_PROTECT:register_kprobe"):
                self.inspect(data)

    def test_gpl_target_export_keeps_actual_module_license_gate(self):
        self.elf.tags = self.elf.tags.replace(b"license=GPL", b"license=Proprietary")
        with self.assertRaisesRegex(ValueError, "IMPORT_GPL:register_kprobe"):
            self.inspect()

    def test_target_init_cfi_uses_real_entry_preceding_word(self):
        self.config["CONFIG_CFI_CLANG"] = "y"
        self.elf.get_symbol_by_name = lambda name: [{"st_shndx": 1, "st_value": 4}]
        section = Mock()
        fields = {"sh_type": "SHT_PROGBITS", "sh_flags": 4, "sh_size": 8}
        section.__getitem__ = Mock(side_effect=fields.__getitem__)
        section.data.return_value = self.contract["initKcfi"].to_bytes(4, "little") + b"CODE"
        self.elf.get_section = lambda index: section
        self.assertFalse(self.inspect()["coldBootOrSuQualified"])
        section.data.return_value = b"\0" * 8
        with self.assertRaisesRegex(ValueError, "INIT_CFI_TARGET"):
            self.inspect()


class ParameterMetadataChecks(unittest.TestCase):
    def setUp(self):
        self.symbols = {"msu_sdk_call_prefix": [{"st_shndx": 1, "st_value": 0}],
                        "msu_sdk_call_blr": [{"st_shndx": 1, "st_value": 32}]}
        self.section = {"sh_type": "SHT_PROGBITS", "sh_flags": 4, "sh_size": 256}
        self.tags = b"parmtype=credential:string\0"
        self.config = {"CONFIG_ARM64": "y", "CONFIG_MODULES": "y", "CONFIG_ARM64_4K_PAGES": "y"}

    def metadata(self):
        table = Mock()
        table.get_symbol_by_name.side_effect = self.symbols.get
        elf = Mock()
        elf.get_section_by_name.side_effect = lambda name: {".symtab": table, ".modinfo": Section(self.tags)}.get(name)
        elf.get_section.return_value = self.section
        with patch.object(package, "ELFFile", return_value=elf):
            return package.module_parameter_metadata(b"in-memory module only", self.config)

    def test_delta_uses_real_symbol_difference_and_page_config(self):
        for token, page in (("4K", 4096), ("16K", 16384), ("64K", 65536)):
            self.config = {"CONFIG_ARM64": "y", "CONFIG_MODULES": "y", "CONFIG_ARM64_" + token + "_PAGES": "y"}
            result = self.metadata()
            self.assertEqual(result["metadataDisplacement"], page - 32)
            self.assertEqual(result["credentialMode"], "module-parameter")
            self.assertFalse(result["parameterPermissionValidatedFromModule"])
            self.assertFalse(result["runtimeCredentialOrCfiQualified"])

    def test_parameter_permission_and_clear_sites_are_source_evidence_only(self):
        source = (Path(__file__).parents[1] / "bridge.c").read_text(encoding="utf-8")
        self.assertIn("static char credential[49];", source)
        self.assertIn("module_param_string(credential, credential, 49, 0);", source)
        self.assertIn("error = msu_boot_sdk_native_start(&layout, credential);\n    memzero_explicit(credential, sizeof credential);", source)
        start = source.split("static int __init msu_init_bridge_start(void)", 1)[1]
        clear = start.split("clear:\n", 1)[1].split("return error;", 1)[0]
        self.assertIn("memzero_explicit(credential, sizeof credential);", clear)
        self.assertIn("memzero_explicit(deployment_namespace, sizeof deployment_namespace);", clear)
        self.assertNotIn("msu_init_bridge_credential", source)

    def test_parameter_metadata_requires_unique_string_type(self):
        for tags in (b"", b"parmtype=credential:charp\0", self.tags * 2):
            self.tags = tags
            with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_CREDENTIAL_PARAMETER_TYPE"):
                self.metadata()

    def test_missing_duplicate_or_cross_section_symbols_fail(self):
        for symbols, error in (
            ({"msu_sdk_call_prefix": []}, "METADATA_SYMBOL:msu_sdk_call_prefix"),
            ({"msu_sdk_call_prefix": [{"st_shndx": 1, "st_value": 0}] * 2}, "METADATA_SYMBOL:"),
            ({"msu_sdk_call_prefix": [{"st_shndx": "SHN_UNDEF", "st_value": 0}]}, "METADATA_SYMBOL:"),
            ({"msu_sdk_call_blr": [{"st_shndx": 2, "st_value": 32}]}, "METADATA_SYMBOL_SECTION")):
            with self.subTest(error=error):
                original = dict(self.symbols)
                self.symbols.update(symbols)
                with self.assertRaisesRegex(ValueError, error):
                    self.metadata()
                self.symbols = original

    def test_unaligned_out_of_section_zero_or_out_of_range_delta_fail(self):
        for call, size, error in ((34, 256, "SYMBOL_RANGE"), (256, 256, "SYMBOL_RANGE"),
                                  (4096, 4100, "METADATA_DISPLACEMENT"),
                                  (134221828, 134221832, "METADATA_DISPLACEMENT")):
            with self.subTest(call=call):
                self.symbols["msu_sdk_call_blr"][0]["st_value"] = call
                self.section["sh_size"] = size
                with self.assertRaisesRegex(ValueError, error):
                    self.metadata()

    def test_page_size_is_not_inferred_from_release(self):
        for config in ({"CONFIG_ARM64": "y", "CONFIG_MODULES": "y"},
                       {**self.config, "CONFIG_ARM64_16K_PAGES": "y"},
                       {**self.config, "CONFIG_ARM64": "n"}):
            self.config = config
            with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_PAGE_CONFIG"):
                self.metadata()


class PortableBundleChecks(unittest.TestCase):
    """All files are dictionary bytes; no fixture .ko is written to disk."""

    def setUp(self):
        self.root = (Path(__file__).parent / "memory-bundle-fixture").resolve()
        source, kernel = self.root / "source", self.root / "kernel"
        self.output = self.root / "artifact"
        self.paths = {name: source / name for name in (
            "target_boot", "kernel_image", "credential_file", "bridge", "handoff",
            "handoff_verifier", "target_identity", "target_contract", "btf")}
        self.paths.update(target_config=kernel / ".config", symvers=kernel / "Module.symvers")
        data = {name: ("memory-only " + name).encode() for name in self.paths}
        data.update(credential_file=b"A" * 48, target_config=b"CONFIG_ARM64=y\nCONFIG_MODULES=y\n",
                    target_contract=b'{"sourceReceipt":"relative/receipt.json","ready":false}\n')
        data["bridge"] = NO_DIRECT_MODULE
        data["target_identity"] = json.dumps({"release": "6.18.21-4k",
            "configSha256": package.digest(data["target_config"]),
            "rawImageReference": {"sha256": package.digest(data["kernel_image"])}}).encode()
        self.inputs = {self.paths[name]: blob for name, blob in data.items()}
        self.inputs[kernel / "include/generated/utsrelease.h"] = b'#define UTS_RELEASE "6.18.21-4k"\n'
        self.files, self.directories = dict(self.inputs), set()
        self.argv = ["package.py", "--kernel-build", str(kernel),
                     "--credential-symbol", "msu_init_bridge_credential"]
        for name, path in self.paths.items():
            if name != "btf":
                self.argv.extend(["--" + name.replace("_", "-"), str(path)])

    def run_package(self, output, btf=True, fail=None, corrupt=None, generic=False):
        def read(path):
            if path not in self.files:
                raise FileNotFoundError(str(path))
            return self.files[path]

        def mkdir(path, **kwargs):
            if path in self.directories or path in self.files:
                raise FileExistsError(str(path))
            self.directories.add(path)

        def write(path, blob):
            if path.parent not in self.directories:
                raise FileNotFoundError(str(path.parent))
            if path.name == fail:
                self.files[path] = blob[:3]
                raise OSError("injected partial write")
            self.files[path] = blob + b"!" if path.name == corrupt else blob
            return len(blob)

        def rename(path, target):
            if target in self.files:
                raise FileExistsError(str(target))
            self.files[target] = self.files.pop(path)
            return target

        argv = [self.argv[0]]
        for option, value in zip(self.argv[1::2], self.argv[2::2]):
            if not generic or option not in ("--credential-file", "--credential-symbol"):
                argv += [option, value]
        argv += ["--output", str(output)]
        if btf:
            argv += ["--btf", str(self.paths["btf"])]
        actual_spec = package.importlib.util.spec_from_file_location
        actual_module = package.importlib.util.module_from_spec
        verifier_spec, verifier = Mock(), Mock()

        def selected_spec(name, path):
            if name == "ultra_init_build":
                self.assertEqual(Path(path), self.paths["handoff_verifier"])
                return verifier_spec
            return actual_spec(name, path)

        def selected_module(spec):
            return verifier if spec is verifier_spec else actual_module(spec)

        with ExitStack() as stack:
            for method, replacement in (
                ("read_bytes", read), ("read_text", lambda p, **kw: read(p).decode()),
                ("mkdir", mkdir), ("write_bytes", write),
                ("write_text", lambda p, text, **kw: write(p, text.encode("utf-8"))),
                ("rename", rename)):
                stack.enter_context(patch.object(Path, method, replacement))
            stack.enter_context(patch.object(sys, "argv", argv))
            # Real ELF section parsing sees no session, task or runtime tables.
            # Structural qualification and the handoff verifier remain separate
            # ports: this fixture exercises main/publishing I/O, not loadability.
            stack.enter_context(patch.object(package, "inspect_module", return_value={"coldBootOrSuQualified": False}))
            stack.enter_context(patch.object(package, "module_credential",
                **({"side_effect": AssertionError("generic path read a key")} if generic else {"return_value": b"A" * 48})))
            stack.enter_context(patch.object(package, "module_parameter_metadata",
                return_value={"credentialMode": "module-parameter", "metadataDisplacement": 4064}))
            stack.enter_context(patch.object(package.importlib.util, "spec_from_file_location", side_effect=selected_spec))
            stack.enter_context(patch.object(package.importlib.util, "module_from_spec", side_effect=selected_module))
            package.main()

    def test_moved_bundle_resolves_every_flat_reference(self):
        for btf, generic in ((True, False), (False, False), (True, True), (False, True)):
            output = self.output / (str(btf) + str(generic))
            self.run_package(output, btf=btf, generic=generic)
            moved = self.root / "relocated" / (str(btf) + str(generic))
            bundled = {moved / p.relative_to(output): blob for p, blob in self.files.items()
                       if p.is_relative_to(output)}
            manifest = json.loads(bundled[moved / "manifest.json"])
            fields = {"targetBoot", "config", "moduleSymvers", "targetContract", "bridge", "handoff", "bundleSources"}
            if btf:
                fields.add("btf")
            credential_fields = {"credentialMode", "metadataDisplacement"} if generic else {"credentialSha256"}
            self.assertEqual(set(manifest), {"schemaVersion", "kernelRelease", "kernelSha256"} | credential_fields
                             | fields | {field + "Sha256" for field in fields})
            if generic:
                self.assertEqual(manifest["credentialMode"], "module-parameter")
                self.assertEqual(manifest["metadataDisplacement"], 4064)
            for field in fields:
                relative = Path(manifest[field])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                self.assertEqual(package.digest(bundled[moved / relative]), manifest[field + "Sha256"])
            self.assertEqual(bundled[moved / "target-contract.json"], self.inputs[self.paths["target_contract"]])
            self.assertEqual(bundled[moved / "target-identity.source.json"], self.inputs[self.paths["target_identity"]])
            provenance = json.loads(bundled[moved / "BUNDLE-SOURCES.json"])
            self.assertEqual(provenance["targetContractReferenceBase"], str(self.paths["target_contract"].parent))
            self.assertFalse(provenance["targetContractReferencesRebased"])
            self.assertFalse(provenance["targetContractFunctionalProofEvaluated"])
            self.assertNotIn(self.inputs[self.paths["credential_file"]], bundled.values())
            self.assertNotIn(moved / "manifest.json.tmp", bundled)

    def test_generic_packaging_does_not_read_an_installation_key(self):
        del self.files[self.paths["credential_file"]]
        self.run_package(self.output, generic=True)
        manifest = json.loads(self.files[self.output / "manifest.json"])
        self.assertNotIn("credentialSha256", manifest)
        self.assertEqual(manifest["credentialMode"], "module-parameter")
        provenance = json.loads(self.files[self.output / "BUNDLE-SOURCES.json"])
        self.assertNotIn("credential_file", provenance["inputs"])

    def test_full_config_identity_keeps_auto_conf_digest_separate(self):
        active = self.files[self.paths["target_config"]]
        full = b"# exact image configuration\n" + active
        self.files[self.paths["target_config"]] = full
        target = json.loads(self.files[self.paths["target_identity"]])
        target.update(targetConfigSha256=package.digest(full), targetConfigBytes=len(full))
        self.files[self.paths["target_identity"]] = json.dumps(target).encode()
        self.run_package(self.output)
        self.assertEqual(self.files[self.output / "target.config"], full)
        preserved = json.loads(self.files[self.output / "target-identity.source.json"])
        self.assertEqual(preserved["configSha256"], package.digest(active))
        self.assertEqual(preserved["targetConfigSha256"], package.digest(full))

    def test_explicit_full_config_identity_never_falls_back_to_legacy_hash(self):
        target = json.loads(self.files[self.paths["target_identity"]])
        target.update(targetConfigSha256="0" * 64,
                      targetConfigBytes=len(self.files[self.paths["target_config"]]))
        self.files[self.paths["target_identity"]] = json.dumps(target).encode()
        with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_IMAGE_IDENTITY"):
            self.run_package(self.output)
        self.assertNotIn(self.output / "manifest.json", self.files)

    def test_full_config_identity_requires_exact_byte_count(self):
        original = json.loads(self.files[self.paths["target_identity"]])
        length = len(self.files[self.paths["target_config"]])
        for index, size in enumerate((None, length + 1, str(length), float(length))):
            with self.subTest(bytes=size):
                output = self.output / str(index)
                target = dict(original, targetConfigSha256=original["configSha256"])
                if size is not None:
                    target["targetConfigBytes"] = size
                self.files[self.paths["target_identity"]] = json.dumps(target).encode()
                with self.assertRaisesRegex(ValueError, "ULTRA_BRIDGE_TARGET_IMAGE_IDENTITY"):
                    self.run_package(output)
                self.assertNotIn(output / "manifest.json", self.files)

    def test_missing_input_has_no_success_entry(self):
        for name in ("target_boot", "target_config", "symvers", "target_contract", "btf"):
            with self.subTest(input=name):
                path = self.paths[name]
                blob = self.files.pop(path)
                try:
                    with self.assertRaises(FileNotFoundError):
                        self.run_package(self.output)
                    self.assertNotIn(self.output, self.directories)
                    self.assertNotIn(self.output / "manifest.json", self.files)
                finally:
                    self.files[path] = blob

    def test_copy_and_manifest_failures_have_no_success_entry(self):
        for fail, corrupt in (("target-contract.json", None), ("manifest.json.tmp", None),
                              (None, "target.config")):
            with self.subTest(fail=fail, corrupt=corrupt):
                output = self.output / (fail or corrupt)
                with self.assertRaises((OSError, ValueError)):
                    self.run_package(output, fail=fail, corrupt=corrupt)
                self.assertNotIn(output / "manifest.json", self.files)
                self.assertEqual({p: self.files[p] for p in self.inputs}, self.inputs)

    def test_existing_directory_is_not_replaced(self):
        self.directories.add(self.output)
        self.files[self.output / "manifest.json"] = b"existing consumer entry"
        original = dict(self.files)
        with self.assertRaises(FileExistsError):
            self.run_package(self.output)
        self.assertEqual(self.files, original)


if __name__ == "__main__":
    unittest.main()
