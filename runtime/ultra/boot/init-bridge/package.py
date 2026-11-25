#!/usr/bin/env python3
"""Package real bridge/shim bytes into the existing UltraInitBootProducer API.

These are structural/loading-input checks, never a claim of cold-boot/SU
qualification. Uses pyelftools, already used by the current host builder.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


def ELFFile(stream):
    # Real parsing still requires pyelftools; mocked I/O fixtures need no parser.
    from elftools.elf.elffile import ELFFile as parse
    return parse(stream)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def add_python_dependency_options(parser):
    parser.add_argument("--python-dependency-root", type=Path)
    parser.add_argument("--python-dependency-manifest", type=Path)
    parser.add_argument("--python-dependency-manifest-sha256")


def python_dependency(args):
    values = (args.python_dependency_root, args.python_dependency_manifest,
              args.python_dependency_manifest_sha256)
    if not any(values):
        return None
    if not all(values):
        raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_ARGUMENTS")
    root, manifest = args.python_dependency_root.resolve(), args.python_dependency_manifest.resolve()
    raw = manifest.read_bytes()
    if digest(raw) != args.python_dependency_manifest_sha256:
        raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_MANIFEST_IDENTITY")
    declared = json.loads(raw)
    if declared.get("schema") != "maplesu-python-dependency-source/1" or declared.get("distribution") != "pyelftools":
        raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_SCHEMA")
    seen = set()
    for row in declared["files"]:
        relative = row["relativePath"]
        if relative in seen or "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_MEMBER")
        seen.add(relative)
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_MEMBER")
        actual = path.read_bytes()
        if len(actual) != row["bytes"] or digest(actual) != row["sha256"]:
            raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_SOURCE_IDENTITY:" + relative)
    if "elftools/elf/elffile.py" not in seen:
        raise ValueError("ULTRA_BRIDGE_PYTHON_DEPENDENCY_PARSER_REQUIRED")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return {"manifest": file_identity(manifest), "version": declared["version"], "files": len(seen)}


def kmi_api():
    spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).with_name("target_kmi.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_direct_api():
    spec = importlib.util.spec_from_file_location("bridge_legacy_direct", Path(__file__).with_name("legacy_direct.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compiled_native_layouts_api():
    spec = importlib.util.spec_from_file_location("bridge_compiled_native_layouts", Path(__file__).with_name("compiled_native_layouts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_module_facts_api():
    spec = importlib.util.spec_from_file_location("bridge_legacy_object_facts", Path(__file__).with_name("legacy_module_cfi_facts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_cfi_api():
    spec = importlib.util.spec_from_file_location("bridge_legacy_cfi", Path(__file__).with_name("legacy_cfi_contract.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def task_profile_api():
    spec = importlib.util.spec_from_file_location("bridge_task_profile_abi", Path(__file__).with_name("task_profile_abi.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_values(data):
    values = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r"(CONFIG_\w+)=(.*)", line)
        if match:
            name, value = match.groups()
            if name in values:
                raise ValueError("ULTRA_BRIDGE_TARGET_CONFIG_DUPLICATE:" + name)
            values[name] = value
    return values


def module_versions(elf):
    def collect(rows):
        versions = {}
        for name, crc in rows:
            if not name or name in versions:
                raise ValueError("ULTRA_BRIDGE_MODVERSIONS_FORMAT")
            versions[name] = crc
        return versions

    section = elf.get_section_by_name("__versions")
    if section:
        data = section.data()
        if len(data) % 64:
            raise ValueError("ULTRA_BRIDGE_MODVERSIONS_FORMAT")
        return collect((data[at + 8:at + 64].split(b"\0", 1)[0].decode(),
                        int.from_bytes(data[at:at + 8], "little"))
                       for at in range(0, len(data), 64))
    names = elf.get_section_by_name("__version_ext_names")
    crcs = elf.get_section_by_name("__version_ext_crcs")
    if names is not None or crcs is not None:
        if names is None or crcs is None:
            raise ValueError("ULTRA_BRIDGE_MODVERSIONS_FORMAT")
        encoded = names.data()
        if encoded and not encoded.endswith(b"\0"):
            raise ValueError("ULTRA_BRIDGE_MODVERSIONS_FORMAT")
        labels = encoded[:-1].split(b"\0") if encoded else []
        raw = crcs.data()
        if len(raw) != len(labels) * 4:
            raise ValueError("ULTRA_BRIDGE_MODVERSIONS_FORMAT")
        return collect((name.decode(), int.from_bytes(raw[at * 4:at * 4 + 4], "little"))
                       for at, name in enumerate(labels))
    return {}


def inspect_module(data, release, config, symvers, target_contract=None):
    if config.get("CONFIG_ARM64") != "y" or config.get("CONFIG_MODULES") != "y":
        raise ValueError("ULTRA_BRIDGE_TARGET_MODULE_CONFIG")
    # Presence is checked here; the normal target loader verifies signer trust.
    if config.get("CONFIG_MODULE_SIG_FORCE") == "y" and not data.endswith(b"~Module signature appended~\n"):
        raise ValueError("ULTRA_BRIDGE_TARGET_MODULE_SIGNATURE_REQUIRED")
    elf = ELFFile(io.BytesIO(data))
    if (elf.elfclass != 64 or not elf.little_endian or
            elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_AARCH64"):
        raise ValueError("ULTRA_BRIDGE_MODULE_ELF_TARGET")
    symbols = elf.get_section_by_name(".symtab")
    info = elf.get_section_by_name(".modinfo")
    if symbols is None or info is None:
        raise ValueError("ULTRA_BRIDGE_MODULE_METADATA")
    defined, imports = set(), set()
    for symbol in symbols.iter_symbols():
        if not symbol.name:
            continue
        if symbol["st_shndx"] != "SHN_UNDEF":
            defined.add(symbol.name)
        elif symbol["st_info"]["bind"] != "STB_WEAK":
            imports.add(symbol.name)
    # The selected root-loader, owner host and SU provider implementations must
    # be linked; symbol presence alone does not establish their runtime closure.
    required = {"init_module", "msu_boot_sdk_init", "msu_manager_resident_init",
                "msu_management_init", "msu_runtime_service_register",
                "msu_su_registry_create", "msu_su_read_current"}
    if required - defined:
        raise ValueError("ULTRA_BRIDGE_PROVIDERS_MISSING:" + ",".join(sorted(required - defined)))
    tags = [entry.decode() for entry in info.data().split(b"\0") if entry]
    vermagic = [tag[9:] for tag in tags if tag.startswith("vermagic=")]
    versions = module_versions(elf)
    target_magic = target_contract.get("targetVermagic") if target_contract else None
    if (len(vermagic) != 1 or
            (target_magic is None and vermagic[0].split(" ", 1)[0] != release) or
            (target_magic is not None and (not target_magic.startswith(release + " ") or
                not kmi_api().same_magic(vermagic[0], target_magic, bool(versions))))):
        raise ValueError("ULTRA_BRIDGE_VERMAGIC_TARGET")
    namespaces = {tag[10:] for tag in tags if tag.startswith("import_ns=")}
    exported = {}
    for line in symvers.decode().splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) not in (4, 5) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", fields[0]):
            raise ValueError("ULTRA_BRIDGE_SYMVERS_FORMAT")
        if fields[1] in exported:
            raise ValueError("ULTRA_BRIDGE_SYMVERS_DUPLICATE:" + fields[1])
        if fields[3] not in ("EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL"):
            raise ValueError("ULTRA_BRIDGE_SYMVERS_FORMAT")
        exported[fields[1]] = (int(fields[0], 16), fields[2], fields[3], fields[4] if len(fields) > 4 else "")
    if not exported:
        raise ValueError("ULTRA_BRIDGE_SYMVERS_EMPTY")
    cfi_mode = target_contract.get("cfiMode", "kcfi" if config.get("CONFIG_CFI_CLANG") == "y" or config.get("CONFIG_CFI") == "y" else "none") if target_contract else None
    direct = legacy_direct_api().inspect(data, cfi_mode)
    ordinary_imports = imports - set(direct["imports"])
    needed = ordinary_imports | ({"module_layout"} if config.get("CONFIG_MODVERSIONS") == "y" else set())
    if target_contract and target_contract.get("ddkExportComparison") is not None:
        kmi = kmi_api()
        kmi.ddk_export_comparison(exported,
            kmi.symvers_exports(kmi.checked(target_contract["inputs"]["buildSymvers"])), needed,
            selected_only=target_contract.get("abiEvidence", {}).get("method") == "same-kmi-module-loader")
    licenses = {tag[8:] for tag in tags if tag.startswith("license=")}
    gpl = bool(licenses & {"GPL", "GPL v2", "GPL and additional rights", "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL"})
    if config.get("CONFIG_MODULE_SIG_PROTECT") == "y" and target_contract is None:
        raise ValueError("ULTRA_BRIDGE_SIG_PROTECT_TARGET_REQUIRED")
    unprotected = set(target_contract.get("unprotectedSymbols", [])) if target_contract else set()
    for name in sorted(needed):
        if name not in exported:
            raise ValueError("ULTRA_BRIDGE_IMPORT_NOT_EXPORTED:" + name)
        crc, provider, export_class, namespace = exported[name]
        if provider != "vmlinux":
            raise ValueError("ULTRA_BRIDGE_EXTERNAL_MODULE_DEPENDENCY:" + name + ":" + provider)
        if namespace and namespace not in namespaces:
            raise ValueError("ULTRA_BRIDGE_IMPORT_NAMESPACE:" + name + ":" + namespace)
        if export_class == "EXPORT_SYMBOL_GPL" and not gpl:
            raise ValueError("ULTRA_BRIDGE_IMPORT_GPL:" + name)
        if config.get("CONFIG_MODVERSIONS") == "y" and versions.get(name) != crc:
            raise ValueError("ULTRA_BRIDGE_IMPORT_CRC:" + name)
        # A signature trailer does not establish a trusted GKI signing key.
        if config.get("CONFIG_MODULE_SIG_PROTECT") == "y" and name in imports and name not in unprotected:
            raise ValueError("ULTRA_BRIDGE_IMPORT_SIG_PROTECT:" + name)
    legacy_facts = None
    if cfi_mode == "legacy-lto-cfi":
        legacy_facts = legacy_cfi_api().verify_module(data, target_contract["legacyCfi"])
    elif target_contract is not None and config.get("CONFIG_CFI_CLANG") == "y":
        entries = symbols.get_symbol_by_name("init_module")
        if not entries or len(entries) != 1 or not isinstance(entries[0]["st_shndx"], int):
            raise ValueError("ULTRA_BRIDGE_INIT_CFI_SYMBOL")
        entry = entries[0]
        section = elf.get_section(entry["st_shndx"])
        offset = entry["st_value"]
        if (section["sh_type"] == "SHT_NOBITS" or not section["sh_flags"] & 4 or
                offset < 4 or offset > section["sh_size"] - 4 or
                int.from_bytes(section.data()[offset - 4:offset], "little") != target_contract["initKcfi"]):
            raise ValueError("ULTRA_BRIDGE_INIT_CFI_TARGET")
    return {"imports": sorted(imports), "ordinaryImports": sorted(ordinary_imports),
            "legacyDirectImports": direct, "vermagic": vermagic[0],
            "providerSymbolsPresent": sorted(required), "cfiMode": cfi_mode,
            "legacyCfi": legacy_facts, "coldBootOrSuQualified": False}


def module_credential(data, name):
    elf = ELFFile(io.BytesIO(data))
    table = elf.get_section_by_name(".symtab")
    symbols = table.get_symbol_by_name(name) if table is not None else None
    if not symbols or len(symbols) != 1:
        raise ValueError("ULTRA_BRIDGE_CREDENTIAL_SYMBOL_REQUIRED:" + name)
    symbol = symbols[0]
    if not isinstance(symbol["st_shndx"], int) or symbol["st_size"] < 48:
        raise ValueError("ULTRA_BRIDGE_CREDENTIAL_SYMBOL_STORAGE")
    section = elf.get_section(symbol["st_shndx"])
    at = symbol["st_value"]
    if section["sh_type"] == "SHT_NOBITS" or at > section["sh_size"] - 48:
        raise ValueError("ULTRA_BRIDGE_CREDENTIAL_SYMBOL_STORAGE")
    return section.data()[at:at + 48]


def module_parameter_metadata(data, config):
    pages = [size for token, size in (("4K", 4096), ("16K", 16384), ("64K", 65536))
             if config.get("CONFIG_ARM64_" + token + "_PAGES") == "y"]
    if config.get("CONFIG_ARM64") != "y" or config.get("CONFIG_MODULES") != "y" or len(pages) != 1:
        raise ValueError("ULTRA_BRIDGE_TARGET_PAGE_CONFIG")
    elf = ELFFile(io.BytesIO(data))
    table = elf.get_section_by_name(".symtab")
    info = elf.get_section_by_name(".modinfo")
    if table is None or info is None:
        raise ValueError("ULTRA_BRIDGE_MODULE_METADATA")
    parameter = [tag for tag in info.data().split(b"\0") if tag.startswith(b"parmtype=credential:")]
    if parameter != [b"parmtype=credential:string"]:
        raise ValueError("ULTRA_BRIDGE_CREDENTIAL_PARAMETER_TYPE")
    symbols = []
    for name in ("msu_sdk_call_prefix", "msu_sdk_call_blr"):
        found = table.get_symbol_by_name(name)
        if not found or len(found) != 1 or not isinstance(found[0]["st_shndx"], int):
            raise ValueError("ULTRA_BRIDGE_METADATA_SYMBOL:" + name)
        symbols.append(found[0])
    prefix, blr = symbols
    if prefix["st_shndx"] != blr["st_shndx"]:
        raise ValueError("ULTRA_BRIDGE_METADATA_SYMBOL_SECTION")
    section = elf.get_section(prefix["st_shndx"])
    start, call = prefix["st_value"], blr["st_value"]
    if (section["sh_type"] == "SHT_NOBITS" or not section["sh_flags"] & 4 or
            start < 0 or call <= start or call + 4 > section["sh_size"] or
            start % 4 or call % 4):
        raise ValueError("ULTRA_BRIDGE_METADATA_SYMBOL_RANGE")
    displacement = pages[0] - (call - start)
    if not displacement or displacement % 4 or not -134217728 <= displacement <= 134217728:
        raise ValueError("ULTRA_BRIDGE_METADATA_DISPLACEMENT")
    return {"credentialMode": "module-parameter", "metadataDisplacement": displacement,
            "pageBytes": pages[0], "callBlrFromPrefix": call - start,
            "credentialParameterType": "string", "parameterPermissionValidatedFromModule": False,
            "parameterPermissionSource": "bridge.c:module_param_string(credential, credential, 49, 0)",
            "runtimeCredentialOrCfiQualified": False}



def file_identity(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=digest(data))


def check_identity(path, reference, label):
    actual = file_identity(path)
    if any(actual[key] != reference.get(key) for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_SESSION_INPUT_CHANGED:" + label)
    return actual


def session_symbol(elf, name, kind):
    table = elf.get_section_by_name(".symtab")
    matches = table.get_symbol_by_name(name) if table is not None else None
    if (not matches or len(matches) != 1 or matches[0]["st_info"]["type"] != kind or
            not isinstance(matches[0]["st_shndx"], int)):
        raise ValueError("ULTRA_BRIDGE_SESSION_SYMBOL:" + name)
    symbol = matches[0]
    section = elf.get_section(symbol["st_shndx"])
    at, size = symbol["st_value"] - section["sh_addr"], symbol["st_size"]
    if at < 0 or size <= 0 or at + size > section["sh_size"]:
        raise ValueError("ULTRA_BRIDGE_SESSION_SYMBOL_BOUNDS:" + name)
    return symbol, section, at, size


def verify_session_module(data, report):
    elf = ELFFile(io.BytesIO(data))
    symbol, section, at, size = session_symbol(elf, "msu_su_session_abi_words", "STT_OBJECT")
    if (report.get("schemaVersion") != 1 or report.get("symbol") != symbol.name or
            section.name != ".msu.session.abi" or report.get("section") != section.name or
            section["sh_type"] != "SHT_PROGBITS" or section["sh_flags"] & 7 != 2 or
            report.get("sectionFlags") != section["sh_flags"] or report.get("bytes") != size or
            report.get("offset") != symbol["st_value"] or size != 96 or at % 4):
        raise ValueError("ULTRA_BRIDGE_SESSION_MARKER")
    raw = section.data()[at:at + size]
    values = list(struct.unpack("<24I", raw))
    if (report.get("values") != values or values[:3] != [0x4d535553, 1, 96] or
            report.get("compiledSha256") != digest(raw)):
        raise ValueError("ULTRA_BRIDGE_SESSION_COMPILED_BYTES")
    expected = {"msu_su_session_ioctl", "msu_su_session_flush", "msu_su_session_release",
                "msu_su_session_free_rcu", "msu_su_session_resume", "msu_su_session_exit_work"}
    if values[18:20] != [0xffffffff, 0]:
        expected.add("msu_su_session_compat_ioctl")
    callbacks, policy = report.get("callbacks", {}), report.get("cfiPolicy", {})
    if (callbacks.keys() != expected or policy.get("mode") not in ("kcfi", "none", "legacy-lto-cfi") or
            not isinstance(policy.get("normalizeIntegers"), bool)):
        raise ValueError("ULTRA_BRIDGE_SESSION_CALLBACK_POLICY")
    if policy["mode"] == "legacy-lto-cfi":
        checker = legacy_cfi_api().ModuleChecker(data)
        for name in callbacks:
            checker.canonical(name)
    for name, callback in callbacks.items():
        entry, code, start, _ = session_symbol(elf, name, "STT_FUNC")
        if (callback.get("symbol") != name or callback.get("offset") != entry["st_value"] or
                not code["sh_flags"] & 4 or entry["st_value"] % 4):
            raise ValueError("ULTRA_BRIDGE_SESSION_CALLBACK_ENTRY:" + name)
        if policy["mode"] == "kcfi":
            if (start < 4 or callback.get("kcfiPrefix") != int.from_bytes(code.data()[start - 4:start], "little") or
                    callback.get("objectKcfiType") != callback.get("kcfiPrefix") or
                    callback.get("objectKcfiTypeSource") != "actual-object-entry-prefix"):
                raise ValueError("ULTRA_BRIDGE_SESSION_CALLBACK_KCFI:" + name)
        elif callback.get("kcfiPrefix") is not None or callback.get("objectKcfiType") is not None:
            raise ValueError("ULTRA_BRIDGE_SESSION_CALLBACK_UNEXPECTED_KCFI:" + name)


def session_source_proof(selection_path, build_path, module_root):
    selected = json.loads(selection_path.read_text(encoding="utf-8-sig"))
    build = json.loads(build_path.read_text(encoding="utf-8-sig"))
    if build.get("exitCode") != 0 or build.get("inputsUnchanged") is not True or build.get("nativeComponentsOnly"):
        raise ValueError("ULTRA_BRIDGE_SESSION_STRICT_BUILD_REQUIRED")
    artifacts = [item for item in build.get("artifacts", [])
                 if item.get("path") == "/module/maplesu_ultra_bridge.ko"]
    if len(artifacts) != 1:
        raise ValueError("ULTRA_BRIDGE_SESSION_STRICT_ARTIFACT_REQUIRED")
    check_identity(module_root / "maplesu_ultra_bridge.ko", artifacts[0], "strict-build-module")
    roots = "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/"
    sources = {}
    for logical in (roots + "su_exec_session.c", roots + "su_exec_session.h"):
        rows = [row for row in selected["inputs"] if row["repositoryPath"] == logical]
        if len(rows) != 1:
            raise ValueError("ULTRA_BRIDGE_SESSION_SELECTED_SOURCE:" + logical)
        row = rows[0]
        staged = Path(row["staged"])
        if staged.is_absolute() or ".." in staged.parts:
            raise ValueError("ULTRA_BRIDGE_SESSION_SELECTED_PATH")
        actual = check_identity(module_root / staged, row["selected"], logical)
        matches = [item for item in build["sources"] if item["path"] == "/module/" + staged.as_posix()]
        if len(matches) != 1 or any(matches[0][key] != actual[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_SESSION_BUILD_SOURCE:" + logical)
        sources[logical] = dict(selected=row["selected"], staged=staged.as_posix(),
                                bytes=actual["bytes"], sha256=actual["sha256"])
    if not any(item.get("sha256") == file_identity(selection_path)["sha256"] and
               item.get("path") == "/module/SOURCE-SELECTION.json" for item in build["sources"]):
        raise ValueError("ULTRA_BRIDGE_SESSION_BUILD_SELECTION")
    return sources


def verify_session_provenance(report, bridge, selection, build, obj, command):
    proof = report.get("bridgeProvenance", {})
    if (proof.get("schemaVersion") != 1 or proof.get("method") not in
            ("same-tu-object-derived-btf", "same-final-module-derived-btf") or
            proof.get("originalModuleWritten") is not False):
        raise ValueError("ULTRA_BRIDGE_SESSION_PROVENANCE")
    for name, path in (("bridge", bridge), ("sourceSelection", selection),
                       ("strictBuild", build), ("sessionObject", obj), ("sessionCommand", command)):
        check_identity(path, proof.get(name, {}), name)
    if session_source_proof(selection, build, bridge.parent) != proof.get("sources"):
        raise ValueError("ULTRA_BRIDGE_SESSION_SOURCE_PROOF")
    if proof.get("method") == "same-final-module-derived-btf":
        verify_module_debug_source(proof, bridge, build)
    verify_session_module(bridge.read_bytes(), report)


def alloc_sections(data):
    elf = ELFFile(io.BytesIO(data))
    return sorted((section.name, section["sh_type"], section["sh_flags"], section["sh_addr"],
                   section["sh_size"], None if section["sh_type"] == "SHT_NOBITS" else digest(section.data()))
                  for section in elf.iter_sections() if section["sh_flags"] & 2 and
                  section.name not in (".BTF", ".BTF.ext"))


def module_runtime_facts(data):
    """Compare strip-debug outputs without treating ELF index renumbering as a change."""
    elf = ELFFile(io.BytesIO(data))
    if (elf.elfclass != 64 or not elf.little_endian or
            elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_AARCH64"):
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_ELF")
    debug = lambda name: name.startswith((".debug", ".zdebug", ".rel.debug", ".rela.debug",
                                          ".rel.zdebug", ".rela.zdebug"))
    sections = list(elf.iter_sections())
    names = [section.name for section in sections]
    if len(set(names)) != len(names):
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_SECTION_NAMES")
    table = elf.get_section_by_name(".symtab")
    if table is None:
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_SYMBOLS")
    symbols = []
    for symbol in table.iter_symbols():
        index = symbol["st_shndx"]
        owner = names[index] if isinstance(index, int) else index
        symbols.append((symbol.name, symbol["st_info"]["bind"], symbol["st_info"]["type"],
            tuple(sorted(symbol["st_other"].items())), owner, symbol["st_value"], symbol["st_size"]))
    retained = Counter(row for row in symbols if row[2] != "STT_FILE" and not debug(row[4]))
    runtime_sections, relocations = [], []
    for section in sections:
        if section["sh_flags"] & 2 or section.name in (".BTF", ".BTF.ext"):
            runtime_sections.append((section.name, section["sh_type"], section["sh_flags"],
                section["sh_addr"], section["sh_size"], section["sh_addralign"], section["sh_entsize"],
                None if section["sh_type"] == "SHT_NOBITS" else digest(section.data())))
        if section["sh_type"] not in ("SHT_RELA", "SHT_REL") or debug(names[section["sh_info"]]):
            continue
        if elf.get_section(section["sh_link"]).name != ".symtab":
            raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_RELOCATION_SYMBOLS")
        records = Counter((row["r_offset"], row["r_info_type"], symbols[row["r_info_sym"]],
            row["r_addend"] if row.is_RELA() else None) for row in section.iter_relocations())
        relocations.append((section.name, names[section["sh_info"]], records))
    return sorted(runtime_sections), retained, sorted(relocations)


def module_debug_source(bridge, build_path):
    """Use only the successful strict build's retained pre-strip debug carrier."""
    build = json.loads(build_path.read_text(encoding="utf-8-sig"))
    if (build.get("exitCode") != 0 or build.get("inputsUnchanged") is not True or
            build.get("nativeComponentsOnly")):
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_STRICT_BUILD_REQUIRED")
    artifacts = [row for row in build.get("artifacts", []) if row.get("path") ==
                 "/module/maplesu_ultra_bridge.ko"]
    if len(artifacts) != 1:
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_STRICT_ARTIFACT_REQUIRED")
    actual = check_identity(bridge, artifacts[0], "debug-final-module")
    strip = build.get("stripDebug")
    if strip is None:
        return bridge
    check_identity(bridge, strip.get("output", {}), "debug-strip-output")
    if strip.get("status") == "SIGNED_MODULE_PRESERVED":
        check_identity(bridge, strip.get("input", {}), "debug-signed-module")
        return bridge
    reference = strip.get("unstripped", {})
    if (strip.get("exitCode") != 0 or any(reference.get(key) != strip.get("input", {}).get(key)
            for key in ("bytes", "sha256")) or not reference.get("sha256") or
            strip.get("output", {}).get("sha256") != actual["sha256"]):
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_STRIP_RECEIPT")
    raw = reference.get("path", "").replace("\\", "/")
    if ".." in raw.split("/") or Path(raw).name != "maplesu_ultra_bridge.unstripped.ko":
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_RETAINED_PATH")
    # A formal510 receipt may be copied from build-evidence/ to canonical
    # kernel/ unchanged. Resolve only that cohort-local sibling, not a search.
    candidates = [Path(raw), build_path.parent / Path(raw).name,
                  build_path.parent.parent / Path(raw).parent.name / Path(raw).name]
    source = next((path for path in candidates if path.is_file()), None)
    if source is None:
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_MISSING")
    check_identity(source, reference, "unstripped-module")
    if module_runtime_facts(source.read_bytes()) != module_runtime_facts(bridge.read_bytes()):
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_RUNTIME_CHANGED")
    return source.resolve()


def verify_module_debug_source(provenance, bridge, build_path):
    source = module_debug_source(bridge, build_path)
    reference = provenance.get("moduleDebugSource")
    if reference is not None:
        check_identity(source, reference, "module-debug-source")
    elif source != bridge:
        raise ValueError("ULTRA_BRIDGE_DEBUG_SOURCE_PROVENANCE_REQUIRED")


def session_abi_main():
    """Extract BTF only into an independent copy; preserve the actual LKM and TU."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bridge", "session-object", "session-command", "source-selection", "build-receipt",
                 "claim-builder", "pahole", "llvm-objcopy", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    add_python_dependency_options(parser)
    args = parser.parse_args(sys.argv[2:])
    dependency = python_dependency(args)
    bridge, obj, command = args.bridge.resolve(), args.session_object.resolve(), args.session_command.resolve()
    paths = dict(bridge=bridge, sessionObject=obj, sessionCommand=command,
                 sourceSelection=args.source_selection.resolve(), strictBuild=args.build_receipt.resolve(),
                 claimBuilder=args.claim_builder.resolve())
    before = {name: file_identity(path) for name, path in paths.items()}
    sources = session_source_proof(paths["sourceSelection"], paths["strictBuild"], bridge.parent)
    command_text = command.read_text(encoding="utf-8")
    selected_c = sources["runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/su_exec_session.c"]["staged"]
    selected_h = sources["runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/su_exec_session.h"]["staged"]
    if (" -c -o /module/" + obj.relative_to(bridge.parent).as_posix() + " /module/" + selected_c not in command_text or
            "/module/" + selected_h not in command_text):
        raise ValueError("ULTRA_BRIDGE_SESSION_ACTUAL_TU_COMMAND")
    raw_object = obj.read_bytes()
    native_object = raw_object.startswith(b"\x7fELF")
    source = obj if native_object else module_debug_source(bridge, paths["strictBuild"])
    if not native_object:
        paths["moduleDebugSource"] = source
        before["moduleDebugSource"] = file_identity(source)
    method = "same-tu-object-derived-btf" if native_object else "same-final-module-derived-btf"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    derived = output / "session-btf.elf"
    shutil.copyfile(source, derived)
    commands = [[str(args.llvm_objcopy.resolve()), "--decompress-debug-sections", str(derived)],
                [str(args.pahole.resolve()), "-J", str(derived)]]
    for index, argv in enumerate(commands):
        with (output / ("derive-%d.log" % index)).open("xb") as log:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise ValueError("ULTRA_BRIDGE_SESSION_DERIVED_BTF:" + str(result.returncode))
    if alloc_sections(source.read_bytes()) != alloc_sections(derived.read_bytes()):
        raise ValueError("ULTRA_BRIDGE_SESSION_DERIVED_CODE_CHANGED")
    sys.path.insert(0, str(paths["claimBuilder"].parent))
    spec = importlib.util.spec_from_file_location("bridge_session_claim_facts", paths["claimBuilder"])
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    policy = api.session_cfi_policy(command)
    with bridge.open("rb") as stream:
        facts = api.session_abi_facts(derived, ELFFile(stream), policy)
    if not native_object:
        # LTO may replace the original .o with bitcode. Keep the final-link
        # provenance explicit and require every definition's real DWARF CU.
        with derived.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                raise ValueError("ULTRA_BRIDGE_SESSION_LTO_DWARF_REQUIRED")
            needed = set(facts["callbacks"]) | {facts["symbol"]}
            found = set()
            for cu in elf.get_dwarf_info().iter_CUs():
                top = cu.get_top_DIE()
                cu_name = top.attributes.get("DW_AT_name")
                if cu_name is None or not cu_name.value.decode().replace("\\", "/").endswith("/su_exec_session.c"):
                    continue
                for die in cu.iter_DIEs():
                    name = die.attributes.get("DW_AT_name")
                    if name is not None and name.value.decode() in needed and not die.attributes.get("DW_AT_declaration"):
                        found.add(name.value.decode())
            if found != needed:
                raise ValueError("ULTRA_BRIDGE_SESSION_LTO_CU_DEFINITIONS:" + ",".join(sorted(needed - found)))
    facts["bridgeProvenance"] = dict(schemaVersion=1, method=method, originalModuleWritten=False,
        **before, sources=sources, derivedObject=file_identity(derived),
        tools={name: file_identity(path.resolve()) for name, path in
               (("pahole", args.pahole), ("llvmObjcopy", args.llvm_objcopy))}, commands=commands)
    if dependency is not None:
        facts["bridgeProvenance"]["pythonDependency"] = dependency
    verify_session_provenance(facts, bridge, paths["sourceSelection"], paths["strictBuild"], obj, command)
    for name, path in paths.items():
        check_identity(path, before[name], name)
    python_dependency(args)
    result = output / "session-abi.json"
    encoded = (json.dumps(facts, indent=2) + "\n").encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ValueError("ULTRA_BRIDGE_SESSION_ABI_SIZE_LIMIT")
    result.write_bytes(encoded)
    print(json.dumps(file_identity(result), indent=2))

def publish_bundle(output, paths, data, release, module, source_data):
    files = {"target_boot": ("targetBoot", "target-boot.img"),
             "target_config": ("config", "target.config"),
             "symvers": ("moduleSymvers", "Module.symvers"),
             "target_contract": ("targetContract", "target-contract.json"),
             "bridge": ("bridge", "bridge.ko"), "handoff": ("handoff", "ultra-init"),
             "target_identity": (None, "target-identity.source.json")}
    if "btf" in data:
        files["btf"] = ("btf", "target.btf")
    if "abiEvidence" in module:
        data["abi_evidence"] = (json.dumps(module["abiEvidence"], indent=2) + "\n").encode("utf-8")
        if not 0 < len(data["abi_evidence"]) <= 1024 * 1024:
            raise ValueError("ULTRA_BRIDGE_ABI_EVIDENCE_SIZE_LIMIT")
        files["abi_evidence"] = ("abiEvidence", "abi-evidence.json")
    if "session_abi" in data:
        files["session_abi"] = ("sessionAbi", "session-abi.json")
    if "task_profile_abi" in data:
        files["task_profile_abi"] = ("taskProfileAbi", "task-profile-abi.json")
    manifest = {"schemaVersion": 1, "kernelRelease": release,
                "kernelSha256": digest(data["kernel_image"])}
    if "targetVermagic" in module:
        manifest["targetVermagic"] = module["targetVermagic"]
    if module["credentialMode"] == "module-parameter":
        manifest.update(credentialMode="module-parameter", metadataDisplacement=module["metadataDisplacement"])
    else:
        manifest["credentialSha256"] = digest(data["credential_file"])
    if "session_abi" in data and not 0 < len(data["session_abi"]) <= 1024 * 1024:
        raise ValueError("ULTRA_BRIDGE_BUNDLE_SESSION_ABI_SIZE_LIMIT")
    if "task_profile_abi" in data and not 0 < len(data["task_profile_abi"]) <= 1024 * 1024:
        raise ValueError("ULTRA_BRIDGE_BUNDLE_TASK_PROFILE_ABI_SIZE_LIMIT")
    output.mkdir(parents=True, exist_ok=False)
    for name, (field, filename) in files.items():
        destination = output / filename
        destination.write_bytes(data[name])
        copied = destination.read_bytes()
        if copied != data[name]:
            raise ValueError("ULTRA_BRIDGE_BUNDLE_COPY_MISMATCH:" + name)
        if field:
            manifest[field] = filename
            manifest[field + "Sha256"] = digest(copied)
    # Copy proofs verbatim. Embedded relative references still describe their
    # original source directory, not files rebased into the portable bundle.
    sources = {"schemaVersion": 1, "targetContractReferenceBase": str(paths["target_contract"].parent),
               "targetContractReferencesRebased": False, "targetContractFunctionalProofEvaluated": False,
               "inputs": {name: {"path": str(path), "bytes": len(source_data[name]), "sha256": digest(source_data[name]),
                                 "bundledBytes": len(data[name]), "bundledSha256": digest(data[name]),
                                 "bundledAs": files[name][1] if name in files else None}
                          for name, path in paths.items()}}
    source_proof = (json.dumps(sources, indent=2) + "\n").encode("utf-8")
    if len(source_proof) > 1024 * 1024:
        raise ValueError("ULTRA_BRIDGE_BUNDLE_SOURCES_SIZE_LIMIT")
    (output / "BUNDLE-SOURCES.json").write_bytes(source_proof)
    manifest.update(bundleSources="BUNDLE-SOURCES.json", bundleSourcesSha256=digest(source_proof))
    (output / "MODULE-INPUT-CHECK.json").write_text(json.dumps(module, indent=2) + "\n", encoding="utf-8")
    # A short/failed manifest write is never the consumer's entry point.
    encoded = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    if len(encoded) > 16 * 1024:
        raise ValueError("ULTRA_BRIDGE_BUNDLE_MANIFEST_SIZE_LIMIT")
    pending = output / "manifest.json.tmp"
    pending.write_bytes(encoded)
    if pending.read_bytes() != encoded:
        raise ValueError("ULTRA_BRIDGE_BUNDLE_MANIFEST_MISMATCH")
    pending.rename(output / "manifest.json")


def bind_runtime_layouts(module, btf_bytes, config, kernel):
    """Bind allocatable native tables to the packaged target BTF; retain source bytes separately."""
    elf = ELFFile(io.BytesIO(module))
    sdk = elf.get_section_by_name(".msu.init_bridge.runtime_layout")
    layout = elf.get_section_by_name(".msu.runtime.layout")
    names = elf.get_section_by_name(".msu.runtime.names")
    if sdk is None and layout is None:
        return module, {"present": False, "bound": False}
    if sdk is None or layout is None or names is None or not btf_bytes:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_CLOSURE")
    api = kmi_api()
    sys.path.insert(0, str(api.ROOT / "scripts"))
    sys.path.insert(0, str(api.ROOT / "tools/specgen"))
    from policy_btf_abi import Btf
    from specgen.kallsyms import decode
    target = Btf(btf_bytes)
    data = bytearray(module)
    def words(section):
        if section["sh_type"] != "SHT_PROGBITS" or not section["sh_flags"] & 2 or section["sh_size"] % 4:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_STORAGE")
        return list(struct.unpack("<%dI" % (section["sh_size"] // 4), section.data()))
    runtime = words(layout)
    if len(runtime) < 6 or runtime[:2] != [0x4d53554c, 1] or runtime[2] != len(runtime) * 4 or runtime[4:6] != [0, 0]:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_HEADER")
    labels = names.data().rstrip(b"\0").decode("ascii").split("\0")
    if len(labels) != runtime[3] or len(runtime) != 6 + 3 * len(labels) or len(labels) != len(set(labels)):
        raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_NAMES")
    aliases = {}
    alias_section = elf.get_section_by_name(".msu.runtime.aliases")
    if alias_section is not None:
        encoded = b"vfsmount.mnt_user_ns=vfsmount.mnt_userns\0\0"
        if (alias_section["sh_type"] != "SHT_PROGBITS" or alias_section["sh_flags"] & 3 != 2 or
                alias_section.data() != encoded or "vfsmount.mnt_user_ns" not in labels):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_ALIASES")
        aliases["vfsmount.mnt_user_ns"] = "vfsmount.mnt_userns"
    alignment_section = elf.get_section_by_name(".msu.runtime.alignment")
    if alignment_section is None:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_ALIGNMENT_REQUIRED")
    alignments = words(alignment_section)
    if len(alignments) != len(labels):
        raise ValueError("ULTRA_BRIDGE_RUNTIME_ALIGNMENT_COUNT")
    for index, label in enumerate(labels):
        at = 6 + index * 3
        if runtime[at:at + 3] == [0xffffffff, 0, 0]:
            if alignments[index] != 0:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_ABSENT_ALIGNMENT:" + label)
            continue
        owner, member = aliases.get(label, label).split(".", 1)
        facts = target.named_structure_selected(owner, [member])
        field = facts["members"][member]
        alignment = alignments[index]
        if (field["bytes"] != runtime[at + 1] or field["offset"] < 0 or
                alignment <= 0 or alignment & (alignment - 1) or field["offset"] % alignment or
                field["offset"] + field["bytes"] > facts["bytes"]):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_WIDTH:" + label)
        runtime[at:at + 3] = [field["offset"], field["bytes"], facts["bytes"]]
    runtime[4] = 1
    sdk_words = words(sdk)
    if len(sdk_words) != 23 or sdk_words[:4] != [0x4d534942, 1, 92, 0] or sdk_words[4:6] != [1, 76]:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_SDK_HEADER")
    pages = [size for key, size in (("CONFIG_ARM64_4K_PAGES", 4096), ("CONFIG_ARM64_16K_PAGES", 16384),
                                   ("CONFIG_ARM64_64K_PAGES", 65536)) if config.get(key) == "y"]
    if len(pages) != 1:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_SDK_PAGE")
    sdk_words[6] = pages[0]
    for owner, members, owner_index, indices in (
        ("task_struct", ["cred"], 7, [9]),
        ("cred", ["suid", "securebits", "usage"], 8, [10, 11, 12]),
        ("kprobe", ["addr", "symbol_name", "pre_handler"], 14, [15, 16, 17])):
        facts = target.named_structure_selected(owner, members)
        sdk_words[owner_index] = facts["bytes"]
        for member, index in zip(members, indices):
            sdk_words[index] = facts["members"][member]["offset"]
        if owner == "cred":
            sdk_words[13] = facts["members"]["usage"]["bytes"]
    sdk_words[18] = target.named_structure_selected("pt_regs", ["pc"])["members"]["pc"]["offset"]
    if config.get("CONFIG_SECCOMP") == "y":
        task = target.named_structure_selected("task_struct", ["seccomp"])
        seccomp = target.named_structure_selected("seccomp", ["mode"])
        sdk_words[22] = task["members"]["seccomp"]["offset"] + seccomp["members"]["mode"]["offset"]
    else:
        sdk_words[22] = 0
    if sdk_words[11] != sdk_words[10] + 24:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_SDK_SAVED_ID_WINDOW")
    sdk_words[3] = 1
    for section, values in ((layout, runtime), (sdk, sdk_words)):
        start = section["sh_offset"]
        data[start:start + section["sh_size"]] = struct.pack("<%dI" % len(values), *values)
    profiles = elf.get_section_by_name(".msu.su-runtime.profiles")
    if profiles is None:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_REQUIRED")
    profile_words = words(profiles)
    symbols = decode(kernel)
    cfi_mode = legacy_cfi_api().mode(kernel, symbols, config)
    cfi = int(cfi_mode == "kcfi")
    if (len(profile_words) != 93 or profile_words[:6] != [0x4d535550, 1, 372, 5, 0, cfi] or
            profile_words[7] != 0):
        raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_HEADER")
    filename = target.named_structure_selected("filename", ["name"])["members"]["name"]
    if filename["bytes"] != 8 or filename["offset"] % 8:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_FILENAME")
    profile_words[6] = filename["offset"]
    symbols = decode(kernel)
    profile_names = ["do_execveat_common", "__arm64_sys_newfstatat", "__arm64_sys_faccessat",
                     "__arm64_sys_statx", "__arm64_sys_faccessat2"]
    for index, name in enumerate(profile_names):
        position = 32 + index * 68
        if profiles.data()[position:position + 40] != name.encode().ljust(40, b"\0"):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_NAME:" + name)
        values = set(symbols.all_offsets(name))
        if not values and index >= 3:
            entries = [0] * 7
        else:
            if len(values) != 1:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_SYMBOL:" + name)
            offset = values.pop()
            if offset < 4 or offset % 4 or offset + 24 > len(kernel):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_BOUNDS:" + name)
            entries = [struct.unpack_from("<I", kernel, offset - 4)[0] if index and cfi else 0,
                       *struct.unpack_from("<6I", kernel, offset)]
        at = 18 + index * 17
        if any(profile_words[at:at + 7]):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILES_UNBOUND:" + name)
        profile_words[at:at + 7] = entries
    profile_words[4] = 1
    start = profiles["sh_offset"]
    data[start:start + profiles["sh_size"]] = struct.pack("<93I", *profile_words)
    derived = bytes(data)
    return derived, {"present": True, "bound": True, "fields": labels, "fieldAliases": aliases,
                     "profiles": profile_names,
                     "targetBtfSha256": digest(btf_bytes), "sourceModuleSha256": digest(module),
                     "derivedModuleSha256": digest(derived), "runtimeOrDeviceAccepted": False}


def catalog_api():
    spec = importlib.util.spec_from_file_location("bridge_package_catalog", Path(__file__).with_name("package_catalog.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def component_kmi(release, selection=None, build=None):
    # DDK vermagic often has no Android tag. Its actual build cohort supplies
    # the asset classification, as in KernelSU's DDK build and KMI asset naming.
    candidates = []
    command = (build or {}).get("command", [])
    for index, argument in enumerate(command):
        if argument.startswith("O="):
            candidates.append(argument[2:])
        elif argument == "-C" and index + 1 < len(command):
            candidates.append(command[index + 1])
    for row in (selection or {}).get("selectedNativePrivateHeaders", []):
        candidates.append(row.get("kernelBuild", ""))
    for candidate in candidates:
        name = str(candidate).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if re.fullmatch(r"android[0-9]+-(?:5\.(?:10|15)|6\.(?:1|6|12|18))", name):
            return name
    if isinstance(release, str):
        series = re.match(r"^(5\.(?:10|15)|6\.(?:1|6|12|18))(?:\.|-)", release)
        android = re.search(r"(?:^|-)android([0-9]+)(?:-|$)", release)
        if series is not None and android is not None:
            return "android" + android[1] + "-" + series[1]
    return None


def inspect_component_module(data, release, config, cfi_mode):
    """Verify a build's inputs without claiming facts about a consumer kernel."""
    if cfi_mode not in ("none", "kcfi", "legacy-lto-cfi"):
        raise ValueError("ULTRA_COMPONENT_CFI_MODE")
    elf = ELFFile(io.BytesIO(data))
    if (elf.elfclass != 64 or not elf.little_endian or
            elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_AARCH64"):
        raise ValueError("ULTRA_COMPONENT_MODULE_ELF")
    table, info = elf.get_section_by_name(".symtab"), elf.get_section_by_name(".modinfo")
    if table is None or info is None:
        raise ValueError("ULTRA_COMPONENT_MODULE_METADATA")
    tags = [x.decode("ascii") for x in info.data().split(b"\0") if x]
    if tags.count("maplesu_runtime_facts=1") != 1:
        raise ValueError("ULTRA_COMPONENT_RUNTIME_FACTS_REQUIRED")
    for name in ("credential", "deployment_namespace"):
        if tags.count("parmtype=" + name + ":string") != 1:
            raise ValueError("ULTRA_COMPONENT_PARAMETER:" + name)
    magic = [x[9:] for x in tags if x.startswith("vermagic=")]
    if len(magic) != 1 or magic[0].split(" ", 1)[0] != release:
        raise ValueError("ULTRA_COMPONENT_BUILD_RELEASE")
    symbols = {s.name for s in table.iter_symbols()}
    actual_cfi = ("kcfi" if any(name.startswith("__kcfi_typeid_") for name in symbols) or
                  elf.get_section_by_name(".kcfi_traps") is not None else
                  "legacy-lto-cfi" if "__cfi_check" in symbols else "none")
    defined = {s.name for s in table.iter_symbols() if s["st_shndx"] != "SHN_UNDEF"}
    required = {"init_module", "msu_boot_sdk_init", "msu_manager_resident_init",
                "msu_management_init", "msu_runtime_service_register", "msu_su_registry_create",
                "msu_runtime_btf_init", "msu_runtime_accessor_init", "msu_task_profile_runtime_produce"}
    if required - defined:
        raise ValueError("ULTRA_COMPONENT_RUNTIME_PRODUCERS:" + ",".join(sorted(required - defined)))
    direct = legacy_direct_api().inspect(data, actual_cfi)
    metadata = module_parameter_metadata(data, config)
    return dict(metadata, cfiMode=actual_cfi, requestedCfiMode=cfi_mode, buildVermagic=magic[0],
                legacyDirectImports=direct, runtimeFactsAbi="maplesu-runtime-facts/1",
                targetQualified=False, deviceQualified=False)


def component_main():
    parser = argparse.ArgumentParser(description="Package a strict-built, boot-adapting KMI component")
    for name in ("kernel-build", "bridge", "handoff", "handoff-verifier",
                 "source-selection", "strict-build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--kmi", required=True)
    parser.add_argument("--cfi-mode", required=True, choices=("none", "kcfi", "legacy-lto-cfi"))
    parser.add_argument("--ksu-init", type=Path)
    add_python_dependency_options(parser)
    args = parser.parse_args(sys.argv[2:])
    python_dependency(args)
    catalog = catalog_api()
    catalog.require(re.fullmatch(r"android[0-9]+-(?:5\.(?:10|15)|6\.(?:1|6|12|18))", args.kmi),
                    "ULTRA_COMPONENT_KMI")
    paths = {name: getattr(args, name).resolve() for name in
             ("bridge", "handoff", "handoff_verifier", "source_selection", "strict_build")}
    paths.update(config=args.kernel_build.resolve() / ".config",
                 release=args.kernel_build.resolve() / "include/generated/utsrelease.h")
    if args.ksu_init:
        paths["ksu_init"] = args.ksu_init.resolve()
    data = {name: path.read_bytes() for name, path in paths.items()}
    selection = json.loads(data["source_selection"])
    catalog.require(selection.get("runtimeFactsSelected") is True and
                    selection.get("targetBinding", {}).get("kind") == "runtime-kmi-component",
                    "ULTRA_COMPONENT_RUNTIME_SOURCE_SELECTION")
    sources, dependencies = catalog.selection_sources(selection)
    catalog.check_strict_build(paths["source_selection"], paths["strict_build"],
                               {"bytes": len(data["bridge"]), "sha256": digest(data["bridge"])})
    build = json.loads(data["strict_build"])
    for name in ("config", "release"):
        expected = {"bytes": len(data[name]), "sha256": digest(data[name])}
        catalog.require(any(all(row.get(k) == expected[k] for k in expected)
                            for row in build.get("sources", [])), "ULTRA_COMPONENT_BUILD_INPUT:" + name)
    releases = re.findall(r'^#define UTS_RELEASE "([^"\r\n]+)"$', data["release"].decode(), re.M)
    catalog.require(len(releases) == 1, "ULTRA_COMPONENT_BUILD_RELEASE")
    release = releases[0]
    build_kmi = component_kmi(release, selection, build)
    module = inspect_component_module(data["bridge"], release, config_values(data["config"]), args.cfi_mode)
    verifier_spec = importlib.util.spec_from_file_location("component_handoff_verifier", paths["handoff_verifier"])
    verifier = importlib.util.module_from_spec(verifier_spec)
    verifier_spec.loader.exec_module(verifier)
    verifier.verify_static_executable(data["handoff"])
    if "ksu_init" in data:
        verifier.verify_static_executable(data["ksu_init"])
    generation = digest(catalog.encoded({"moduleSources": sources, "handoffSha256": digest(data["handoff"])}))
    manifest = dict(schemaVersion=2, kind="kmi-component", kmi=build_kmi or args.kmi, architecture="arm64",
                    pageSize=module["pageBytes"], cfiMode=module["cfiMode"], kernelRelease=release,
                    credentialMode="module-parameter", metadataDisplacement=module["metadataDisplacement"],
                    runtimeFactsAbi="maplesu-runtime-facts/1", sourceGenerationSha256=generation)
    files = {"bridge": "bridge.ko", "handoff": "ultra-init"}
    if "ksu_init" in data:
        files["ksu_init"] = "ksuinit"
    source_proof = dict(schemaVersion=2, kind="kmi-component", sourceGenerationSha256=generation,
        buildClassification=dict(kmi=build_kmi, requestedKmi=args.kmi, requestedCfiMode=args.cfi_mode,
                                 cfiMode=module["cfiMode"], buildCommand=build.get("command")),
        generationInputs={"moduleSources": sources, "handoffSha256": digest(data["handoff"])},
        sourceSelection=file_identity(paths["source_selection"]), strictBuild=file_identity(paths["strict_build"]),
        inputs={name: dict(file_identity(path), bundledAs=files.get(name),
                          bundledBytes=len(data[name]), bundledSha256=digest(data[name])) for name, path in paths.items()})
    data["bundleSources"] = catalog.encoded(source_proof)
    files["bundleSources"] = "BUNDLE-SOURCES.json"
    output = args.output.resolve()
    catalog.require(not output.exists(), "ULTRA_COMPONENT_OUTPUT_NOT_FRESH")
    for path, expected in dependencies:
        catalog.same(catalog.identity(path), expected, "ULTRA_COMPONENT_SELECTED_SOURCE_CHANGED")
    for name, path in paths.items():
        catalog.require(path.read_bytes() == data[name], "ULTRA_COMPONENT_INPUT_CHANGED:" + name)
    output.mkdir(parents=True)
    for name, filename in files.items():
        field = "ksuInit" if name == "ksu_init" else name
        (output / filename).write_bytes(data[name])
        catalog.require((output / filename).read_bytes() == data[name], "ULTRA_COMPONENT_COPY_CHANGED:" + name)
        manifest[field] = filename
        manifest[field + "Sha256"] = digest(data[name])
    (output / "MODULE-INPUT-CHECK.json").write_bytes(catalog.encoded(module))
    # Publish the entry point only after all selected source and output identities agree.
    pending = output / "manifest.json.tmp"
    pending.write_bytes(catalog.encoded(manifest))
    catalog.require(pending.read_bytes() == catalog.encoded(manifest), "ULTRA_COMPONENT_MANIFEST_COPY")
    pending.rename(output / "manifest.json")
    print(json.dumps(manifest, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("target-boot", "kernel-image", "kernel-build", "target-config",
                 "symvers", "bridge", "handoff", "handoff-verifier", "target-identity", "target-contract", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--credential-file", type=Path)
    parser.add_argument("--credential-symbol")
    parser.add_argument("--btf", type=Path)
    parser.add_argument("--session-abi", type=Path)
    parser.add_argument("--task-profile-abi", type=Path)
    add_python_dependency_options(parser)
    args = parser.parse_args()
    dependency = python_dependency(args)
    if bool(args.credential_file) != bool(args.credential_symbol):
        parser.error("ULTRA_BRIDGE_LEGACY_CREDENTIAL_PAIR_REQUIRED")
    paths = {name: getattr(args, name).resolve() for name in
             ("target_boot", "kernel_image", "target_config", "symvers",
              "bridge", "handoff", "handoff_verifier", "target_identity", "target_contract")}
    if args.credential_file:
        paths["credential_file"] = args.credential_file.resolve()
    data = {name: path.read_bytes() for name, path in paths.items()}
    if args.session_abi:
        paths["session_abi"] = args.session_abi.resolve()
        data["session_abi"] = paths["session_abi"].read_bytes()
    if args.task_profile_abi:
        paths["task_profile_abi"] = args.task_profile_abi.resolve()
        data["task_profile_abi"] = paths["task_profile_abi"].read_bytes()
    original_data = dict(data)
    if args.btf:
        paths["btf"] = args.btf.resolve()
        data["btf"] = paths["btf"].read_bytes()
        original_data["btf"] = data["btf"]
    if "credential_file" in data and not re.fullmatch(rb"[A-Za-z0-9]{48}", data["credential_file"]):
        raise ValueError("ULTRA_BRIDGE_CREDENTIAL_SHAPE")
    kdir = args.kernel_build.resolve()
    contract = json.loads(data["target_contract"])
    if not isinstance(contract, dict) or not contract:
        raise ValueError("ULTRA_BRIDGE_TARGET_CONTRACT_REQUIRED")
    kmi_contract = None
    if contract.get("schema") == "maplesu-init-bridge-kmi-target/1":
        kmi_contract = kmi_api().read_contract(paths["target_contract"], kdir)
        for name, reference in (("target_boot", contract["inputs"]["targetBoot"]),
                                ("kernel_image", contract["inputs"]["kernelImage"]),
                                ("target_config", contract["inputs"]["targetConfig"]),
                                ("symvers", contract["targetSymvers"])):
            if digest(data[name]) != reference["sha256"] or len(data[name]) != reference["bytes"]:
                raise ValueError("ULTRA_BRIDGE_KMI_PACKAGE_INPUT:" + name)
        target_btf = contract["inputs"].get("targetBtf")
        if target_btf is None:
            if "btf" in data or contract.get("abiEvidence", {}).get("method") != "same-kmi-module-loader":
                raise ValueError("ULTRA_BRIDGE_KMI_PACKAGE_INPUT:btf")
        elif ("btf" not in data or digest(data["btf"]) != target_btf["sha256"] or len(data["btf"]) != target_btf["bytes"]):
            raise ValueError("ULTRA_BRIDGE_KMI_PACKAGE_INPUT:btf")
    else:
        if (kdir / ".config").read_bytes() != data["target_config"]:
            raise ValueError("ULTRA_BRIDGE_TARGET_CONFIG_MISMATCH")
        if (kdir / "Module.symvers").read_bytes() != data["symvers"]:
            raise ValueError("ULTRA_BRIDGE_TARGET_SYMVERS_MISMATCH")
    release_header = (kdir / "include/generated/utsrelease.h").read_text()
    releases = re.findall(r'^#define UTS_RELEASE "([^"\r\n]+)"$', release_header, re.M)
    if len(releases) != 1:
        raise ValueError("ULTRA_BRIDGE_KERNEL_RELEASE")
    release = contract["kernelRelease"] if kmi_contract else releases[0]
    if kmi_contract and releases[0] != contract["buildRelease"]:
        raise ValueError("ULTRA_BRIDGE_KMI_BUILD_RELEASE")
    target = json.loads(data["target_identity"])
    config_digest = target.get("configSha256")
    if "targetConfigSha256" in target:
        config_digest = target["targetConfigSha256"]
        if (type(target.get("targetConfigBytes")) is not int or
                target["targetConfigBytes"] != len(data["target_config"])):
            raise ValueError("ULTRA_BRIDGE_TARGET_IMAGE_IDENTITY")
    if (target.get("release") != release or
            config_digest != digest(data["target_config"]) or
            target.get("rawImageReference", {}).get("sha256") != digest(data["kernel_image"])):
        raise ValueError("ULTRA_BRIDGE_TARGET_IMAGE_IDENTITY")
    config = config_values(data["target_config"])
    bridge_elf = ELFFile(io.BytesIO(data["bridge"]))
    has_session = bridge_elf.get_section_by_name(".msu.session.abi") is not None
    if has_session != ("session_abi" in data):
        raise ValueError("ULTRA_BRIDGE_SESSION_MANIFEST_REQUIRED")
    session = None
    if has_session:
        session = json.loads(data["session_abi"])
        bridge_root = paths["bridge"].parent
        session_object = bridge_root / "sdk/src/module/su_redirect_tu/kernel/su_exec_session.o"
        session_command = session_object.with_name(".su_exec_session.o.cmd")
        verify_session_provenance(session, paths["bridge"], bridge_root / "SOURCE-SELECTION.json",
                                  bridge_root.parent / "kernel/BUILD.json", session_object, session_command)
    task_api = task_profile_api()
    has_task_profile = task_api.module_present(data["bridge"])
    if has_task_profile != ("task_profile_abi" in data):
        raise ValueError("ULTRA_BRIDGE_TASK_PROFILE_MANIFEST_REQUIRED")
    task_profile = None
    if has_task_profile:
        if not 0 < len(data["task_profile_abi"]) <= 1024 * 1024:
            raise ValueError("ULTRA_BRIDGE_TASK_PROFILE_ABI_SIZE_LIMIT")
        task_profile = json.loads(data["task_profile_abi"])
        task_api.verify_provenance(task_profile, paths["bridge"], paths["bridge"].parent / "SOURCE-SELECTION.json",
                                  paths["bridge"].parent.parent / "kernel/BUILD.json", paths["target_config"])
    if kmi_contract and kmi_contract.get("abiEvidence", {}).get("method") == "same-kmi-module-loader":
        # Establish every ordinary import/CRC, module_layout, namespace, GPL,
        # vermagic and CFI requirement before making the compiled tables ready.
        module = inspect_module(data["bridge"], release, config, data["symvers"], kmi_contract)
        sys.path.insert(0, str(kmi_api().ROOT / "tools/specgen"))
        from specgen.kallsyms import decode
        data["bridge"], runtime_binding, module["abiEvidence"] = compiled_native_layouts_api().bind(
            data["bridge"], config, data["kernel_image"], kmi_contract, module, decode(data["kernel_image"]))
    else:
        data["bridge"], runtime_binding = bind_runtime_layouts(data["bridge"], data.get("btf"), config, data["kernel_image"])
        module = inspect_module(data["bridge"], release, config, data["symvers"], kmi_contract)
    if dependency is not None:
        module["pythonDependency"] = dependency
    module["runtimeLayoutBinding"] = runtime_binding
    if kmi_contract and kmi_contract.get("cfiMode") == "legacy-lto-cfi":
        pages = [value for key, value in (("CONFIG_ARM64_4K_PAGES", 4096),
                 ("CONFIG_ARM64_16K_PAGES", 16384), ("CONFIG_ARM64_64K_PAGES", 65536)) if config.get(key) == "y"]
        if len(pages) != 1:
            raise ValueError("ULTRA_BRIDGE_LEGACY_PAGE_CONFIG")
        object_root = paths["bridge"].parent
        commands = [object_root / ".native_legacy_cfi.o.cmd",
                    object_root / "producer/module/.maplesu_boot_sdk.o.cmd"]
        module["legacyCompilerFacts"] = legacy_module_facts_api().collect(paths["bridge"], commands, pages[0])
        module["legacyCompilerFacts"]["boundModuleSha256"] = digest(data["bridge"])
    if session is not None:
        verify_session_module(data["bridge"], session)
        if kmi_contract and kmi_contract.get("cfiMode") == "legacy-lto-cfi":
            if session["cfiPolicy"]["mode"] != "legacy-lto-cfi":
                raise ValueError("ULTRA_BRIDGE_SESSION_LEGACY_DISABLED")
            module["legacyCfi"] = legacy_cfi_api().verify_module(
                data["bridge"], kmi_contract["legacyCfi"], session["callbacks"])
        session["bundledModuleSha256"] = digest(data["bridge"])
        data["session_abi"] = (json.dumps(session, indent=2) + "\n").encode("utf-8")
        module["sessionAbi"] = dict(compiledSha256=session["compiledSha256"],
                                    cfiPolicy=session["cfiPolicy"], runtimeOrDeviceAccepted=False)
    if task_profile is not None:
        task_api.verify_module(data["bridge"], task_profile)
        task_profile["bundledModuleSha256"] = digest(data["bridge"])
        task_profile["bundledModuleBytes"] = len(data["bridge"])
        data["task_profile_abi"] = (json.dumps(task_profile, indent=2) + "\n").encode("utf-8")
        module["taskProfileAbi"] = dict(sourceSuccessorSha256=task_profile["sourceSuccessorIdentity"]["sha256"],
            cfiPolicy=task_profile["cfiPolicy"], targetQualified=False, deviceQualified=False)
    if kmi_contract:
        module["targetVermagic"] = contract["targetVermagic"]
        module["buildRelease"] = contract["buildRelease"]
    if args.credential_file:
        if module_credential(data["bridge"], args.credential_symbol) != data["credential_file"]:
            raise ValueError("ULTRA_BRIDGE_CREDENTIAL_BINDING")
        module["credentialMode"] = "legacy-embedded"
    else:
        module.update(module_parameter_metadata(data["bridge"], config))
    module["targetIdentitySha256"] = digest(data["target_identity"])
    module["targetContractFunctionalProofEvaluated"] = False
    # Use the shim owner's verifier; do not maintain a second static ELF parser.
    spec = importlib.util.spec_from_file_location("ultra_init_build", paths["handoff_verifier"])
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.verify_static_executable(data["handoff"])
    for name, path in paths.items():
        if path.read_bytes() != original_data[name]:
            raise ValueError("ULTRA_BRIDGE_INPUT_CHANGED:" + name)
    python_dependency(args)
    publish_bundle(args.output.resolve(), paths, data, release, module, original_data)


if __name__ == "__main__":
    if sys.argv[1:2] == ["session-abi"]:
        session_abi_main()
    elif sys.argv[1:2] == ["component"]:
        component_main()
    else:
        main()
