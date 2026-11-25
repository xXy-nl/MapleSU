#!/usr/bin/env python3
"""Derive one KMI module target from the actual paired boot/Image and DDK.

No compiler or device runs. The DDK keeps its real release/config/symbol CRCs.
The resulting contract binds the target, build inputs and generated profile.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PureWindowsPath
import re
import struct
import sys
import zlib

SCHEMA = "maplesu-init-bridge-kmi-target/1"
ROOT = Path(__file__).resolve().parents[4]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    data = path.read_bytes()
    row = {"path": str(path.resolve()), "bytes": len(data), "sha256": digest(data)}
    if path.resolve().is_relative_to(ROOT):
        row["repositoryPath"] = path.resolve().relative_to(ROOT).as_posix()
    return row


def reference_path(row, generated_directory=None):
    if generated_directory is not None:
        # The contract is an explicit input; its two generated siblings move
        # with it across host/container output mounts, retaining their hashes.
        recorded = row["path"]
        name = PureWindowsPath(recorded).name
        if (not name or name in (".", "..") or re.split(r"[/\\]", recorded)[-1] != name or
                name.endswith((".", " ")) or re.search(r'[<>:"/\\|?*\x00-\x1f]', name) or
                re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?", name, re.I)):
            raise ValueError("ULTRA_BRIDGE_KMI_GENERATED_REFERENCE")
        return generated_directory / name
    if "repositoryPath" not in row:
        return Path(row["path"])
    path = (ROOT / row["repositoryPath"]).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("ULTRA_BRIDGE_KMI_REFERENCE_PATH")
    return path


def checked(row, generated_directory=None):
    path = reference_path(row, generated_directory)
    actual = identity(path)
    if any(actual[key] != row[key] for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_KMI_INPUT_CHANGED:" + str(path))
    return path.read_bytes()


def legacy_direct_api():
    spec = importlib.util.spec_from_file_location("bridge_legacy_direct", Path(__file__).with_name("legacy_direct.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def direct_native_targets(data, image, table):
    facts = legacy_direct_api().inspect(data, "legacy-lto-cfi")
    rows = []
    for pair in facts.get("directImportsV2", []):
        offsets = set(table.all_offsets(pair["target"]))
        if len(offsets) != 1:
            raise ValueError("ULTRA_BRIDGE_KMI_DIRECT_TARGET:" + pair["target"])
        offset = offsets.pop()
        if offset < 0 or offset % 4 or offset > len(image) - 4:
            raise ValueError("ULTRA_BRIDGE_KMI_DIRECT_TARGET_BOUNDS:" + pair["target"])
        rows.append(dict(pair, offset=offset))
    return rows, facts.get("directMarkerSha256")


def legacy_resident_text_owner_qualification(blobs, table):
    from elftools.elf.elffile import ELFFile
    name = "__module_address"
    direct, marker = direct_native_targets(blobs["residentTextOwnerReference"], blobs["kernelImage"], table)
    selected = [row for row in direct if row["target"] == name]
    if selected:
        return {"scope": "conditional-__module_address-typed-direct-import",
                "prototypeMethod": "module-typed-forwarding-call26-target-native-body",
                "targetPrototype": None, "buildPrototype": None,
                "privateTypesStaticallyQualified": False, "targetAbiQualified": False,
                "target": selected[0], "directMarkerSha256": marker,
                "reference": {"symbol": "ref_" + name,
                              "sha256": digest(blobs["residentTextOwnerReference"])}}
    private, _ = native_private_symbols(blobs["residentTextOwnerReference"])
    if name not in private:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REFERENCE_SYMBOL")
    elf = ELFFile(io.BytesIO(blobs["residentTextOwnerReference"]))
    symbols = elf.get_section_by_name(".symtab")
    pointers = symbols.get_symbol_by_name("msu_native_" + name) or []
    if (len(pointers) != 1 or pointers[0]["st_info"]["type"] != "STT_OBJECT" or
            pointers[0]["st_size"] != 8 or not isinstance(pointers[0]["st_shndx"], int)):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REFERENCE_SYMBOL")
    body = set(table.all_offsets(name))
    canonical = set(table.all_offsets(name + ".cfi_jt"))
    if len(body) != 1 or len(canonical) != 1:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SYMBOL:" + name)
    body, canonical = body.pop(), canonical.pop()
    image = blobs["kernelImage"]
    if any(at < 0 or at % 4 or at + 4 > len(image) for at in (body, canonical)):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SYMBOL_BOUNDS:" + name)
    branch = canonical
    raw = struct.unpack_from("<I", image, branch)[0]
    if raw in (0xd503245f, 0xd50324df):
        branch += 4
        if branch + 4 > len(image):
            raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SYMBOL_BOUNDS:" + name)
        raw = struct.unpack_from("<I", image, branch)[0]
    immediate = raw & 0x03ffffff
    displacement = immediate - (1 << 26) if immediate & (1 << 25) else immediate
    target = branch + displacement * 4
    if raw & 0xfc000000 != 0x14000000 or target < 0 or target + 4 > len(image) or body not in (canonical, target):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_CANONICAL:" + name)
    return {"scope": "conditional-__module_address-typed-import",
            "prototypeMethod": "runtime-native-typed-cfi-resolver", "targetPrototype": None,
            "buildPrototype": None, "privateTypesStaticallyQualified": False, "targetAbiQualified": False,
            "target": {"symbol": name, "offset": body, "canonicalOffset": canonical},
            "reference": {"symbol": "ref_" + name,
                          "sha256": digest(blobs["residentTextOwnerReference"])}}


def resident_text_owner_qualification(blobs, table):
    if "targetBtf" not in blobs:
        return legacy_resident_text_owner_qualification(blobs, table)
    from elftools.elf.elffile import ELFFile
    sys.path.insert(0, str(ROOT / "scripts"))
    from policy_btf_abi import Btf

    name, expected = "__module_address", "f*smodule(i8:64;)"
    try:
        target = Btf(blobs["targetBtf"]).function(name)
        build = Btf(blobs["buildBtf"]).function(name)
    except ValueError as error:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_PROTOTYPE:" + name) from error
    if target != expected or build != target:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_PROTOTYPE:" + name)
    offsets = set(table.all_offsets(name))
    if len(offsets) != 1:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SYMBOL:" + name)
    offset = offsets.pop()
    image = blobs["kernelImage"]
    if offset < 4 or offset % 4 or offset + 4 > len(image):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SYMBOL_BOUNDS:" + name)
    target_kcfi = struct.unpack_from("<I", image, offset - 4)[0]
    elf = ELFFile(io.BytesIO(blobs["residentTextOwnerReference"]))
    if (elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" or
            elf["e_type"] != "ET_REL"):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REFERENCE_ELF")
    symbols = elf.get_section_by_name(".symtab")
    references = symbols.get_symbol_by_name("ref_" + name) if symbols else []
    pointers = symbols.get_symbol_by_name("msu_native_" + name) if symbols else []
    if (len(references or []) != 1 or len(pointers or []) != 1 or
            references[0]["st_info"]["type"] != "STT_FUNC" or
            pointers[0]["st_info"]["type"] != "STT_OBJECT" or pointers[0]["st_size"] != 8 or
            not isinstance(pointers[0]["st_shndx"], int) or
            not isinstance(references[0]["st_shndx"], int)):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REFERENCE_SYMBOL")
    reference = references[0]
    section = elf.get_section(reference["st_shndx"])
    at = reference["st_value"] - section["sh_addr"]
    data = section.data()
    if at < 4 or at % 4 or not reference["st_size"] or at + reference["st_size"] > len(data):
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REFERENCE_BOUNDS")
    reference_kcfi = struct.unpack_from("<I", data, at - 4)[0]
    if target_kcfi != 0x240e48bf or reference_kcfi != target_kcfi:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_KCFI:" + name)
    return {"scope": "conditional-__module_address-typed-import",
            "targetPrototype": target, "buildPrototype": build,
            "target": {"symbol": name, "offset": offset, "kcfi": target_kcfi},
            "reference": {"symbol": "ref_" + name, "offset": at, "kcfi": reference_kcfi}}


def symvers_exports(data):
    exports = {}
    for line in data.decode("ascii").splitlines():
        fields = line.split()
        if not fields:
            continue
        if (len(fields) not in (4, 5) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", fields[0]) or
                fields[3] not in ("EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL")):
            raise ValueError("ULTRA_BRIDGE_KMI_SYMVERS_FORMAT")
        if fields[1] in exports:
            raise ValueError("ULTRA_BRIDGE_KMI_DDK_EXPORT_DUPLICATE:" + fields[1])
        exports[fields[1]] = (int(fields[0], 16), fields[2], fields[3], fields[4] if len(fields) > 4 else "")
    if not exports:
        raise ValueError("ULTRA_BRIDGE_KMI_SYMVERS_EMPTY")
    return exports


def ddk_export_comparison(target_exports, build_exports, needed=(), *, selected_only=False):
    # Extra target exports are not module dependencies. Shared ABI stays strict;
    # the package consumer checks every strong ELF import against both tables.
    shared = target_exports.keys() & build_exports.keys()
    for name in sorted(set(needed) if selected_only else shared):
        if name not in target_exports or name not in build_exports:
            continue
        if target_exports[name] != build_exports[name]:
            raise ValueError("ULTRA_BRIDGE_KMI_DDK_EXPORT:" + name)
    for name in sorted(needed):
        if name not in target_exports:
            raise ValueError("ULTRA_BRIDGE_KMI_TARGET_IMPORT:" + name)
        if name not in build_exports:
            raise ValueError("ULTRA_BRIDGE_KMI_DDK_IMPORT:" + name)
    return {"policy": "selected-module-imports-only" if selected_only else "shared-export-abi-and-selected-module-imports",
            "sharedExportCount": len(shared),
            "targetOnlyExports": sorted(target_exports.keys() - build_exports.keys()),
            "buildOnlyExportCount": len(build_exports.keys() - target_exports.keys())}


def read_contract(path, kernel_build=None, *, require_resident_text_owner=False, selected_imports=None):
    contract = json.loads(path.read_bytes())
    if contract.get("schema") != SCHEMA:
        raise ValueError("ULTRA_BRIDGE_KMI_CONTRACT_SCHEMA")
    if contract.get("sameMagic", {}).get("policy") != "skip-release-word-only-with-actual-crcs":
        raise ValueError("ULTRA_BRIDGE_KMI_SAME_MAGIC_CONTRACT")
    checked(contract["generator"])
    if contract.get("cfiMode") == "legacy-lto-cfi":
        checked(contract["legacyCfiGenerator"])
        inputs = contract["inputs"]
        sys.path.insert(0, str(ROOT / "scripts"))
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from specgen.kallsyms import decode
        image = checked(inputs["kernelImage"])
        if legacy_cfi_api().target_facts(image, decode(image)) != contract["legacyCfi"]:
            raise ValueError("ULTRA_BRIDGE_LEGACY_TARGET_CONTRACT")
    if contract.get("targetRelease") is not None:
        checked(contract["releaseGenerator"])
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from specgen.kallsyms import decode
        image = checked(contract["inputs"]["kernelImage"])
        actual = module_loader_api().target_release(image, decode(image))
        if (actual != contract["targetRelease"] or actual["release"] != contract["kernelRelease"] or
                actual["vermagic"] != contract["targetVermagic"]):
            raise ValueError("ULTRA_BRIDGE_KMI_TARGET_RELEASE_CONTRACT")
    if contract.get("moduleLoader") is not None:
        checked(contract["moduleLoaderGenerator"])
        sys.path.insert(0, str(ROOT / "scripts"))
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from policy_btf_abi import Btf
        from specgen.kallsyms import decode
        inputs = contract["inputs"]
        image = checked(inputs["kernelImage"])
        symvers = checked(contract["targetSymvers"], path.resolve().parent)
        exports = []
        for line in symvers.decode("ascii").splitlines():
            fields = line.split()
            exports.append((fields[1], int(fields[0], 16), fields[3], fields[4] if len(fields) > 4 else ""))
        same, allowed, loader = module_loader_api().capture(image, decode(image),
            Btf(checked(inputs["targetBtf"])), contract["targetVermagic"], exports)
        if (same != contract["sameMagic"] or allowed != contract["unprotectedSymbols"] or
                loader != contract["moduleLoader"]):
            raise ValueError("ULTRA_BRIDGE_KMI_INLINE_LOADER_CONTRACT")
    loader_abi = contract.get("abiEvidence", {}).get("method") == "same-kmi-module-loader"
    if contract.get("targetExportsGenerator") is not None:
        checked(contract["targetExportsGenerator"])
    if loader_abi:
        if contract.get("targetExportsGenerator") is None:
            raise ValueError("ULTRA_BRIDGE_KMI_LOADER_EXPORT_GENERATOR")
        inputs = contract["inputs"]
        values = configs(checked(inputs["targetConfig"]))
        if (contract.get("cfiMode") != "legacy-lto-cfi" or values.get("CONFIG_MODVERSIONS") != "y" or
                values.get("CONFIG_MODULES") != "y" or "targetBtf" in inputs):
            raise ValueError("ULTRA_BRIDGE_KMI_LOADER_ABI_MODE")
        actual = loader_abi_evidence(inputs, contract["kernelRelease"], contract["buildRelease"],
                                     contract["targetVermagic"], checked(contract["targetSymvers"], path.resolve().parent))
        if actual != contract["abiEvidence"]:
            raise ValueError("ULTRA_BRIDGE_KMI_LOADER_ABI_CONTRACT")
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from specgen.kallsyms import decode
        image = checked(inputs["kernelImage"])
        exports = target_exports_api().capture(image, decode(image), values)
        actual_symvers = "".join("0x%08x\t%s\tvmlinux\t%s\t%s\n" % (crc, name, export_class, ns)
                                  for name, crc, export_class, ns in exports).encode("ascii")
        if actual_symvers != checked(contract["targetSymvers"], path.resolve().parent).replace(b"\r\n", b"\n"):
            raise ValueError("ULTRA_BRIDGE_KMI_LOADER_EXPORT_CONTRACT")
        actual_private = native_private_symbols(checked(inputs["nativeImportsReference"]))
        if (actual_private[0] != contract.get("privateSymbols") or
                actual_private[1] != contract.get("optionalPrivateSymbols")):
            raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_PRIVATE_CONTRACT")
        direct_rows, direct_marker = direct_native_targets(checked(inputs["nativeImportsReference"]), image, decode(image))
        if (direct_rows != contract.get("directNativeTargetsV2", []) or
                direct_marker != contract.get("directNativeMarkerSha256")):
            raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_DIRECT_CONTRACT")
        if native_import_features(checked(inputs["nativeImportsFeature"]), checked(inputs["nativeImportsCommand"])) != contract.get("nativeImportsFeatures"):
            raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_FEATURE_CONTRACT")
        if selected_imports is not None:
            for suffix in ("c", "h"):
                name = "native_imports." + suffix
                if selected_imports.get(name) != checked(inputs["nativeImports" + suffix.upper()]):
                    raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_SELECTED_IMPORTS:" + name)
    resident = contract.get("residentTextOwner")
    blobs = {}
    for name, row in contract["inputs"].items():
        data = checked(row)
        if resident is not None and name in ("targetBtf", "buildBtf", "kernelImage", "residentTextOwnerReference",
                                              "residentTextOwnerImportsC", "residentTextOwnerImportsH"):
            blobs[name] = data
    checked(contract["profile"], path.resolve().parent)
    symvers = checked(contract["targetSymvers"], path.resolve().parent)
    if contract.get("ddkExportComparison") is not None:
        comparison = ddk_export_comparison(symvers_exports(symvers),
            symvers_exports(checked(contract["inputs"]["buildSymvers"])),
            {"module_layout"} if loader_abi else (), selected_only=loader_abi)
        if comparison != contract["ddkExportComparison"]:
            raise ValueError("ULTRA_BRIDGE_KMI_DDK_EXPORT_CONTRACT")
    if kernel_build is not None:
        for name, relative in (("buildConfig", ".config"), ("buildSymvers", "Module.symvers"),
                               ("buildRelease", "include/generated/utsrelease.h")):
            if digest((kernel_build / relative).read_bytes()) != contract["inputs"][name]["sha256"]:
                raise ValueError("ULTRA_BRIDGE_KMI_BUILD_INPUT:" + name)
    if require_resident_text_owner and resident is None:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_REQUIRED")
    if resident is not None:
        required = ("kernelImage", "residentTextOwnerReference", "residentTextOwnerImportsC", "residentTextOwnerImportsH")
        if not loader_abi:
            required += ("targetBtf", "buildBtf")
        if any(name not in blobs for name in required):
            raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_INPUTS")
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from specgen.kallsyms import decode
        if resident_text_owner_qualification(blobs, decode(blobs["kernelImage"])) != resident:
            raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_CONTRACT")
        if require_resident_text_owner and selected_imports is None:
            raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SELECTED_IMPORTS_REQUIRED")
        if selected_imports is not None:
            for suffix in ("c", "h"):
                name = "native_imports." + suffix
                if selected_imports.get(name) != blobs["residentTextOwnerImports" + suffix.upper()]:
                    raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_SELECTED_IMPORTS:" + name)
    if selected_imports is not None:
        for key, name in (("nativeDirectH", "native_direct.h"),
                          ("nativeSdkImportsC", "native_sdk_imports.c"),
                          ("nativeSdkH", "native_sdk.h"),
                          ("nativeKbuild", "Kbuild"),
                          ("nativeProducerC", "producer/module/maplesu_boot_sdk.c")):
            if key in contract["inputs"] and selected_imports.get(name) != checked(contract["inputs"][key]):
                raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_SELECTED_IMPORTS:" + name)
    return contract


def native_import_features(header, command):
    values = {}
    for name in ("MSU_MANAGEMENT_RESIDENT_TEXT_OWNER", "MSU_MANAGEMENT_CRED_UCOUNTS",
                 "MSU_SU_EXEC_SESSION_NATIVE", "MSU_SU_NONROOT_NATIVE"):
        declarations = re.findall(rb"^#define\s+" + name.encode() + rb"\s+([01])\s*$", header, re.M)
        flags = re.findall(rb"(?:^|\s)-D" + name.encode() + rb"(?:=([01]))?(?=\s|$)", command)
        found = [int(value) for value in declarations] + [int(value or b"1") for value in flags]
        if len(set(found)) > 1:
            raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_FEATURE_AMBIGUOUS:" + name)
        values[name] = found[0] if found else 0
    return values


def native_private_symbols(data):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    symbols = elf.get_section_by_name(".symtab")
    if (elf.elfclass != 64 or not elf.little_endian or elf["e_type"] != "ET_REL" or
            elf["e_machine"] != "EM_AARCH64" or symbols is None):
        raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_IMPORTS_REFERENCE")
    names = {symbol.name for symbol in symbols.iter_symbols()
             if symbol["st_info"]["type"] == "STT_FUNC" and isinstance(symbol["st_shndx"], int)}
    private = {name[4:] for name in names if re.fullmatch(r"ref_[A-Za-z0-9_]+", name)}
    private.update(name[len("reference_"):] for name in names
                   if re.fullmatch(r"reference_[A-Za-z0-9_]+", name))
    direct = legacy_direct_api().inspect(data, "legacy-lto-cfi")
    direct_targets = {row["target"] for row in direct.get("directImportsV2", [])}
    for defined, native in (("msu_native_set_memory_ro", "set_memory_ro"),
                            ("msu_native_set_memory_rw", "set_memory_rw"),
                            ("msu_native_set_memory_x", "set_memory_x"),
                            ("msu_native_set_memory_nx", "set_memory_nx"),
                            ("msu_native_patch_text", "aarch64_insn_patch_text"),
                            ("msu_native_procattr_type", "proc_pid_attr_write")):
        if defined in names:
            private.add(native)
    if not private:
        raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_PRIVATE_SYMBOLS")
    # A module-owned typed wrapper with a proved direct relocation does not
    # perform a runtime native CFI lookup. Local resident registry entries also
    # belong to this module; only absent external providers remain optional.
    private -= direct_targets
    provider_names = {"maplesu_legacy_hook_provider_get", "maplesu_legacy_hook_provider_put"}
    private -= provider_names & names
    optional = {"__d_path"} | provider_names
    return sorted(private - optional), sorted(private & optional)


def target_exports_api():
    spec = importlib.util.spec_from_file_location("bridge_target_exports", Path(__file__).with_name("target_exports.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def release_series(release):
    found = re.match(r"^(\d+\.\d+)\.", release)
    if found is None:
        raise ValueError("ULTRA_BRIDGE_KMI_RELEASE_SERIES")
    return found[1]


def loader_abi_evidence(inputs, release, build_release, magic, symvers):
    target_series, build_series = release_series(release), release_series(build_release)
    if target_series != build_series:
        raise ValueError("ULTRA_BRIDGE_KMI_BUILD_SERIES")
    target_exports = symvers_exports(symvers)
    build_exports = symvers_exports(checked(inputs["buildSymvers"]))
    ddk_export_comparison(target_exports, build_exports, {"module_layout"}, selected_only=True)
    return {"schema": "maplesu-same-kmi-loader-abi/1", "method": "same-kmi-module-loader",
            "targetBootSha256": inputs["targetBoot"]["sha256"],
            "targetKernelSha256": inputs["kernelImage"]["sha256"],
            "targetConfigSha256": inputs["targetConfig"]["sha256"],
            "targetRelease": release, "targetVermagic": magic, "buildRelease": build_release,
            "targetSeries": target_series, "buildSeries": build_series,
            "buildSymversSha256": inputs["buildSymvers"]["sha256"],
            "targetSymversSha256": digest(symvers),
            "moduleLayoutCrc": "%08x" % target_exports["module_layout"][0],
            "privatePrototypeMethod": "runtime-native-typed-cfi-resolver",
            "recursiveTypeEvidence": None, "unprovenPrivateTypes": ["user_arg_ptr"],
            "privateTypesStaticallyQualified": False, "targetAbiQualified": False}


def same_magic(actual, required, has_crcs):
    # kernel/module/version.c: preserve the leading space and the entire suffix.
    if has_crcs:
        actual = actual[actual.find(" "):] if " " in actual else ""
        required = required[required.find(" "):] if " " in required else ""
    return actual == required


def module_loader_api():
    spec = importlib.util.spec_from_file_location("target_module_loader", Path(__file__).with_name("target_module_loader.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_cfi_api():
    spec = importlib.util.spec_from_file_location("target_legacy_cfi", Path(__file__).with_name("legacy_cfi_contract.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configs(data):
    result = {}
    for line in data.decode().splitlines():
        if line.startswith("CONFIG_"):
            key, value = line.split("=", 1)
            if key in result:
                raise ValueError("ULTRA_BRIDGE_KMI_CONFIG_DUPLICATE:" + key)
            result[key] = value
    return result



def profile_entry_words(image, offset, name):
    if offset < 4 or offset % 4 or offset + 24 > len(image):
        raise ValueError("ULTRA_BRIDGE_KMI_PROFILE_BOUNDS:" + name)
    words = struct.unpack_from("<6I", image, offset)
    instruction = words[0]
    # Match create_entries() and msu_su_gate_instruction(): PAC/BTI is optional,
    # while the displaced instruction must use the native gate's supported subset.
    if (instruction & 0xffffff3f == 0xd503241f or
            instruction in (0xd503233f, 0xd503237f, 0xd503231f, 0xd503235f)):
        instruction = words[1]
    if not (instruction == 0xd503201f or
            instruction & 0x1f000000 == 0x11000000 or
            instruction & 0x3e000000 == 0x28000000 or
            instruction & 0x3b000000 in (0x39000000, 0x38000000) or
            instruction & 0x7fe0ffe0 == 0x2a0003e0 or
            instruction in (0xd503233f, 0xd503237f, 0xd503231f, 0xd503235f)):
        raise ValueError("ULTRA_BRIDGE_KMI_PROFILE_ENTRY_REQUIRES_RECOVERED_INPUT:" + name)
    return words


def capture(args):
    sys.path.insert(0, str(ROOT / "scripts"))
    sys.path.insert(0, str(ROOT / "tools/specgen"))
    from policy_btf_abi import Btf
    from specgen.kallsyms import decode
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    paths = {"targetBoot": args.target_boot, "kernelImage": args.kernel_image,
             "targetConfig": args.target_config, "buildConfig": args.kernel_build / ".config",
             "buildSymvers": args.kernel_build / "Module.symvers",
             "buildRelease": args.kernel_build / "include/generated/utsrelease.h"}
    for name, argument in (("targetBtf", args.target_btf), ("buildBtf", args.build_btf)):
        if argument is not None:
            paths[name] = argument
    resident_reference = getattr(args, "resident_text_owner_reference", None)
    if resident_reference is not None:
        paths.update(residentTextOwnerReference=resident_reference,
                     residentTextOwnerImportsC=Path(__file__).with_name("native_imports.c"),
                     residentTextOwnerImportsH=Path(__file__).with_name("native_imports.h"))
    native_reference = getattr(args, "native_imports_reference", None) or (resident_reference if args.target_btf is None else None)
    if resident_reference is not None and args.target_btf is None:
        paths.update(residentTextOwnerImportsC=resident_reference.parent / "native_imports.c",
                     residentTextOwnerImportsH=resident_reference.parent / "native_imports.h")
    if native_reference is not None:
        paths.update(nativeImportsReference=native_reference,
                     nativeImportsC=native_reference.parent / "native_imports.c",
                     nativeImportsH=native_reference.parent / "native_imports.h",
                     nativeImportsFeature=native_reference.parent / "msu_resolver_build_config.h",
                     nativeImportsCommand=native_reference.parent / ".native_imports.o.cmd")
    if native_reference is not None:
        from elftools.elf.elffile import ELFFile
        reference_elf = ELFFile(io.BytesIO(native_reference.read_bytes()))
        marker = reference_elf.get_section_by_name(".msu_direct_calls")
        if marker is not None and marker.data().startswith(b"MAPLESU_DIRECT_V2\0"):
            for key, relative in (("nativeDirectH", "native_direct.h"),
                                  ("nativeSdkImportsC", "native_sdk_imports.c"),
                                  ("nativeSdkH", "native_sdk.h"),
                                  ("nativeSdkCommand", ".native_sdk_imports.o.cmd"),
                                  ("nativeKbuild", "Kbuild"),
                                  ("nativeProducerC", "producer/module/maplesu_boot_sdk.c")):
                paths[key] = native_reference.parent / relative
    before = {name: identity(path) for name, path in paths.items()}
    blobs = {name: path.read_bytes() for name, path in paths.items()}
    image, boot = blobs["kernelImage"], blobs["targetBoot"]
    if len(image) < 64 or image[56:60] != b"ARMd" or boot[:8] != b"ANDROID!":
        raise ValueError("ULTRA_BRIDGE_KMI_TARGET_IMAGE")
    version, kernel_bytes = struct.unpack_from("<I", boot, 40)[0], struct.unpack_from("<I", boot, 8)[0]
    if version not in (3, 4) or kernel_bytes <= 0 or boot[4096:4096 + kernel_bytes] != image:
        raise ValueError("ULTRA_BRIDGE_KMI_PAIRED_BOOT_IMAGE:raw-v3-v4-kernel-required")
    table = decode(image)
    resident = resident_text_owner_qualification(blobs, table) if resident_reference is not None else None

    def unique(name):
        values = set(table.all_offsets(name))
        if len(values) != 1:
            raise ValueError("ULTRA_BRIDGE_KMI_SYMBOL:" + name)
        return values.pop()

    def cstring(offset):
        if not 0 <= offset < len(image):
            raise ValueError("ULTRA_BRIDGE_KMI_STRING_BOUNDS")
        return image[offset:image.index(0, offset)].decode("ascii")

    has_btf = "targetBtf" in blobs
    if has_btf:
        start, stop = unique("__start_BTF"), unique("__stop_BTF")
        if image[start:stop] != blobs["targetBtf"] or "buildBtf" not in blobs:
            raise ValueError("ULTRA_BRIDGE_KMI_BTF_IMAGE")
    elif set(table.all_offsets("__start_BTF")) or set(table.all_offsets("__stop_BTF")):
        raise ValueError("ULTRA_BRIDGE_KMI_BTF_INPUT_REQUIRED")
    start = image.index(b"IKCFG_ST") + 8
    stop = image.index(b"IKCFG_ED", start)
    if zlib.decompress(image[start:stop], 31) != blobs["targetConfig"]:
        raise ValueError("ULTRA_BRIDGE_KMI_CONFIG_IMAGE")
    target_config, build_config = configs(blobs["targetConfig"]), configs(blobs["buildConfig"])
    abi_options = ("ARM64", "ARM64_4K_PAGES", "ARM64_16K_PAGES", "ARM64_64K_PAGES", "ARM64_VA_BITS",
                   "COMPAT", "MODULES", "MODVERSIONS", "MODULE_UNLOAD", "SMP", "PREEMPT_BUILD",
                   "PREEMPT", "PREEMPT_DYNAMIC", "CFI", "CFI_CLANG", "CFI_ICALL_NORMALIZE_INTEGERS",
                   "LTO_NONE", "LTO_CLANG_FULL", "LTO_CLANG_THIN", "SHADOW_CALL_STACK", "RANDSTRUCT_NONE")
    for name in abi_options:
        key = "CONFIG_" + name
        if target_config.get(key, "n") != build_config.get(key, "n"):
            raise ValueError("ULTRA_BRIDGE_KMI_CONFIG_ABI:" + key)
    if target_config.get("CONFIG_MODVERSIONS") != "y":
        raise ValueError("ULTRA_BRIDGE_KMI_MODVERSIONS_REQUIRED")
    cfi_mode = legacy_cfi_api().mode(image, table, target_config)
    legacy = legacy_cfi_api().target_facts(image, table) if cfi_mode == "legacy-lto-cfi" else None
    target_release = module_loader_api().target_release(image, table)
    release = target_release["release"]
    build_release = re.fullmatch(rb'#define UTS_RELEASE "([^"\r\n]+)"\s*', blobs["buildRelease"])
    if build_release is None:
        raise ValueError("ULTRA_BRIDGE_KMI_BUILD_RELEASE")
    build_release = build_release[1].decode()
    kmi = re.search(r"(\d+\.\d+)\.[^-]+-(android\d+)-(\d+)", release)
    if kmi is None and has_btf:
        raise ValueError("ULTRA_BRIDGE_KMI_RELEASE_IDENTITY")
    if not has_btf and (cfi_mode != "legacy-lto-cfi" or native_reference is None or release_series(release) != release_series(build_release)):
        raise ValueError("ULTRA_BRIDGE_KMI_NO_BTF_BUILD_SERIES")
    # Both values come from actual named kernel objects, not an unrelated format string.
    magic = target_release["vermagic"]
    target, build = (Btf(blobs["targetBtf"]), Btf(blobs["buildBtf"])) if has_btf else (None, None)
    structures = {
        "task_struct": ["cred", "real_cred", "seccomp", "comm", "pid", "tgid", "mm", "fs", "nsproxy", "flags", "task_works", "start_time", "start_boottime"],
        "cred": ["usage", "uid", "gid", "suid", "sgid", "euid", "egid", "fsuid", "fsgid", "securebits", "cap_effective", "group_info", "user", "ucounts", "security", "user_ns"],
        "kprobe": ["addr", "symbol_name", "pre_handler"], "pt_regs": ["pc", "regs"],
        "file": ["f_path", "f_inode", "f_op", "f_cred"], "fs_struct": ["users", "lock", "seq", "umask", "in_exec", "root", "pwd"],
        "nsproxy": ["count", "mnt_ns"], "mount": ["mnt", "mnt_parent", "mnt_mountpoint", "mnt_ns"],
        "filename": ["name"], "user_arg_ptr": ["is_compat", "ptr"],
        "module": ["name", "init", "exit", "arch"]}
    layouts = {}
    for name, members in structures.items() if has_btf else ():
        left, right = target.named_structure_selected(name, members), build.named_structure_selected(name, members)
        # The selected dereferences and complete object size form this contract;
        # unrelated fields of task_struct are not claimed as an ABI closure.
        left, right = ({"bytes": row["bytes"], "members": row["members"]} for row in (left, right))
        if left != right:
            raise ValueError("ULTRA_BRIDGE_KMI_LAYOUT:" + name)
        layouts[name] = {"bytes": left["bytes"], "members": left["members"]}
    functions = ("kallsyms_lookup_name", "set_memory_ro", "set_memory_rw", "set_memory_x", "set_memory_nx",
                 "aarch64_insn_patch_text", "copy_from_user_nofault", "copy_to_user_nofault", "copy_from_kernel_nofault",
                 "copy_to_kernel_nofault", "filp_open", "file_open_root", "find_task_by_pid_ns", "get_task_exe_file",
                 "get_mm_exe_file", "free_nsproxy", "task_work_add", "path_mount", "path_umount", "our_mnt",
                 "fsnotify_get_mark", "fsnotify_get_group", "fsnotify_destroy_group", "fsnotify_wait_marks_destroyed",
                 "vfs_write", "alloc_uid", "set_cred_ucounts", "core_kernel_text", "sync_icache_aliases",
                 "seccomp_filter_release", "proc_pid_attr_write", "vmalloc", "__vmalloc_node_range", "vmalloc_user",
                 "prepare_creds", "commit_creds", "get_task_cred", "__put_cred", "__arm64_sys_execve")
    prototypes = {}
    for name in functions if has_btf else ():
        left, right = target.function(name), build.function(name)
        if left != right:
            raise ValueError("ULTRA_BRIDGE_KMI_PROTOTYPE:" + name)
        prototypes[name] = left
    exports = target_exports_api().capture(image, table, target_config)
    export_comparison = ddk_export_comparison(
        {name: (crc, "vmlinux", export_class, ns) for name, crc, export_class, ns in exports},
        symvers_exports(blobs["buildSymvers"]), {"module_layout"} if not has_btf else (),
        selected_only=not has_btf)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    def until_ret(name, maximum=256):
        at = unique(name)
        result = []
        for instruction in decoder.disasm(image[at:at + maximum], at):
            result.append(instruction)
            if instruction.mnemonic == "ret":
                return result
        raise ValueError("ULTRA_BRIDGE_KMI_FUNCTION_BOUND:" + name)

    def literal_address(instructions, register):
        for index, insn in enumerate(instructions[:-1]):
            following = instructions[index + 1]
            if (insn.mnemonic == "adrp" and insn.op_str.startswith(register + ", #") and
                    following.mnemonic == "add" and following.op_str.startswith(register + ", " + register + ", #")):
                return int(insn.op_str.split("#")[1], 0) + int(following.op_str.split("#")[1], 0)
        raise ValueError("ULTRA_BRIDGE_KMI_LITERAL_ADDRESS:" + register)

    module_loader = None
    if not has_btf:
        # Pinned KSU uses the actual native module loader. This records the retained
        # runtime gate, not a static proof of this Image's complete loader code.
        same_proof = {"policy": "skip-release-word-only-with-actual-crcs",
                      "implementation": "native-module-loader-runtime-required",
                      "staticLoaderCodeQualified": False, "runtimeRequired": True}
        unprotected = []
        if target_config.get("CONFIG_MODULE_SIG_PROTECT") == "y":
            instructions = until_ret("gki_is_module_unprotected_symbol")
            moves = {instruction.op_str.split(", ")[0]: int(instruction.op_str.split("#")[-1], 0)
                     for instruction in instructions if instruction.mnemonic == "mov" and
                     re.fullmatch(r"w[23], #(?:0x[0-9a-f]+|\d+)", instruction.op_str)}
            count, width = moves.get("w2", 0), moves.get("w3", 0)
            at = unique("gki_unprotected_symbols")
            if (not count or not width or at + count * width > len(image) or
                    literal_address(instructions, "x1") != at):
                raise ValueError("ULTRA_BRIDGE_KMI_SIG_PROTECT_TABLE")
            unprotected = [image[at + index * width:at + (index + 1) * width].split(b"\0", 1)[0].decode("ascii")
                           for index in range(count)]
            if not unprotected or sorted(set(unprotected)) != unprotected or any(
                    not re.fullmatch(r"[A-Za-z0-9_.$]{1,256}", label) for label in unprotected):
                raise ValueError("ULTRA_BRIDGE_KMI_SIG_PROTECT_NAMES")
    elif not set(table.all_offsets("same_magic")):
        same_proof, unprotected, module_loader = module_loader_api().capture(image, table, target, magic, exports)
    else:
        same = until_ret("same_magic")
        # This is the observed target implementation: w2 skips exactly the two
        # strcspn calls, then both paths compare the complete remaining strings.
        core = [(row.mnemonic, row.op_str) for row in same[7:23]]
        expected = [("tbz", "w2, #0, #" + hex(same[18].address)),
                    ("adrp", same[8].op_str), ("add", same[9].op_str),
                    ("mov", "x0, x20"), ("mov", "x1, x21"),
                    ("bl", "#" + hex(unique("strcspn"))), ("add", "x20, x20, x0"),
                    ("mov", "x0, x19"), ("mov", "x1, x21"),
                    ("bl", "#" + hex(unique("strcspn"))), ("add", "x19, x19, x0"),
                    ("mov", "x0, x20"), ("mov", "x1, x19"),
                    ("bl", "#" + hex(unique("strcmp"))), ("cmp", "w0, #0"), ("cset", "w0, eq")]
        if (len(same) != 28 or core != expected or cstring(literal_address(same, "x21")) != " " or
                [(row.mnemonic, row.op_str) for row in same[5:7]] != [("mov", "x19, x1"), ("mov", "x20, x0")]):
            raise ValueError("ULTRA_BRIDGE_KMI_SAME_MAGIC_IMPLEMENTATION")
        same_proof = {"policy": "skip-release-word-only-with-actual-crcs", "offset": unique("same_magic"),
                      "bytes": b"".join(row.bytes for row in same).hex()}
        start = unique("gki_is_module_unprotected_symbol")
        instructions = until_ret("gki_is_module_unprotected_symbol")
        moves = {instruction.op_str.split(", ")[0]: int(instruction.op_str.split("#")[-1], 0)
                 for instruction in instructions if instruction.mnemonic == "mov" and
                 re.fullmatch(r"w[23], #(?:0x[0-9a-f]+|\d+)", instruction.op_str)}
        count, width = moves.get("w2", 0), moves.get("w3", 0)
        start = unique("gki_unprotected_symbols")
        if (not count or not width or start + count * width > len(image) or
                literal_address(instructions, "x1") != start or
                ("bl", "#" + hex(unique("bsearch"))) not in [(row.mnemonic, row.op_str) for row in instructions]):
            raise ValueError("ULTRA_BRIDGE_KMI_SIG_PROTECT_TABLE")
        unprotected = [image[start + index * width:start + (index + 1) * width].split(b"\0", 1)[0].decode("ascii") for index in range(count)]
        if sorted(set(unprotected)) != unprotected or any(not name for name in unprotected):
            raise ValueError("ULTRA_BRIDGE_KMI_SIG_PROTECT_NAMES")
    entries = []
    for name in ("do_execveat_common", "__arm64_sys_newfstatat", "__arm64_sys_faccessat", "__arm64_sys_statx", "__arm64_sys_faccessat2"):
        if has_btf and target.function(name) != build.function(name):
            raise ValueError("ULTRA_BRIDGE_KMI_PROFILE_ABI:" + name)
        if not has_btf and name in ("__arm64_sys_statx", "__arm64_sys_faccessat2") and not set(table.all_offsets(name)):
            entries.append((name, 0, (0,) * 6))
            continue
        offset = unique(name)
        words = profile_entry_words(image, offset, name)
        entries.append((name, 0 if name == "do_execveat_common" or cfi_mode != "kcfi" else struct.unpack_from("<I", image, offset - 4)[0], words))
    start = unique("do_one_initcall")
    end = min(offset for offset, _, _ in table.rows if offset > start)
    init_types = set()
    for offset in range(start + 4, end - 24, 4):
        lo, hi, compare, branch, trap, call = struct.unpack_from("<6I", image, offset)
        # x19 is the original initcall argument. Trace callbacks in this same
        # function have other signatures and call through x8.
        if (struct.unpack_from("<I", image, offset - 4)[0] == 0xb85fc270 and
                lo & 0xffe0001f == 0x72800011 and hi & 0xffe0001f == 0x72a00011 and
                compare == 0x6b11021f and branch == 0x54000040 and
                trap & 0xffe0001f == 0xd4200000 and call == 0xd63f0260):
            init_types.add(((lo >> 5) & 65535) | ((hi >> 5) & 65535) << 16)
    if cfi_mode == "kcfi" and len(init_types) != 1:
        raise ValueError("ULTRA_BRIDGE_KMI_INIT_CFI")
    profile = '''// Generated target Image entries; native DDK layout evidence is recorded separately.
#ifndef MSU_SU_RUNTIME_TARGET_PROFILE_H
#define MSU_SU_RUNTIME_TARGET_PROFILE_H
#include <asm/compat.h>
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union { const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};
typedef int (*msu_su_exec_source_fn)(int, struct filename *, struct user_arg_ptr, struct user_arg_ptr, int);
'''
    for name, member in (("filename", "name"), ("pt_regs", "regs"), ("user_arg_ptr", "ptr")) if has_btf else ():
        layout = layouts[name]
        profile += '_Static_assert(sizeof(struct %s) == %d && offsetof(struct %s, %s) == %d && sizeof(((struct %s *)0)->%s) == %d, "target BTF ABI");\n' % (name, layout["bytes"], name, member, layout["members"][member]["offset"], name, member, layout["members"][member]["bytes"])
    profile += "static const struct msu_su_target_profile msu_su_target_profiles[] = {\n"
    for name, kcfi, words in entries:
        profile += '    { "%s", %dU, { %s } },\n' % (name, kcfi, ", ".join("0x%08xU" % word for word in words))
    profile += "};\n#endif\n"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profile_path, symvers_path = output / "manager_su_runtime_target_profile.h", output / "Module.symvers"
    profile_path.write_text(profile, encoding="utf-8")
    symvers_path.write_text("".join("0x%08x\t%s\tvmlinux\t%s\t%s\n" % (crc, name, export_class, ns) for name, crc, export_class, ns in exports), encoding="utf-8")
    if before != {name: identity(path) for name, path in paths.items()}:
        raise ValueError("ULTRA_BRIDGE_KMI_INPUT_CHANGED")
    contract = {"schema": SCHEMA, "inputs": before, "generator": identity(Path(__file__)),
                "sameMagic": same_proof, "kernelProfile": kmi[2] + "-" + kmi[1] if kmi else args.kernel_build.name,
                "kernelRelease": release, "buildRelease": build_release, "targetVermagic": magic,
                "profile": identity(profile_path), "targetSymvers": identity(symvers_path),
                "layouts": layouts, "prototypes": prototypes, "cfiMode": cfi_mode,
                "initKcfi": init_types.pop() if cfi_mode == "kcfi" else None,
                "legacyCfi": legacy, "legacyCfiGenerator": identity(Path(__file__).with_name("legacy_cfi_contract.py")),
                "unprotectedSymbols": unprotected, "targetExportCount": len(exports),
                "ddkExportComparison": export_comparison,
                "targetBootSemantics": "Exact paired boot argument; no OEM-original or fresh-device claim. Existing owned hooks require prior exact recovery.",
                "targetQualified": False, "deviceOperations": 0}
    contract["targetExportsGenerator"] = identity(Path(__file__).with_name("target_exports.py"))
    if not has_btf:
        contract["abiEvidence"] = loader_abi_evidence(before, release, build_release, magic, symvers_path.read_bytes())
        direct_rows, direct_marker = direct_native_targets(blobs["nativeImportsReference"], image, table)
        if direct_rows:
            contract["directNativeTargetsV2"] = direct_rows
            contract["directNativeMarkerSha256"] = direct_marker
        contract["privateSymbols"], contract["optionalPrivateSymbols"] = native_private_symbols(blobs["nativeImportsReference"])
        contract["nativeImportsFeatures"] = native_import_features(blobs["nativeImportsFeature"], blobs["nativeImportsCommand"])
    contract["targetRelease"] = target_release
    contract["releaseGenerator"] = identity(Path(__file__).with_name("target_module_loader.py"))
    if module_loader is not None:
        contract["moduleLoader"] = module_loader
        contract["moduleLoaderGenerator"] = identity(Path(__file__).with_name("target_module_loader.py"))
    if resident is not None:
        contract["residentTextOwner"] = resident
    (output / "target-contract.json").write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    target_identity = {"release": release, "configSha256": digest(blobs["targetConfig"]),
                       "rawImageReference": before["kernelImage"], "targetBootReference": before["targetBoot"]}
    (output / "target-identity.json").write_text(json.dumps(target_identity, indent=2) + "\n", encoding="utf-8")
    print(str(output / "target-contract.json"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("target-boot", "kernel-image", "target-config", "kernel-build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--native-imports-reference", type=Path)
    parser.add_argument("--target-btf", type=Path)
    parser.add_argument("--build-btf", type=Path)
    parser.add_argument("--resident-text-owner-reference", type=Path,
                        help="Target-compiled native_imports.o with the conditional typed reference; no resident activation")
    capture(parser.parse_args())
