"""Retain checked same-series DDK tables without claiming target BTF evidence."""
import hashlib
import io
import re
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bind(module, config, kernel, contract, module_check, symbols):
    evidence = contract.get("abiEvidence", {})
    if (evidence.get("schema") != "maplesu-same-kmi-loader-abi/1" or
            evidence.get("method") != "same-kmi-module-loader" or
            evidence.get("targetSeries") != evidence.get("buildSeries") or
            evidence.get("targetKernelSha256") != digest(kernel) or
            evidence.get("targetAbiQualified") is not False or
            evidence.get("privateTypesStaticallyQualified") is not False or
            module_check.get("cfiMode") != "legacy-lto-cfi" or
            not isinstance(module_check.get("ordinaryImports"), list)):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_ABI_CONTRACT")
    elf = ELFFile(io.BytesIO(module))
    if elf.elfclass != 64 or not elf.little_endian or elf["e_type"] != "ET_REL" or elf["e_machine"] != "EM_AARCH64":
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_ELF")
    sections = {}
    for index, section in enumerate(elf.iter_sections()):
        if section.name.startswith((".msu.runtime.", ".msu.init_bridge.runtime_layout", ".msu.su-runtime.")):
            if section.name in sections:
                raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_DUPLICATE:" + section.name)
            sections[section.name] = (index, section)

    def section(name, writable=False):
        if name not in sections:
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_REQUIRED:" + name)
        _, row = sections[name]
        if (row["sh_type"] != "SHT_PROGBITS" or row["sh_flags"] != (3 if writable else 2) or
                row["sh_offset"] < 64 or row["sh_offset"] > len(module) or
                row["sh_size"] > len(module) - row["sh_offset"]):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_STORAGE:" + name)
        return row

    def words(name, writable=False):
        row = section(name, writable)
        if row["sh_size"] % 4:
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_WORDS:" + name)
        return list(struct.unpack("<%dI" % (row["sh_size"] // 4), row.data()))

    layout_name, sdk_name, profile_name = ".msu.runtime.layout", ".msu.init_bridge.runtime_layout", ".msu.su-runtime.profiles"
    runtime, sdk, profiles = words(layout_name, True), words(sdk_name, True), words(profile_name, True)
    if (len(runtime) < 6 or runtime[:2] != [0x4d53554c, 1] or runtime[2] != len(runtime) * 4 or
            runtime[4:6] != [0, 0]):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_HEADER")
    encoded_names = section(".msu.runtime.names").data()
    if not encoded_names.endswith(b"\0\0"):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_NAMES")
    labels = encoded_names[:-2].decode("ascii").split("\0")
    if (len(labels) != runtime[3] or len(runtime) != 6 + len(labels) * 3 or len(set(labels)) != len(labels) or
            any(re.fullmatch(r"[A-Za-z0-9_]+\.[A-Za-z0-9_.]+", label) is None for label in labels)):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_NAMES")
    aliases = {}
    if ".msu.runtime.aliases" in sections:
        if (section(".msu.runtime.aliases").data() != b"vfsmount.mnt_user_ns=vfsmount.mnt_userns\0\0" or
                "vfsmount.mnt_user_ns" not in labels):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_ALIASES")
        aliases["vfsmount.mnt_user_ns"] = "vfsmount.mnt_userns"
    alignment = words(".msu.runtime.alignment")
    if len(alignment) != len(labels):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_ALIGNMENT_COUNT")
    owners, fields = {}, {}
    for index, label in enumerate(labels):
        offset, width, extent = runtime[6 + index * 3:9 + index * 3]
        natural = alignment[index]
        if [offset, width, extent] == [0xffffffff, 0, 0]:
            if natural != 0:
                raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_ABSENT_ALIGNMENT:" + label)
            continue
        if (not width or not extent or not natural or natural & (natural - 1) or
                offset % natural or offset > extent or width > extent - offset):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_EXTENT:" + label)
        owner = label.split(".", 1)[0]
        if owner in owners and owners[owner] != extent:
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_OWNER:" + owner)
        owners[owner] = extent
        fields[label] = (offset, width, extent)
    if len(sdk) != 23 or sdk[:6] != [0x4d534942, 1, 92, 0, 1, 76]:
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SDK_HEADER")
    pages = [value for key, value in (("CONFIG_ARM64_4K_PAGES", 4096), ("CONFIG_ARM64_16K_PAGES", 16384),
                                     ("CONFIG_ARM64_64K_PAGES", 65536)) if config.get(key) == "y"]
    if len(pages) != 1 or sdk[6] != pages[0]:
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SDK_PAGE")

    def extent(offset, width, limit):
        return offset <= limit and width <= limit - offset

    # Same conditions as the actual producer's msu_boot_sdk_layout_valid.
    if (not 0 < sdk[7] <= 1 << 20 or not 0 < sdk[8] <= 1 << 16 or
            sdk[9] % 8 or not extent(sdk[9], 8, sdk[7]) or sdk[10] % 4 or sdk[11] != sdk[10] + 24 or
            not extent(sdk[10], 28, sdk[8]) or sdk[13] not in (4, 8) or sdk[12] % sdk[13] or
            not extent(sdk[12], sdk[13], sdk[8]) or
            not (sdk[12] + sdk[13] <= sdk[10] or sdk[12] >= sdk[10] + 28) or
            not 0 < sdk[14] <= 512 or len(set(sdk[15:18])) != 3 or
            any(at % 8 or not extent(at, 8, sdk[14]) for at in sdk[15:18]) or
            not 31 * 8 <= sdk[18] < 512 or sdk[18] % 8 or sdk[19] > 15 or sdk[19] & 10 == 10 or
            sdk[20] > 1 or sdk[21] != 1 or not extent(sdk[22], 4, sdk[7]) or not 0 < sdk[22] <= 32767):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SDK_EXTENT")
    for label, expected in (("task_struct.cred", (sdk[9], 8, sdk[7])),
                            ("cred.suid", (sdk[10], 4, sdk[8])),
                            ("cred.securebits", (sdk[11], 4, sdk[8])),
                            ("cred.usage", (sdk[12], sdk[13], sdk[8]))):
        if fields.get(label) != expected:
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SDK_RUNTIME:" + label)
    if config.get("CONFIG_SECCOMP") != "y":
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SDK_SECCOMP")
    filename = words(".msu.su-runtime.target", True)
    filename_alignment = words(".msu.su-runtime.alignment")
    exec_layout = words(".msu.su-runtime.exec-layout")
    if (len(filename) != 9 or filename[0] != 1 or filename[3] != 8 or
            len(filename_alignment) != 1 or filename_alignment[0] != 8 or filename[2] % 8 or
            not extent(filename[2], 8, filename[1]) or filename[6] != 8 or filename[5] % 8 or
            not extent(filename[5], 8, filename[4]) or filename[7:9] != [0, 0] or
            len(exec_layout) != 2 or exec_layout[0] not in (8, 16) or exec_layout[1] != 2 + exec_layout[0] // 4):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_SU_EXTENT")
    if (len(profiles) != 93 or profiles[:6] != [0x4d535550, 1, 372, 5, 0, 0] or
            profiles[6:8] != [filename[2], 0]):
        raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_PROFILE_HEADER")
    profile_names = ["do_execveat_common", "__arm64_sys_newfstatat", "__arm64_sys_faccessat",
                     "__arm64_sys_statx", "__arm64_sys_faccessat2"]
    profile_data = section(profile_name, True).data()
    for index, name in enumerate(profile_names):
        start = 32 + index * 68
        if profile_data[start:start + 40] != name.encode().ljust(40, b"\0"):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_PROFILE_NAME:" + name)
        at = 18 + index * 17
        if any(profiles[at:at + 7]):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_PROFILE_UNBOUND:" + name)
        locations = set(symbols.all_offsets(name))
        if not locations and index >= 3:
            entries = [0] * 7
        else:
            if len(locations) != 1:
                raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_PROFILE_SYMBOL:" + name)
            offset = locations.pop()
            if offset < 4 or offset % 4 or offset + 24 > len(kernel):
                raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_PROFILE_BOUNDS:" + name)
            entries = [0, *struct.unpack_from("<6I", kernel, offset)]
        profiles[at:at + 7] = entries
    protected_indices = {index for index, _ in sections.values()}
    for row in elf.iter_sections():
        if isinstance(row, RelocationSection) and row["sh_info"] in protected_indices and row.num_relocations():
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_RELOCATION")
    runtime[4], sdk[3], profiles[4] = 1, 1, 1
    data = bytearray(module)
    payloads = {}
    spans = []
    for name, values in ((layout_name, runtime), (sdk_name, sdk), (profile_name, profiles)):
        row = section(name, True)
        start, stop = row["sh_offset"], row["sh_offset"] + row["sh_size"]
        if any(start < old_stop and old_start < stop for old_start, old_stop in spans):
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_OVERLAP")
        section_headers = elf["e_shoff"], elf["e_shoff"] + elf["e_shentsize"] * elf["e_shnum"]
        if start < section_headers[1] and section_headers[0] < stop:
            raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_OVERLAP")
        for other in elf.iter_sections():
            if other.name == name or other["sh_type"] == "SHT_NOBITS" or not other["sh_size"]:
                continue
            if start < other["sh_offset"] + other["sh_size"] and other["sh_offset"] < stop:
                raise ValueError("ULTRA_BRIDGE_COMPILED_LAYOUT_OVERLAP")
        spans.append((start, stop))
        payloads[name] = struct.pack("<%dI" % len(values), *values)
        data[start:stop] = payloads[name]
    derived = bytes(data)
    compiled = {"method": "same-kmi-ddk-compiled-native-tables", "sourceModuleSha256": digest(module),
                "derivedModuleSha256": digest(derived), "runtimeTableSha256": digest(payloads[layout_name]),
                "sdkTableSha256": digest(payloads[sdk_name]), "profileTableSha256": digest(payloads[profile_name]),
                "targetKernelSha256": digest(kernel), "compilerLayoutIsTargetBtf": False}
    manifest = dict(evidence, bridgeSha256=digest(derived),
                    ordinaryImportsSha256=digest("".join(name + "\n" for name in sorted(module_check["ordinaryImports"])).encode("ascii")),
                    directImports=list(module_check["legacyDirectImports"]["imports"]), compiledNativeLayout=compiled)
    direct = module_check["legacyDirectImports"]
    if "directImportsV2" in direct:
        manifest.update(directImportsV2=direct["directImportsV2"],
                        directMarkerSha256=direct["directMarkerSha256"])
    return derived, {"present": True, "bound": True, "fields": labels, "fieldAliases": aliases,
                     "profiles": profile_names, "compiledNativeLayout": compiled,
                     "compilerLayoutIsTargetBtf": False, "runtimeOrDeviceAccepted": False}, manifest
