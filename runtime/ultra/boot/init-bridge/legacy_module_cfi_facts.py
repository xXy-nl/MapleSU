"""Collect actual legacy CFI module facts; runtime membership remains separate."""
from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def command_policy(path):
    modes, lto, cross_dso = set(), False, False
    for token in path.read_text(encoding="utf-8").splitlines()[0].split():
        if token.startswith(("-fsanitize=", "-fno-sanitize=")):
            for name in token.split("=", 1)[1].split(","):
                if name in ("cfi", "cfi-icall", "kcfi"):
                    mode = "legacy" if name != "kcfi" else "kcfi"
                    if token.startswith("-fsanitize="): modes.add(mode)
                    else: modes.discard(mode)
        elif token == "-fno-lto": lto = False
        elif token == "-flto" or token.startswith("-flto="): lto = True
        elif token == "-fsanitize-cfi-cross-dso": cross_dso = True
        elif token == "-fno-sanitize-cfi-cross-dso": cross_dso = False
    if modes != {"legacy"} or not lto or not cross_dso:
        raise ValueError("Actual module TU lacks active legacy LTO cross-DSO CFI: " + str(path))
    return {"identity": identity(path), "legacyEnabled": True, "lto": lto,
            "crossDso": cross_dso}


def collect(path, commands, page_bytes):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if (elf.elfclass != 64 or not elf.little_endian or
                elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_REL"):
            raise ValueError("Expected actual relocatable ARM64 kernel module")
        table = elf.get_section_by_name(".symtab")
        if table is None or elf.get_section_by_name(".gnu.linkonce.this_module") is None:
            raise ValueError("Actual module owner metadata is absent")

        def symbol(name, kind=None):
            rows = table.get_symbol_by_name(name) or []
            if not rows:
                rows = [row for row in table.iter_symbols() if row.name.startswith(name + ".llvm.")]
            if len(rows) != 1 or not isinstance(rows[0]["st_shndx"], int) or (
                    kind is not None and rows[0]["st_info"]["type"] != kind):
                raise ValueError("Actual module symbol missing/ambiguous: " + name)
            return rows[0]

        def location(sym):
            section = elf.get_section(sym["st_shndx"])
            offset = sym["st_value"] - section["sh_addr"]
            if offset < 0 or offset > section["sh_size"]:
                raise ValueError("Module symbol is out of its real section")
            return sym["st_shndx"], offset

        relocations = {}
        types = {}
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection): continue
            symbols = elf.get_section(section["sh_link"])
            for rel in section.iter_relocations():
                key = (section["sh_info"], rel["r_offset"])
                if key in relocations: raise ValueError("Overlapping relocations")
                relocations[key] = (rel, symbols.get_symbol(rel["r_info_sym"]))
                number = str(rel["r_info_type"])
                types[number] = types.get(number, 0) + 1

        def relocated_target(key, required):
            row = relocations.get(key)
            if row is None or row[0]["r_info_type"] != required:
                raise ValueError("Expected real pointer/branch relocation: " + str(key))
            rel, sym = row
            if not isinstance(sym["st_shndx"], int):
                raise ValueError("Canonical target is not defined in this module")
            section, offset = location(sym)
            return section, offset + rel["r_addend"]

        def pointer_member(name):
            pointer = symbol(name, "STT_OBJECT")
            if pointer["st_size"] != 8: raise ValueError("Expected real 64-bit typed pointer")
            section, at = relocated_target(location(pointer), 257)  # ABS64
            code = elf.get_section(section)
            if not code["sh_flags"] & 4: raise ValueError("Canonical pointer is not executable")
            data = code.data()
            if at < 0 or at + 4 > len(data) or at % 4:
                raise ValueError("Canonical pointer bounds/alignment")
            instruction = int.from_bytes(data[at:at + 4], "little")
            branch_at = at + (4 if instruction in (0xd503245f, 0xd50324df) else 0)
            if branch_at + 4 > len(data): raise ValueError("Truncated canonical entry")
            instruction = int.from_bytes(data[branch_at:branch_at + 4], "little")
            if instruction & 0xfc000000 != 0x14000000:
                raise ValueError("Canonical entry is not its actual ARM64 direct branch")
            if (section, branch_at) in relocations:
                body_section, body_at = relocated_target((section, branch_at), 282)  # JUMP26
            else:
                displacement = (instruction & 0x03ffffff) << 2
                if displacement & (1 << 27): displacement -= 1 << 28
                body_section, body_at = section, branch_at + displacement
            body = elf.get_section(body_section)
            if not body["sh_flags"] & 4 or body_at < 0 or body_at + 4 > body["sh_size"]:
                raise ValueError("Canonical branch escapes paired executable sections")
            return {"pointerSymbol": name, "section": code.name, "canonicalOffset": at,
                    "bodySection": body.name, "bodyOffset": body_at,
                    "membershipQualified": False}

        checker = symbol("__cfi_check", "STT_FUNC")
        if not checker["st_size"] or not elf.get_section(checker["st_shndx"])["sh_flags"] & 4:
            raise ValueError("Actual compiler checker is not executable")
        symbol("init_module", "STT_FUNC")
        symbol("__cfi_jt_init_module")
        entries = {name: symbol(name) for name in ("msu_sdk_call_prefix", "msu_sdk_call_blr",
            "msu_sdk_legacy_metadata", "msu_sdk_legacy_carrier_end")}
        if len({value["st_shndx"] for value in entries.values()}) != 1:
            raise ValueError("Legacy carrier was split across sections")
        carrier = elf.get_section(entries["msu_sdk_call_prefix"]["st_shndx"])
        start = entries["msu_sdk_call_prefix"]["st_value"]
        metadata = entries["msu_sdk_legacy_metadata"]["st_value"]
        end = entries["msu_sdk_legacy_carrier_end"]["st_value"]
        blr = entries["msu_sdk_call_blr"]["st_value"]
        if (carrier["sh_addralign"] < page_bytes or start % page_bytes or
                metadata - start != page_bytes or end <= metadata or
                (end - start) % page_bytes or not start < blr < metadata):
            raise ValueError("Actual carrier/page/metadata displacement mismatch")
        return {"schema": "maplesu-legacy-module-cfi-object-facts/1", "module": identity(path),
            "commands": [command_policy(command) for command in commands],
            "checker": {"symbol": checker.name, "section": elf.get_section(checker["st_shndx"]).name,
                        "offset": checker["st_value"], "bytes": checker["st_size"]},
            "typedPointers": [pointer_member("msu_sdk_legacy_call")],
            "carrier": {"section": carrier.name, "offset": start, "metadataOffset": metadata,
                        "bytes": end - start, "pageBytes": page_bytes,
                        "keyMetadataDisplacement": metadata - blr},
            "relocationCountsByType": types, "relocationOwner": "normal-kernel-module-loader",
            "moduleLoaded": False, "runtimeOwnerProbePassed": False,
            "canonicalMembershipPassed": False, "deviceQualified": False}


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--command", type=Path, action="append", required=True)
    parser.add_argument("--page-bytes", type=int, choices=(4096, 16384, 65536), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(collect(args.module, args.command, args.page_bytes),
                                     indent=2) + "\n", encoding="utf-8")
