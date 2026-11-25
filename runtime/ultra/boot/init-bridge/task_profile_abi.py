#!/usr/bin/env python3
"""Retain actual independent-LKM TaskProfile facts; target proof belongs to Manager."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace


def load_api(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package = load_api("task_profile_bridge_package", Path(__file__).with_name("package.py"))
FUNCTIONS = ("msu_task_profile_trace_bind", "msu_task_profile_trace_open",
    "msu_task_profile_trace_close", "msu_task_profile_trace_ready", "msu_task_profile_sys_enter",
    "msu_task_profile_marker_entry", "msu_task_profile_marker_return")
CALLBACKS = FUNCTIONS[4:]
SOURCES = {"runtime/ultra/identity/kernel/" + name for name in
    ("manager_task_state.c", "manager_task_state.h", "manager_su_runtime_target.c", "manager_su_runtime_factory.c")}
TABLES = {"msu_task_profile_trace_compiled_layout": ("traceLayout", ".msu.task_profile.trace-layout", 48, False),
    "msu_task_profile_target": ("targetBinding", ".msu.task_profile.target", 136, True),
    "msu_task_profile_marker_target": ("markerTargetBinding", ".msu.task_profile.marker-target", 112, True)}
NATIVE_PROBE_SOURCE = ('#include <linux/compiler.h>\n#include "manager_task_state.h"\n'
    '#include <linux/list.h>\n#include <linux/spinlock.h>\n'
    'const unsigned int msu_task_profile_native_type_facts[4] __used = {\n'
    '    sizeof(struct list_head), __alignof__(struct list_head), sizeof(rwlock_t), __alignof__(rwlock_t),\n};\n'
    'struct list_head *msu_task_profile_native_list_type __used;\n'
    'rwlock_t *msu_task_profile_native_rwlock_type __used;\n')


def fail(label):
    raise ValueError("ULTRA_BRIDGE_TASK_PROFILE_" + label)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def check_identity(path, reference, label):
    actual = package.file_identity(path)
    if any(actual[key] != reference.get(key) for key in ("bytes", "sha256")):
        fail("INPUT_CHANGED:" + label)
    return actual


def one(rows, predicate, label):
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        fail("MISSING_OR_AMBIGUOUS:" + label)
    return matches[0]


def source_proof(selection_path, build_path, root, successor, build_config):
    selection, build = read_json(selection_path), read_json(build_path)
    if (build.get("exitCode") != 0 or build.get("inputsUnchanged") is not True or
            build.get("nativeComponentsOnly") is True):
        fail("STRICT_BUILD_REQUIRED")
    artifact = one(build.get("artifacts", []), lambda row: row.get("path") ==
        "/module/maplesu_ultra_bridge.ko", "strict-module")
    check_identity(root / "maplesu_ultra_bridge.ko", artifact, "strict-module")
    if (successor.get("schema") != "maplesu-task-profile-source-successor/1" or
            successor.get("productionWritten") is not False or successor.get("sourceOwnerFrozen") is not True or
            len(successor.get("files", [])) != 4 or
            {row["logicalPath"] for row in successor["files"]} != SOURCES):
        fail("SOURCE_SUCCESSOR")
    sources = {}
    for logical in sorted(SOURCES):
        row = one(selection.get("inputs", []), lambda item: item.get("repositoryPath") == logical, logical)
        relative = Path(row["staged"])
        if relative.is_absolute() or ".." in relative.parts or not (root / relative).resolve().is_relative_to(root):
            fail("STAGED_PATH:" + logical)
        selected = one(successor["files"], lambda item: item["logicalPath"] == logical, "successor:" + logical)["after"]
        actual = check_identity(root / relative, row["selected"], logical)
        if any(actual[key] != selected[key] for key in ("bytes", "sha256")):
            fail("SELECTED_SUCCESSOR:" + logical)
        built = one(build.get("sources", []), lambda item: item.get("path") ==
            "/module/" + relative.as_posix(), "build-source:" + logical)
        if any(built.get(key) != actual[key] for key in ("bytes", "sha256")):
            fail("BUILD_SOURCE:" + logical)
        sources[logical] = dict(selected=row["selected"], staged=relative.as_posix(),
            bytes=actual["bytes"], sha256=actual["sha256"])
    selected_identity = package.file_identity(selection_path)
    retained = one(build.get("sources", []), lambda row: row.get("path") ==
        "/module/SOURCE-SELECTION.json", "build-selection")
    if any(retained.get(key) != selected_identity[key] for key in ("bytes", "sha256")):
        fail("BUILD_SELECTION")
    config_identity = package.file_identity(build_config)
    build_command = build.get("command", [])
    if len(build_command) < 3 or build_command[:2] != ["make", "-C"]:
        fail("ACTUAL_BUILD_DIRECTORY")
    actual_config_path = build_command[2].rstrip("/") + "/.config"
    retained_config = one(build.get("sources", []), lambda row: row.get("path") == actual_config_path, "build-config")
    if any(retained_config.get(key) != config_identity[key] for key in ("bytes", "sha256")):
        fail("BUILD_CONFIG")
    return sources


def symbol(elf, name, kind):
    table = elf.get_section_by_name(".symtab")
    matches = table.get_symbol_by_name(name) if table else []
    if (not matches or len(matches) != 1 or matches[0]["st_info"]["type"] != kind or
            not isinstance(matches[0]["st_shndx"], int) or matches[0]["st_shndx"] <= 0):
        fail("SYMBOL:" + name)
    entry = matches[0]
    section = elf.get_section(entry["st_shndx"])
    start, size = entry["st_value"] - section["sh_addr"], entry["st_size"]
    if (section["sh_type"] != "SHT_PROGBITS" or size <= 0 or start < 0 or
            start + size > section["sh_size"] or start % 4 or
            section["sh_offset"] < 64):
        fail("SYMBOL_STORAGE:" + name)
    return entry, section, start, size


def module_present(data):
    elf = package.ELFFile(io.BytesIO(data))
    table = elf.get_section_by_name(".symtab")
    return any(section.name.startswith(".msu.task_profile.") for section in elf.iter_sections()) or bool(
        table and any(table.get_symbol_by_name(name) for name in TABLES))


def table_record(elf, name):
    _, expected_section, expected_bytes, writable = TABLES[name]
    entry, section, at, size = symbol(elf, name, "STT_OBJECT")
    if (section.name != expected_section or size != expected_bytes or section["sh_size"] != size or at != 0 or
            section["sh_flags"] & 7 != (3 if writable else 2) or section["sh_addralign"] < 4 or
            sum(item.name == expected_section for item in elf.iter_sections()) != 1):
        fail("TABLE_STORAGE:" + name)
    raw = section.data()
    values = list(struct.unpack("<%dI" % (size // 4), raw))
    if writable:
        magic = 0x4d535450 if size == 136 else 0x4d53544d
        if values[:3] != [magic, 1, size] or any(values[3:]):
            fail("TABLE_MUST_BE_UNBOUND:" + name)
    elif values[0] != 1 or values[2] != 1 or values[11] != 0:
        fail("TRACE_LAYOUT_HEADER")
    return dict(symbol=name, section=section.name, sectionIndex=entry["st_shndx"],
        sectionFlags=section["sh_flags"], offset=entry["st_value"], fileOffset=section["sh_offset"] + at,
        bytes=size, writable=writable, values=values, sha256=package.digest(raw))


def function_record(elf, name, signature, policy, expected):
    entry, section, at, size = symbol(elf, name, "STT_FUNC")
    if not section["sh_flags"] & 4 or entry["st_value"] % 4:
        fail("FUNCTION_CODE:" + name)
    result = dict(symbol=name, section=section.name, sectionIndex=entry["st_shndx"],
        offset=entry["st_value"], fileOffset=section["sh_offset"] + at, bytes=size,
        signature=signature, sha256=package.digest(section.data()[at:at + size]))
    if policy["mode"] == "kcfi":
        if at < 4:
            fail("KCFI_PREFIX_BOUNDS:" + name)
        prefix = int.from_bytes(section.data()[at - 4:at], "little")
        if prefix != expected.get("typeid") or prefix != expected.get("declarationTypeid"):
            fail("KCFI_CLAIM_DECLARATION:" + name)
        result["typeid"] = prefix
    elif "typeid" in expected:
        fail("UNEXPECTED_CLAIM_KCFI:" + name)
    return result


def typed_callback(elf, btf, name, signature):
    pointer = name + "_type"
    if btf is not None:
        indexes = btf.variables.get(pointer, [])
        if (len(indexes) != 1 or btf.variable(pointer) != signature or
                btf.type_size(btf.types[indexes[0]][3]) != 8):
            fail("CALLBACK_TYPED_VAR:" + pointer)
    entry, section, at, size = symbol(elf, pointer, "STT_OBJECT")
    if size != 8 or section["sh_flags"] & 7 != 3:
        fail("CALLBACK_POINTER_BYTES:" + pointer)
    relocations = []
    for item in elf.iter_sections():
        if item["sh_type"] != "SHT_RELA" or item["sh_info"] != entry["st_shndx"]:
            continue
        symbols = elf.get_section(item["sh_link"])
        for relocation in item.iter_relocations():
            offset = relocation["r_offset"]
            if entry["st_value"] <= offset < entry["st_value"] + 8:
                target = symbols.get_symbol(relocation["r_info_sym"])
                relocations.append(dict(section=item.name, offset=offset, type=relocation["r_info_type"],
                    addend=relocation["r_addend"], symbol=target.name))
    if (len(relocations) != 1 or relocations[0]["offset"] != entry["st_value"] or
            relocations[0]["type"] != 257 or relocations[0]["addend"] != 0 or relocations[0]["symbol"] != name):
        fail("CALLBACK_ABS64_TARGET:" + pointer)
    return dict(symbol=pointer, signature=signature, section=section.name,
        offset=entry["st_value"], fileOffset=section["sh_offset"] + at, relocation=relocations[0])


def verify_module(data, report):
    if report.get("implementationOrigin") == "normal-module-legacy-cfi":
        return legacy_api().verify_module(SimpleNamespace(**globals()), data, report)
    if (report.get("schema") != "maplesu-init-bridge-task-profile-abi/1" or
            report.get("originalModuleWritten") is not False or report.get("targetQualified") is not False or
            report.get("deviceQualified") is not False or set(report.get("functions", {})) != set(FUNCTIONS) or
            set(report.get("tables", {})) != set(TABLES) or set(report.get("callbacks", {})) != set(CALLBACKS)):
        fail("REPORT_CONTRACT")
    elf = package.ELFFile(io.BytesIO(data))
    if (elf.elfclass != 64 or not elf.little_endian or elf["e_type"] != "ET_REL" or
            elf["e_machine"] != "EM_AARCH64"):
        fail("ELF_TARGET")
    policy = report.get("cfiPolicy", {})
    if policy.get("mode") not in ("kcfi", "none") or not isinstance(policy.get("normalizeIntegers"), bool):
        fail("CFI_POLICY")
    ranges = []
    for name in TABLES:
        actual = table_record(elf, name)
        if actual != report["tables"][name]:
            fail("TABLE_FACT:" + name)
        ranges.append((actual["fileOffset"], actual["fileOffset"] + actual["bytes"], name))
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        fail("TABLE_OVERLAP")
    for name in FUNCTIONS:
        expected = report["functions"][name]
        declaration = dict(typeid=expected.get("typeid"), declarationTypeid=expected.get("typeid")) if policy["mode"] == "kcfi" else {}
        actual = function_record(elf, name, expected["signature"], policy, declaration)
        if actual != {key: value for key, value in expected.items() if key not in ("objectComparison",)}:
            fail("FUNCTION_FACT:" + name)
        start = actual["fileOffset"] - (4 if policy["mode"] == "kcfi" else 0)
        end = actual["fileOffset"] + actual["bytes"]
        if any(start < right and left < end for left, right, _ in ranges):
            fail("CODE_TABLE_OVERLAP:" + name)
    for name in CALLBACKS:
        if typed_callback(elf, None, name, report["functions"][name]["signature"]) != report["callbacks"][name]:
            fail("CALLBACK_FACT:" + name)
    return True


def retained_path(reference, report, bridge):
    raw = reference.get("path", "")
    path = Path(raw)
    if path.is_file():
        return path
    automatic = {"/module": bridge.parent, "/run-evidence": bridge.parent.parent,
                 "/source": Path(__file__).resolve().parents[4]}
    declared = report.get("provenance", {}).get("pathBindings", {})
    roots = {"/build-config"} if report.get("implementationOrigin") == "normal-module-legacy-cfi" else {"/claim", "/build-config"}
    if not isinstance(declared, dict) or set(declared) != roots:
        fail("PROVENANCE_PATH_BINDINGS")
    mappings = {**{key: Path(value) for key, value in declared.items()}, **automatic}
    for prefix in sorted(mappings, key=len, reverse=True):
        if raw == prefix or raw.startswith(prefix + "/"):
            suffix = raw[len(prefix):].lstrip("/")
            if ".." in suffix.split("/") or "\\" in suffix:
                fail("PROVENANCE_PATH_COMPONENT")
            return mappings[prefix] / suffix if suffix else mappings[prefix]
    fail("PROVENANCE_PATH_UNRESOLVED:" + raw)


def verify_provenance(report, bridge, selection, build, config):
    if report.get("implementationOrigin") == "normal-module-legacy-cfi":
        return legacy_api().verify_provenance(SimpleNamespace(**globals()), report, bridge, selection, build, config)
    provenance = report.get("provenance", {})
    for name, path in (("bridge", bridge), ("sourceSelection", selection), ("strictBuild", build), ("targetConfig", config)):
        check_identity(path, provenance.get(name, {}), name)
    for name in ("taskObject", "taskCommand", "sourceSuccessor", "claimReference", "claimElf", "claimBuilder", "derivedObject",
                 "nativeProbeSource", "nativeProbeObject", "nativeProbeCommand", "derivedNativeProbe", "buildConfig"):
        reference = provenance.get(name, {})
        check_identity(retained_path(reference, report, bridge), reference, name)
    if (report.get("sourceSuccessorIdentity") != provenance["sourceSuccessor"] or
            read_json(retained_path(provenance["sourceSuccessor"], report, bridge)) != report.get("sourceSuccessor") or
            source_proof(selection, build, bridge.parent, report["sourceSuccessor"], retained_path(provenance["buildConfig"], report, bridge)) != report.get("sources")):
        fail("SOURCE_PROOF")
    reference = read_json(retained_path(provenance["claimReference"], report, bridge))
    if reference.get("claimSha256") != provenance["claimElf"]["sha256"] or report.get("claimSha256") != reference["claimSha256"]:
        fail("CLAIM_IDENTITY")
    if report.get("nativeAlignment", {}).get("independentlyMeasuredFromBridgeBuild") is not True:
        fail("NATIVE_COMPILER_ALIGNMENT_REQUIRED")
    package.verify_module_debug_source(provenance, bridge, build)
    verify_module(bridge.read_bytes(), report)


def dwarf_view(data):
    # R_AARCH64_NONE is a true no-op. Keep standard pyelftools relocation
    # handling for every other entry, and leave original ELF bytes untouched.
    from elftools.elf.elffile import ELFFile

    class DwarfELF(ELFFile):
        def iter_sections(self, *args, **kwargs):
            for section in super().iter_sections(*args, **kwargs):
                if section["sh_type"] in ("SHT_REL", "SHT_RELA"):
                    target = self.get_section(section["sh_info"])
                    if target.name.startswith(".debug_") and not target["sh_flags"] & 2:
                        original = section.iter_relocations

                        def relocated_entries(original=original):
                            for relocation in original():
                                if relocation["r_info_type"] != 0:
                                    yield relocation

                        section.iter_relocations = relocated_entries
                yield section

    view = DwarfELF(io.BytesIO(data))
    if view["e_machine"] != "EM_AARCH64" or view["e_type"] != "ET_REL":
        fail("DWARF_VIEW_TARGET")
    return view


def compile_options(command):
    line = command.read_text(encoding="utf-8").splitlines()[0]
    if " := " not in line:
        fail("ACTUAL_COMPILE_COMMAND")
    tokens = line.split(" := ", 1)[1].split()
    result, skip = [], False
    for token in tokens:
        if skip:
            skip = False
        elif token == "-o":
            skip = True
        elif not token.startswith(("-Wp,-MMD,", "-DKBUILD_BASENAME=")) and not token.endswith(".c"):
            result.append(token)
    return result


def probe_source_main():
    parser = argparse.ArgumentParser(description="Emit the same-config compiler sizeof/alignment probe.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(sys.argv[2:])
    with args.output.resolve().open("xb") as stream:
        stream.write(NATIVE_PROBE_SOURCE.encode("ascii"))
    print(json.dumps(package.file_identity(args.output.resolve()), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bridge", "task-object", "task-command", "source-selection", "build-receipt", "target-config", "build-config",
                 "claim-reference", "claim-elf", "source-successor", "claim-builder", "pahole", "llvm-objcopy", "output",
                 "native-probe-source", "native-probe-object", "native-probe-command"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--path-binding", action="append", default=[])
    package.add_python_dependency_options(parser)
    args = parser.parse_args()
    dependency = package.python_dependency(args)
    path_bindings = {}
    for item in args.path_binding:
        prefix, separator, destination = item.partition("=")
        if (not separator or not prefix.startswith("/") or prefix.endswith("/") or
                prefix in ("/source", "/module", "/run-evidence") or prefix in path_bindings or
                not destination or ".." in prefix.split("/")):
            fail("PATH_BINDING_ARGUMENT")
        path_bindings[prefix] = destination
    if set(path_bindings) != {"/claim", "/build-config"}:
        fail("ACTUAL_MOUNT_ROOT_BINDINGS_REQUIRED")
    paths = {name: getattr(args, argument).resolve() for name, argument in
        (("bridge", "bridge"), ("taskObject", "task_object"), ("taskCommand", "task_command"),
         ("sourceSelection", "source_selection"), ("strictBuild", "build_receipt"), ("targetConfig", "target_config"), ("buildConfig", "build_config"),
         ("claimReference", "claim_reference"), ("claimElf", "claim_elf"), ("sourceSuccessor", "source_successor"),
         ("claimBuilder", "claim_builder"), ("nativeProbeSource", "native_probe_source"),
         ("nativeProbeObject", "native_probe_object"), ("nativeProbeCommand", "native_probe_command"))}
    before = {name: package.file_identity(path) for name, path in paths.items()}
    bridge, obj, command = paths["bridge"], paths["taskObject"], paths["taskCommand"]
    successor = read_json(paths["sourceSuccessor"])
    sources = source_proof(paths["sourceSelection"], paths["strictBuild"], bridge.parent, successor, paths["buildConfig"])
    reference = read_json(paths["claimReference"])
    record = reference.get("taskProfileAbi", {})
    implementation = record.get("implementation", {})
    if (reference.get("claimSha256") != before["claimElf"]["sha256"] or
            implementation.get("schema") != "maplesu-task-profile-implementation/1" or
            implementation.get("present") is not True or implementation.get("metadataComplete") is not True or
            implementation.get("sourceSuccessorIdentity", {}).get("sha256") != before["sourceSuccessor"]["sha256"] or
            {key: value for key, value in implementation.get("sourceSuccessor", {}).items() if key != "identity"} != successor or
            set(implementation.get("functions", {})) != set(FUNCTIONS)):
        fail("SAME_GENERATION_CLAIM_REQUIRED")
    if any(record.get("configIdentity", {}).get(key) != before["buildConfig"][key] for key in ("bytes", "sha256")):
        fail("CLAIM_CONFIG_IDENTITY")
    sys.path.insert(0, str(paths["claimBuilder"].parent))
    api = load_api("bridge_task_profile_claim_facts", paths["claimBuilder"])
    policy = api.session_cfi_policy(command)
    config = package.config_values(paths["targetConfig"].read_bytes())
    build_config = package.config_values(paths["buildConfig"].read_bytes())
    if (policy["mode"] not in ("kcfi", "none") or
            (policy["mode"] == "kcfi") != any(config.get(name) == "y" for name in ("CONFIG_CFI", "CONFIG_CFI_CLANG")) or
            policy["normalizeIntegers"] != (config.get("CONFIG_CFI_ICALL_NORMALIZE_INTEGERS") == "y")):
        fail("ACTUAL_CFI_POLICY")
    objects = {}
    for logical, source in sources.items():
        if not logical.endswith(".c"):
            continue
        staged = Path(source["staged"])
        actual_object = bridge.parent / staged.with_suffix(".o")
        actual_command = actual_object.with_name("." + actual_object.name + ".cmd")
        text = actual_command.read_text(encoding="utf-8")
        expected = " -c -o /module/" + actual_object.relative_to(bridge.parent).as_posix() + " /module/" + staged.as_posix()
        header = "/module/" + sources["runtime/ultra/identity/kernel/manager_task_state.h"]["staged"]
        if expected not in text or header not in text or api.session_cfi_policy(actual_command) != policy:
            fail("ACTUAL_TU_COMMAND:" + logical)
        objects[logical] = dict(object=package.file_identity(actual_object), command=package.file_identity(actual_command))
        if logical.endswith("/manager_task_state.c") and (actual_object != obj or actual_command != command):
            fail("ACTUAL_TASK_OBJECT_PATH")
    if paths["nativeProbeSource"].read_bytes() != NATIVE_PROBE_SOURCE.encode("ascii"):
        fail("NATIVE_PROBE_SOURCE")
    if compile_options(paths["nativeProbeCommand"]) != compile_options(command):
        fail("NATIVE_PROBE_COMPILE_OPTIONS")
    probe_command = paths["nativeProbeCommand"].read_text(encoding="utf-8")
    probe_object = paths["nativeProbeObject"].relative_to(bridge.parent).as_posix()
    probe_source = paths["nativeProbeSource"].relative_to(bridge.parent).as_posix()
    if (" -c -o /module/" + probe_object + " /module/" + probe_source not in probe_command or
            "/module/" + sources["runtime/ultra/identity/kernel/manager_task_state.h"]["staged"] not in probe_command):
        fail("NATIVE_PROBE_ACTUAL_TU_COMMAND")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    derived = output / "task-profile-btf.elf"
    native_derived = output / "native-probe-btf.elf"
    native_probe_is_elf = paths["nativeProbeObject"].read_bytes().startswith(b"\x7fELF")
    debug_source = package.module_debug_source(bridge, paths["strictBuild"])
    paths["moduleDebugSource"] = debug_source
    before["moduleDebugSource"] = package.file_identity(debug_source)
    native_probe_carrier = paths["nativeProbeObject"] if native_probe_is_elf else debug_source
    shutil.copyfile(debug_source, derived)
    shutil.copyfile(native_probe_carrier, native_derived)
    commands = [[str(args.llvm_objcopy.resolve()), "--decompress-debug-sections", str(derived)],
                [str(args.pahole.resolve()), "-J", "--btf_features_strict=var,global_var", str(derived)],
                [str(args.llvm_objcopy.resolve()), "--decompress-debug-sections", str(native_derived)],
                [str(args.pahole.resolve()), "-J", "--btf_features_strict=var,global_var", str(native_derived)]]
    for index, argv in enumerate(commands):
        with (output / ("derive-%d.log" % index)).open("xb") as log:
            result = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            fail("DERIVED_BTF:" + str(result.returncode))
    if package.alloc_sections(bridge.read_bytes()) != package.alloc_sections(derived.read_bytes()):
        fail("DERIVED_CODE_CHANGED")
    if package.alloc_sections(native_probe_carrier.read_bytes()) != package.alloc_sections(native_derived.read_bytes()):
        fail("NATIVE_PROBE_DERIVED_CODE_CHANGED")
    definitions = api.object_btf(derived)
    native_definitions = api.object_btf(native_derived)
    native = implementation.get("nativeAbi", {})
    probe_elf = package.ELFFile(io.BytesIO(native_probe_carrier.read_bytes()))
    _, probe_storage, probe_at, probe_size = symbol(probe_elf, "msu_task_profile_native_type_facts", "STT_OBJECT")
    if probe_size != 16 or probe_storage["sh_flags"] & 7 != 2:
        fail("NATIVE_COMPILER_FACTS_STORAGE")
    native_values = list(struct.unpack("<4I", probe_storage.data()[probe_at:probe_at + probe_size]))
    expected_values = [native["listHeadBytes"], native["listHeadAlignment"], native["rwlockBytes"], native["rwlockAlignment"]]
    if native_values != expected_values or any(not value or value > 65536 for value in native_values) or any(
            alignment & (alignment - 1) or size % alignment for size, alignment in (native_values[:2], native_values[2:])):
        fail("NATIVE_COMPILER_SIZE_ALIGNMENT")
    native_types = {}
    for name, expected in native.get("types", {}).items():
        indexes = [index for index, entry in enumerate(definitions.types)
            if entry and entry[1] in (4, 5, 8) and definitions.name(entry[0]) == name]
        signatures = {definitions.signature(index) for index in indexes}
        if signatures != {expected["signature"]} or any(definitions.type_size(index) != expected["bytes"] for index in indexes):
            fail("NATIVE_BY_VALUE_TYPE:" + name)
        probe_indexes = [index for index, entry in enumerate(native_definitions.types)
            if entry and entry[1] in (4, 5, 8) and native_definitions.name(entry[0]) == name]
        if {native_definitions.signature(index) for index in probe_indexes} != signatures:
            fail("NATIVE_PROBE_BY_VALUE_TYPE:" + name)
        native_types[name] = expected["signature"]
    if not native_types or any(values.get(name, "n") != expected
            for values in (config, build_config) for name, expected in native.get("lockConfig", {}).items()):
        fail("NATIVE_LOCK_CONFIG")
    module = package.ELFFile(io.BytesIO(bridge.read_bytes()))
    with derived.open("rb") as stream:
        debug_elf = dwarf_view(stream.read())
        if not debug_elf.has_dwarf_info():
            fail("ACTUAL_DWARF_REQUIRED")
        needed, found = set(FUNCTIONS) | set(TABLES) | {name + "_type" for name in CALLBACKS}, set()
        for cu in debug_elf.get_dwarf_info().iter_CUs():
            cu_name = cu.get_top_DIE().attributes.get("DW_AT_name")
            if cu_name is None or Path(cu_name.value.decode().replace("\\", "/")).name != "manager_task_state.c":
                continue
            for die in cu.iter_DIEs():
                name = die.attributes.get("DW_AT_name")
                if name is not None and name.value.decode() in needed and not die.attributes.get("DW_AT_declaration"):
                    found.add(name.value.decode())
        if found != needed:
            fail("ACTUAL_CU_DEFINITIONS:" + ",".join(sorted(needed - found)))
        if not native_probe_is_elf:
            probe_names = {"msu_task_profile_native_type_facts", "msu_task_profile_native_list_type", "msu_task_profile_native_rwlock_type"}
            found_probe = set()
            for cu in debug_elf.get_dwarf_info().iter_CUs():
                cu_name = cu.get_top_DIE().attributes.get("DW_AT_name")
                if cu_name is None or Path(cu_name.value.decode().replace("\\", "/")).name != paths["nativeProbeSource"].name:
                    continue
                for die in cu.iter_DIEs():
                    name = die.attributes.get("DW_AT_name")
                    if name is not None and name.value.decode() in probe_names and not die.attributes.get("DW_AT_declaration"):
                        found_probe.add(name.value.decode())
            if found_probe != probe_names:
                fail("NATIVE_PROBE_LTO_CU_DEFINITIONS")
    functions = {}
    native_object = obj.read_bytes().startswith(b"\x7fELF")
    object_elf = package.ELFFile(io.BytesIO(obj.read_bytes())) if native_object else None
    for name in FUNCTIONS:
        signature = "*" + definitions.function(name)
        expected = implementation["functions"][name]
        if signature != expected.get("signature") or signature != expected.get("declarationSignature"):
            fail("FUNCTION_BTF_DECLARATION:" + name)
        actual = function_record(module, name, signature, policy, expected)
        if object_elf is not None:
            original = function_record(object_elf, name, signature, policy, expected)
            if any(original[key] != actual[key] for key in ("bytes", "sha256")):
                fail("OBJECT_FINAL_FUNCTION_BYTES:" + name)
            actual["objectComparison"] = dict(method="actual-tu-function-bytes", **original)
        else:
            actual["objectComparison"] = dict(method="bitcode-final-link-DWARF-CU-and-unchanged-alloc-sections")
        functions[name] = actual
    callbacks = {name: typed_callback(module, definitions, name, functions[name]["signature"]) for name in CALLBACKS}
    if any(callbacks[name]["signature"] != definitions.typedef_function("kretprobe_handler_t") for name in CALLBACKS[1:]):
        fail("MARKER_NATIVE_TYPEDEF")
    tables = {name: table_record(module, name) for name in TABLES}
    for name, (key, _, _, _) in TABLES.items():
        if tables[name]["values"] != implementation[key]["values"]:
            fail("CLAIM_TABLE_BYTES:" + name)
        if object_elf is not None and table_record(object_elf, name)["sha256"] != tables[name]["sha256"]:
            fail("OBJECT_FINAL_TABLE_BYTES:" + name)
    report = dict(schema="maplesu-init-bridge-task-profile-abi/1", originalModuleWritten=False,
        targetQualified=False, deviceQualified=False, claimSha256=before["claimElf"]["sha256"],
        sourceSuccessorIdentity=before["sourceSuccessor"], sourceSuccessor=successor, sources=sources,
        nativeTypes=native_types, cfiPolicy=policy, functions=functions, tables=tables, callbacks=callbacks,
        nativeAlignment=dict(source="actual-bridge-build-command-compiler-facts-and-complete-by-value-BTF",
            independentlyMeasuredFromBridgeBuild=True, values=native_values,
            carrier="native-probe-object" if native_probe_is_elf else "same-final-module-with-actual-probe-CU",
            listHeadAlignment=native_values[1], rwlockAlignment=native_values[3],
            claimAlignmentFacts=native["alignmentFacts"]),
        provenance=dict(**before, derivedObject=package.file_identity(derived), objects=objects, pathBindings=path_bindings,
            derivedNativeProbe=package.file_identity(native_derived),
            method="same-final-module-derived-btf-and-actual-CU", commands=commands,
            dwarfRelocationPolicy="reader-only-R_AARCH64_NONE-in-nonalloc-debug-sections;all-other-relocations-standard",
            tools={name: package.file_identity(path.resolve()) for name, path in
                (("pahole", args.pahole), ("llvmObjcopy", args.llvm_objcopy))}))
    if dependency is not None:
        report["provenance"]["pythonDependency"] = dependency
    verify_provenance(report, bridge, paths["sourceSelection"], paths["strictBuild"], paths["targetConfig"])
    for name, path in paths.items():
        check_identity(path, before[name], name)
    for logical, pair in objects.items():
        for kind, identity in pair.items():
            check_identity(Path(identity["path"]), identity, logical + ":" + kind)
    package.python_dependency(args)
    encoded = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    if not 0 < len(encoded) <= 1024 * 1024:
        fail("REPORT_SIZE_LIMIT")
    result = output / "task-profile-abi.json"
    result.write_bytes(encoded)
    print(json.dumps(package.file_identity(result), indent=2))


def legacy_api():
    return load_api("task_profile_legacy", Path(__file__).with_name("task_profile_legacy.py"))


if __name__ == "__main__":
    if sys.argv[1:2] == ["probe-source"]:
        probe_source_main()
    elif sys.argv[1:2] == ["legacy"]:
        legacy_api().main(SimpleNamespace(**globals()))
    else:
        main()
