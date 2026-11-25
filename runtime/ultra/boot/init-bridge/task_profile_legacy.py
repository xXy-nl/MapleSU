"""TaskProfile facts from an actual legacy-CFI normal module, not a raw claim."""
import argparse
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys


LOCK_CONFIG = ("CONFIG_SMP", "CONFIG_QUEUED_RWLOCKS", "CONFIG_PARAVIRT_SPINLOCKS",
    "CONFIG_DEBUG_SPINLOCK", "CONFIG_DEBUG_LOCK_ALLOC", "CONFIG_PREEMPT_RT")
ORIGIN = "normal-module-legacy-cfi"


def dependency(api):
    return api.load_api("task_profile_legacy_contract", Path(__file__).with_name("legacy_cfi_contract.py"))


def actual_policy(command):
    enabled, normalized = set(), False
    for token in command.read_text(encoding="utf-8").splitlines()[0].split():
        if token.startswith(("-fsanitize=", "-fno-sanitize=")):
            values = set(token.split("=", 1)[1].split(","))
            enabled = enabled | values if token.startswith("-fsanitize=") else enabled - values
        elif token in ("-fsanitize-cfi-icall-normalize-integers", "-fsanitize-cfi-icall-experimental-normalize-integers"):
            normalized = True
        elif token in ("-fno-sanitize-cfi-icall-normalize-integers", "-fno-sanitize-cfi-icall-experimental-normalize-integers"):
            normalized = False
    mode = "kcfi" if "kcfi" in enabled else "legacy-lto-cfi" if enabled & {"cfi", "cfi-icall"} else "none"
    return dict(mode=mode, normalizeIntegers=normalized)


def native_type(btf, name):
    indexes = [index for index, entry in enumerate(btf.types) if entry and
        entry[1] in (4, 5, 8) and btf.name(entry[0]) == name]
    facts = {(btf.signature(index), btf.type_size(index)) for index in indexes}
    if len(facts) != 1:
        raise ValueError("ULTRA_BRIDGE_TASK_PROFILE_NATIVE_TYPE:" + name)
    signature, size = facts.pop()
    return dict(signature=signature, bytes=size)


def model_location(model, address):
    matches = [(index, address - base) for index, base in model.bases.items()
        if base <= address < base + len(model.sections[index])]
    if len(matches) != 1:
        raise ValueError("ULTRA_BRIDGE_TASK_PROFILE_LEGACY_MODEL_LOCATION")
    index, offset = matches[0]
    section = model.elf.get_section(index)
    return dict(section=section.name, sectionIndex=index, offset=offset,
        fileOffset=section["sh_offset"] + offset)


def callback(api, elf, btf, model, name, signature):
    pointer = name + "_type"
    if btf is not None:
        indexes = btf.variables.get(pointer, [])
        if (len(indexes) != 1 or btf.variable(pointer) != signature or
                btf.type_size(btf.types[indexes[0]][3]) != 8):
            api.fail("CALLBACK_TYPED_VAR:" + pointer)
    entry, section, at, size = api.symbol(elf, pointer, "STT_OBJECT")
    if size != 8 or section["sh_flags"] & 7 != 3:
        api.fail("CALLBACK_POINTER_BYTES:" + pointer)
    rows = []
    for item in elf.iter_sections():
        if item["sh_type"] != "SHT_RELA" or item["sh_info"] != entry["st_shndx"]:
            continue
        table = elf.get_section(item["sh_link"])
        for relocation in item.iter_relocations():
            if entry["st_value"] <= relocation["r_offset"] < entry["st_value"] + 8:
                target = table.get_symbol(relocation["r_info_sym"])
                rows.append(dict(section=item.name, offset=relocation["r_offset"],
                    type=relocation["r_info_type"], addend=relocation["r_addend"], symbol=target.name))
    if len(rows) != 1 or rows[0]["offset"] != entry["st_value"] or rows[0]["type"] != 257:
        api.fail("CALLBACK_ABS64_TARGET:" + pointer)
    canonical = model.canonical(name)
    if int.from_bytes(model.read(model.address(pointer), 8), "little") != canonical:
        api.fail("CALLBACK_CANONICAL_TARGET:" + pointer)
    return dict(symbol=pointer, signature=signature, section=section.name,
        offset=entry["st_value"], fileOffset=section["sh_offset"] + at,
        relocation=rows[0], canonical=model_location(model, canonical))


def trace_registration(api, model, name, canonical):
    """Prove the actual native registration/unregistration callback argument."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    proofs = []
    for owner, imported in (("msu_task_profile_trace_open", "tracepoint_probe_register_prio"),
            ("msu_task_profile_trace_close", "tracepoint_probe_unregister")):
        function = model.symbol(owner)
        section = function["st_shndx"]
        start, end = function["st_value"], function["st_value"] + function["st_size"]
        matches = [(at, rel) for (index, at), (rel, target) in model.relocations.items()
            if index == section and start <= at < end and target.name == imported and rel["r_info_type"] == 283]
        if len(matches) != 1:
            api.fail("UNCHECKED_TRACE_REGISTRATION_CALL:" + owner)
        at, relocation = matches[0]
        base = model.bases[section]
        rows = list(decoder.disasm(bytes(model.sections[section][start:at]), base + start))
        def argument(register, stop, depth=0):
            if depth >= 16:
                api.fail("UNCHECKED_TRACE_REGISTRATION_DEPTH")
            for index in range(stop - 1, max(-1, stop - 33), -1):
                ins = rows[index]
                if ins.mnemonic in ("b", "bl", "blr", "br", "ret") or ins.mnemonic.startswith(("b.", "cb", "tb")):
                    break
                _, writes = ins.regs_access()
                if register not in {ins.reg_name(reg).replace("w", "x", 1) for reg in writes}:
                    continue
                args = ins.operands
                if ins.mnemonic in ("adr", "adrp") and args[1].type == ARM64_OP_IMM:
                    return args[1].imm
                if ins.mnemonic in ("mov", "add") and args[1].type == ARM64_OP_REG:
                    value = argument(ins.reg_name(args[1].reg), index, depth + 1)
                    if ins.mnemonic == "mov":
                        return value
                    if len(args) == 3 and args[2].type == ARM64_OP_IMM:
                        return value + (args[2].imm << args[2].shift.value)
                break
            api.fail("UNCHECKED_TRACE_REGISTRATION_ARGUMENT:" + owner)
        if argument("x1", len(rows)) != canonical:
            api.fail("UNCHECKED_TRACE_REGISTRATION_TARGET:" + owner)
        proofs.append(dict(function=owner, imported=imported, call=model_location(model, base + at),
            callback=model_location(model, canonical), relocationType=relocation["r_info_type"],
            proof="actual-relocated-native-registration-argument"))
    return proofs


def callback_machine_abi(signature):
    """Project only simple pointer/64-bit integer parameters of the real module BTF.

    This discards pointee names and integer signedness deliberately: target
    instructions establish register transport, not a semantic C declaration.
    """
    import re
    if not signature.startswith("*fv(") or not signature.endswith(";)"):
        return None
    arguments = signature[4:-1].split(";")
    if arguments[-1] != "":
        return None
    arguments = arguments[:-1]
    if len(arguments) != 3 or any(not re.fullmatch(r"(?:\*+(?:v|s[A-Za-z_][A-Za-z_0-9]*|i[1-8]:[0-9]+)|i8:[0-9]+)", arg)
            for arg in arguments):
        return None
    return dict(pcs="aapcs64", argumentRegisters=["x0", "x1", "x2"], argumentBytes=[8, 8, 8])


def task_member(api, model, contract, name, callsites, target, functions, canonical):
    unchecked = [row for row in callsites if row.get("cfiMode") == "unchecked-native-callsite"]
    if not unchecked:
        return model.member(name, callsites)
    if (len(callsites) != 1 or name != "msu_task_profile_sys_enter" or
            "typeIdHex" in unchecked[0] or
            target["taskProfileCallerTypeSets"].get(unchecked[0]["caller"]) != []):
        api.fail("UNCHECKED_TRACE_CALLBACK_ABI:" + name)
    fact = unchecked[0]
    if fact.get("proof") == "actual-symbol-bounded-uninstrumented-trace-loop-and-btf":
        if fact.get("callbackSignature") != functions[name]["signature"]:
            api.fail("UNCHECKED_TRACE_CALLBACK_ABI:" + name)
        return dict(symbol=name, cfiMode="unchecked-native-callsite",
            callbackSignature=functions[name]["signature"],
            proof="actual-native-unchecked-trace-callsite-not-cfi-membership",
            registration=trace_registration(api, model, name, canonical), runtimeOwnerQualified=False)
    if (fact.get("proof") != "actual-symbol-bounded-uninstrumented-trace-loop-and-registration-writer" or
            fact.get("caller") != "__traceiter_sys_enter" or fact.get("btfAvailable") is not False or
            fact.get("machineAbiQualified") is not True or
            any(fact.get(key) is not False for key in ("targetSemanticSignatureQualified", "targetCfiTypeIdQualified",
                "runtimeOwnerQualified", "deviceQualified")) or
            any(key in fact for key in ("callbackSignature", "iteratorSignature", "btfSha256")) or
            not fact.get("registrationWriter") or callback_machine_abi(functions[name]["signature"]) is None or
            {key: fact.get("callbackMachineAbi", {}).get(key) for key in ("pcs", "argumentRegisters", "argumentBytes")} !=
            callback_machine_abi(functions[name]["signature"]) or
            fact.get("callbackMachineAbi", {}).get("argumentSources") != ["record-data", "iterator-x1", "iterator-x2"] or
            fact.get("callbackMachineAbi", {}).get("returnValueUsed") is not False):
        api.fail("UNCHECKED_TRACE_CALLBACK_ABI:" + name)
    return dict(symbol=name, cfiMode="unchecked-native-callsite",
        moduleCallbackSignature=functions[name]["signature"], callbackMachineAbi=fact["callbackMachineAbi"],
        proof="actual-native-unchecked-trace-machine-abi-not-semantic-or-cfi-membership",
        registration=trace_registration(api, model, name, canonical), machineAbiQualified=True,
        targetSemanticSignatureQualified=False, targetCfiTypeIdQualified=False, runtimeOwnerQualified=False)


def legacy_proof(api, data, target, functions):
    contract = dependency(api)
    model = contract.ModuleChecker(data)
    if model.elf.get_section_by_name(".gnu.linkonce.this_module") is None:
        api.fail("LEGACY_NORMAL_MODULE_OWNER")
    owner = model.symbol("__this_module")
    if owner["st_info"]["type"] != "STT_OBJECT" or owner["st_size"] <= 0:
        api.fail("LEGACY_NORMAL_MODULE_OWNER")
    # Retain the actual native init consumer; requested callbacks are checked
    # below. Static membership never claims module/shadow publication.
    normal = contract.verify_module(data, target)
    members = {}
    for name in api.CALLBACKS:
        canonical = model.canonical(name)
        callsites = target["taskProfileCallsites"][name]
        member = task_member(api, model, contract, name, callsites, target, functions, canonical)
        branch = canonical
        instruction = int.from_bytes(model.read(branch, 4), "little")
        if instruction in (0xd503245f, 0xd50324df):
            branch += 4
            instruction = int.from_bytes(model.read(branch, 4), "little")
        body = branch + contract.signed(instruction & 0x03ffffff, 26) * 4
        member["canonical"] = dict(**model_location(model, canonical),
            branch=model_location(model, branch), body=model_location(model, body))
        members[name] = member
    checker = api.function_record(model.elf, "__cfi_check", "", {"mode": "legacy-lto-cfi"}, {})
    return dict(schema="maplesu-task-profile-legacy-cfi/1", mode="legacy-lto-cfi",
        targetSha256=target["targetSha256"], checker=checker, members=members,
        callerTypeSets=target["taskProfileCallerTypeSets"], callbackCallsites=target["taskProfileCallsites"],
        normalModule=normal, relocationOwner="normal-kernel-module-loader",
        moduleLoaded=False, runtimeOwnerQualified=False, deviceQualified=False)


def verify_module(api, data, report):
    if (report.get("schema") != "maplesu-init-bridge-task-profile-abi/1" or
            report.get("implementationOrigin") != ORIGIN or
            any(report.get(name) is not False for name in ("originalModuleWritten", "targetQualified", "deviceQualified")) or
            set(report.get("functions", {})) != set(api.FUNCTIONS) or
            set(report.get("tables", {})) != set(api.TABLES) or
            set(report.get("callbacks", {})) != set(api.CALLBACKS) or
            report.get("cfiPolicy", {}).get("mode") != "legacy-lto-cfi"):
        api.fail("LEGACY_REPORT_CONTRACT")
    elf = api.package.ELFFile(io.BytesIO(data))
    contract = dependency(api)
    model = contract.ModuleChecker(data)
    target = report["legacyTarget"]
    if legacy_proof(api, data, target, report["functions"]) != report["legacyCfi"]:
        api.fail("LEGACY_CHECKER_MEMBERSHIP")
    ranges = []
    for name in api.TABLES:
        actual = api.table_record(elf, name)
        if actual != report["tables"][name]:
            api.fail("TABLE_FACT:" + name)
        ranges.append((actual["fileOffset"], actual["fileOffset"] + actual["bytes"]))
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:])):
        api.fail("TABLE_OVERLAP")
    for name in api.FUNCTIONS:
        expected = report["functions"][name]
        actual = api.function_record(elf, name, expected["signature"], report["cfiPolicy"], {})
        if actual != expected:
            api.fail("FUNCTION_FACT:" + name)
        if any(actual["fileOffset"] < right and left < actual["fileOffset"] + actual["bytes"] for left, right in ranges):
            api.fail("CODE_TABLE_OVERLAP:" + name)
    for name in api.CALLBACKS:
        if callback(api, elf, None, model,
                name, report["functions"][name]["signature"]) != report["callbacks"][name]:
            api.fail("CALLBACK_FACT:" + name)
    return True


def verify_provenance(api, report, bridge, selection, build, config):
    provenance = report.get("provenance", {})
    for name, path in (("bridge", bridge), ("sourceSelection", selection), ("strictBuild", build), ("targetConfig", config)):
        api.check_identity(path, provenance.get(name, {}), name)
    for name in ("sourceSuccessor", "taskObject", "taskCommand", "buildConfig", "derivedObject",
            "nativeProbeSource", "nativeProbeObject", "nativeProbeCommand", "derivedNativeProbe", "targetContract", "targetImage",
            "claimBuilder", "collector", "legacyCollector", "legacyContract", "legacyCompilerFacts"):
        reference = provenance[name]
        api.check_identity(api.retained_path(reference, report, bridge), reference, name)
    successor = api.read_json(api.retained_path(provenance["sourceSuccessor"], report, bridge))
    if (successor != report["sourceSuccessor"] or provenance["sourceSuccessor"] != report["sourceSuccessorIdentity"] or
            api.source_proof(selection, build, bridge.parent, successor,
                api.retained_path(provenance["buildConfig"], report, bridge)) != report["sources"]):
        api.fail("SOURCE_PROOF")
    target_contract = api.read_json(api.retained_path(provenance["targetContract"], report, bridge))
    if target_contract.get("cfiMode") != "legacy-lto-cfi" or target_contract.get("legacyCfi") != report["legacyTarget"]:
        api.fail("LEGACY_TARGET_CONTRACT")
    if target_contract["inputs"]["kernelImage"]["sha256"] != provenance["targetImage"]["sha256"]:
        api.fail("LEGACY_TARGET_IMAGE")
    if any(target_contract["inputs"][key][field] != provenance[label][field]
            for key, label in (("targetConfig", "targetConfig"), ("buildConfig", "buildConfig"))
            for field in ("bytes", "sha256")):
        api.fail("LEGACY_TARGET_CONFIG_IDENTITY")
    for entry in provenance["actualLegacyCommands"]:
        reference = entry["identity"]
        api.check_identity(api.retained_path(reference, report, bridge), reference, "actual-legacy-command")
    command_policy = api.load_api("task_profile_legacy_verify_flags",
        Path(__file__).with_name("legacy_module_cfi_facts.py")).command_policy
    commands = [api.retained_path(entry["identity"], report, bridge)
        for entry in provenance["actualLegacyCommands"]]
    if ([{key: value for key, value in command_policy(path).items() if key != "identity"} for path in commands] !=
            [{key: value for key, value in entry.items() if key != "identity"} for entry in provenance["actualLegacyCommands"]] or
            len(commands) < 5 or len(set(commands)) != len(commands)):
        api.fail("LEGACY_ACTUAL_COMMAND_FACTS")
    target_config = api.package.config_values(config.read_bytes())
    build_config = api.package.config_values(api.retained_path(provenance["buildConfig"], report, bridge).read_bytes())
    policy = dict(mode="legacy-lto-cfi",
        normalizeIntegers=target_config.get("CONFIG_CFI_ICALL_NORMALIZE_INTEGERS") == "y")
    if (report["cfiPolicy"] != policy or any(actual_policy(path) != policy for path in commands) or
            not any(target_config.get(key) == "y" for key in ("CONFIG_CFI", "CONFIG_CFI_CLANG")) or
            any(target_config.get(key, "n") != build_config.get(key, "n") for key in LOCK_CONFIG)):
        api.fail("LEGACY_ACTUAL_CFI_POLICY")
    api.package.verify_module_debug_source(provenance, bridge, build)
    verify_module(api, bridge.read_bytes(), report)


def main(api):
    parser = argparse.ArgumentParser(description=__doc__)
    arguments = ("bridge", "task-object", "task-command", "source-selection", "build-receipt", "target-config",
        "build-config", "source-successor", "claim-builder", "native-probe-source", "native-probe-object",
        "native-probe-command", "target-contract", "target-image", "pahole", "llvm-objcopy", "output")
    for name in arguments:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--path-binding", action="append", default=[])
    api.package.add_python_dependency_options(parser)
    args = parser.parse_args(sys.argv[2:])
    python_dependency = api.package.python_dependency(args)
    paths = {name: getattr(args, argument.replace("-", "_")).resolve() for name, argument in (
        ("bridge", "bridge"), ("taskObject", "task-object"), ("taskCommand", "task-command"),
        ("sourceSelection", "source-selection"), ("strictBuild", "build-receipt"), ("targetConfig", "target-config"),
        ("buildConfig", "build-config"), ("sourceSuccessor", "source-successor"), ("claimBuilder", "claim-builder"),
        ("nativeProbeSource", "native-probe-source"), ("nativeProbeObject", "native-probe-object"),
        ("nativeProbeCommand", "native-probe-command"), ("targetContract", "target-contract"), ("targetImage", "target-image"))}
    paths.update(collector=Path(api.__file__).resolve(), legacyCollector=Path(__file__).resolve(),
        legacyContract=Path(__file__).with_name("legacy_cfi_contract.py").resolve(),
        legacyCompilerFacts=Path(__file__).with_name("legacy_module_cfi_facts.py").resolve())
    before = {name: api.package.file_identity(path) for name, path in paths.items()}
    bridge, command = paths["bridge"], paths["taskCommand"]
    bindings = dict(item.split("=", 1) for item in args.path_binding)
    if len(bindings) != len(args.path_binding) or set(bindings) != {"/build-config"}:
        api.fail("ACTUAL_MOUNT_ROOT_BINDINGS_REQUIRED")
    successor = api.read_json(paths["sourceSuccessor"])
    sources = api.source_proof(paths["sourceSelection"], paths["strictBuild"], bridge.parent, successor, paths["buildConfig"])
    legacy = dependency(api)
    command_policy = api.load_api("task_profile_legacy_flags",
        Path(__file__).with_name("legacy_module_cfi_facts.py")).command_policy
    commands = [command, paths["nativeProbeCommand"], bridge.parent / ".native_legacy_cfi.o.cmd",
        bridge.parent / "producer/module/.maplesu_boot_sdk.o.cmd"]
    for logical, source in sources.items():
        if not logical.endswith(".c"):
            continue
        obj = bridge.parent / Path(source["staged"]).with_suffix(".o")
        actual_command = obj.with_name("." + obj.name + ".cmd")
        actual = actual_command.read_text(encoding="utf-8")
        expected = " -c -o /module/" + obj.relative_to(bridge.parent).as_posix() + " /module/" + source["staged"]
        if expected not in actual or "/module/" + sources["runtime/ultra/identity/kernel/manager_task_state.h"]["staged"] not in actual:
            api.fail("ACTUAL_TU_COMMAND:" + logical)
        commands.append(actual_command)
    policies = [command_policy(path) for path in dict.fromkeys(commands)]
    if paths["nativeProbeSource"].read_bytes() != api.NATIVE_PROBE_SOURCE.encode("ascii") or \
            api.compile_options(paths["nativeProbeCommand"]) != api.compile_options(command):
        api.fail("NATIVE_PROBE_COMPILE_OPTIONS")
    probe_command = paths["nativeProbeCommand"].read_text(encoding="utf-8")
    if (" -c -o /module/" + paths["nativeProbeObject"].relative_to(bridge.parent).as_posix() +
            " /module/" + paths["nativeProbeSource"].relative_to(bridge.parent).as_posix() not in probe_command or
            "/module/" + sources["runtime/ultra/identity/kernel/manager_task_state.h"]["staged"] not in probe_command):
        api.fail("NATIVE_PROBE_ACTUAL_TU_COMMAND")
    target_contract = api.read_json(paths["targetContract"])
    target = target_contract.get("legacyCfi", {})
    if (target_contract.get("cfiMode") != "legacy-lto-cfi" or
            target_contract.get("inputs", {}).get("kernelImage", {}).get("sha256") != before["targetImage"]["sha256"] or
            target.get("targetSha256") != before["targetImage"]["sha256"] or
            set(target.get("taskProfileCallsites", {})) != set(api.CALLBACKS)):
        api.fail("LEGACY_TARGET_CONTRACT")
    config = api.package.config_values(paths["targetConfig"].read_bytes())
    build_config = api.package.config_values(paths["buildConfig"].read_bytes())
    if not any(config.get(key) == "y" for key in ("CONFIG_CFI", "CONFIG_CFI_CLANG")) or any(
            config.get(key, "n") != build_config.get(key, "n") for key in LOCK_CONFIG):
        api.fail("LEGACY_TARGET_CONFIG")
    normalize = config.get("CONFIG_CFI_ICALL_NORMALIZE_INTEGERS") == "y"
    sys.path.insert(0, str(paths["claimBuilder"].parent))
    compiler = api.load_api("task_profile_legacy_btf_api", paths["claimBuilder"])
    if any(actual_policy(path) != {"mode": "legacy-lto-cfi", "normalizeIntegers": normalize}
            for path in dict.fromkeys(commands)):
        api.fail("LEGACY_ACTUAL_CFI_POLICY")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    derived, probe = output / "task-profile-btf.elf", output / "native-probe-btf.elf"
    native = paths["nativeProbeObject"]
    native_elf = native.read_bytes().startswith(b"\x7fELF")
    debug_source = api.package.module_debug_source(bridge, paths["strictBuild"])
    paths["moduleDebugSource"] = debug_source
    before["moduleDebugSource"] = api.package.file_identity(debug_source)
    carrier = native if native_elf else debug_source
    derivations = []
    for source, destination in ((debug_source, derived), (carrier, probe)):
        shutil.copyfile(source, destination)
        for argv in ([str(args.llvm_objcopy), "--decompress-debug-sections", str(destination)],
                [str(args.pahole), "-J", "--btf_features_strict=var,global_var", str(destination)]):
            with (output / ("derive-%d.log" % len(derivations))).open("xb") as stream:
                completed = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=False)
            derivations.append(argv)
            if completed.returncode:
                api.fail("DERIVED_BTF:" + str(completed.returncode))
        if api.package.alloc_sections(source.read_bytes()) != api.package.alloc_sections(destination.read_bytes()):
            api.fail("DERIVED_CODE_CHANGED")
    definitions, native_definitions = compiler.object_btf(derived), compiler.object_btf(probe)
    elf = api.package.ELFFile(io.BytesIO(bridge.read_bytes()))
    model = legacy.ModuleChecker(bridge.read_bytes())
    needed = set(api.FUNCTIONS) | set(api.TABLES) | {name + "_type" for name in api.CALLBACKS}
    found = set()
    probe_names = {"msu_task_profile_native_type_facts", "msu_task_profile_native_list_type", "msu_task_profile_native_rwlock_type"}
    found_probe = set()
    for cu in api.dwarf_view(derived.read_bytes()).get_dwarf_info().iter_CUs():
        name = cu.get_top_DIE().attributes.get("DW_AT_name")
        cu_name = Path(name.value.decode().replace("\\", "/")).name if name is not None else None
        if cu_name not in ("manager_task_state.c", paths["nativeProbeSource"].name):
            continue
        for die in cu.iter_DIEs():
            name = die.attributes.get("DW_AT_name")
            if name is not None and not die.attributes.get("DW_AT_declaration"):
                if cu_name == "manager_task_state.c" and name.value.decode() in needed:
                    found.add(name.value.decode())
                elif cu_name == paths["nativeProbeSource"].name and name.value.decode() in probe_names:
                    found_probe.add(name.value.decode())
    if found != needed:
        api.fail("ACTUAL_CU_DEFINITIONS:" + ",".join(sorted(needed - found)))
    if not native_elf and found_probe != probe_names:
        api.fail("NATIVE_PROBE_LTO_CU_DEFINITIONS")
    probe_elf = api.package.ELFFile(io.BytesIO(carrier.read_bytes()))
    _, storage, at, size = api.symbol(probe_elf, "msu_task_profile_native_type_facts", "STT_OBJECT")
    if size != 16 or storage["sh_flags"] & 7 != 2:
        api.fail("NATIVE_COMPILER_FACTS_STORAGE")
    values = list(struct.unpack("<4I", storage.data()[at:at + size]))
    _, final_storage, final_at, final_size = api.symbol(elf, "msu_task_profile_native_type_facts", "STT_OBJECT")
    if final_size != size or final_storage.data()[final_at:final_at + size] != storage.data()[at:at + size]:
        api.fail("NATIVE_PROBE_FINAL_MODULE_FACTS")
    if any(not value or value > 65536 for value in values) or any(
            alignment & (alignment - 1) or size % alignment for size, alignment in (values[:2], values[2:])):
        api.fail("NATIVE_COMPILER_SIZE_ALIGNMENT")
    types = {name: native_type(definitions, name) for name in ("list_head", "rwlock_t")}
    if types != {name: native_type(native_definitions, name) for name in types} or \
            values[::2] != [types["list_head"]["bytes"], types["rwlock_t"]["bytes"]]:
        api.fail("NATIVE_PROBE_BY_VALUE_TYPE")
    functions = {name: api.function_record(elf, name, "*" + definitions.function(name),
        {"mode": "legacy-lto-cfi"}, {}) for name in api.FUNCTIONS}
    callbacks = {name: callback(api, elf, definitions, model, name, functions[name]["signature"]) for name in api.CALLBACKS}
    if any(callbacks[name]["signature"] != definitions.typedef_function("kretprobe_handler_t") for name in api.CALLBACKS[1:]):
        api.fail("MARKER_NATIVE_TYPEDEF")
    report = dict(schema="maplesu-init-bridge-task-profile-abi/1", implementationOrigin=ORIGIN,
        originalModuleWritten=False, targetQualified=False, deviceQualified=False,
        sourceSuccessorIdentity=before["sourceSuccessor"], sourceSuccessor=successor, sources=sources,
        nativeTypes={name: item["signature"] for name, item in types.items()},
        nativeAbi=dict(types=types, listHeadBytes=values[0], listHeadAlignment=values[1],
            rwlockBytes=values[2], rwlockAlignment=values[3],
            lockConfig={key: config.get(key, "n") for key in LOCK_CONFIG}),
        nativeAlignment=dict(independentlyMeasuredFromBridgeBuild=True, values=values,
            listHeadAlignment=values[1], rwlockAlignment=values[3]),
        cfiPolicy=dict(mode="legacy-lto-cfi", normalizeIntegers=normalize), functions=functions,
        tables={name: api.table_record(elf, name) for name in api.TABLES}, callbacks=callbacks,
        legacyTarget=target, legacyCfi=legacy_proof(api, bridge.read_bytes(), target, functions),
        provenance=dict(**before, derivedObject=api.package.file_identity(derived),
            derivedNativeProbe=api.package.file_identity(probe), pathBindings=bindings,
            commands=derivations, actualLegacyCommands=policies,
            dwarfRelocationPolicy="reader-only-R_AARCH64_NONE-in-nonalloc-debug-sections;all-other-relocations-standard"))
    if python_dependency is not None:
        report["provenance"]["pythonDependency"] = python_dependency
    verify_provenance(api, report, bridge, paths["sourceSelection"], paths["strictBuild"], paths["targetConfig"])
    for name, path in paths.items():
        api.check_identity(path, before[name], name)
    api.package.python_dependency(args)
    encoded = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    if not 0 < len(encoded) <= 1024 * 1024:
        api.fail("REPORT_SIZE_LIMIT")
    destination = output / "task-profile-abi.json"
    destination.write_bytes(encoded)
    print(json.dumps(api.package.file_identity(destination), indent=2))
