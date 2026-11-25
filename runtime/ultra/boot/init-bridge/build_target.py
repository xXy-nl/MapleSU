#!/usr/bin/env python3
"""Run one real target Kbuild; preserve compiler/modpost failure verbatim.

--native-only builds the two independent native components. A module build
requires the completed provider Kbuild in --module-source; this tool does not
invent its entry, export bindings, service factory or credential implementation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


TARGET_PROFILE_SOURCES = ("fs/exec.c", "fs/stat.c", "fs/open.c",
                          "arch/arm64/include/asm/syscall_wrapper.h",
                          "arch/arm64/include/asm/ptrace.h", "include/linux/binfmts.h")


def identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path.resolve()), "bytes": size, "sha256": digest.hexdigest()}


def strip_module_debug(module, tool, evidence):
    before = identity(module)
    with module.open("rb") as stream:
        stream.seek(max(0, before["bytes"] - 28))
        signed = stream.read().endswith(b"~Module signature appended~\n")
    if signed:
        return {"status": "SIGNED_MODULE_PRESERVED", "input": before, "output": before}, 0
    original = evidence / "maplesu_ultra_bridge.unstripped.ko"
    shutil.copyfile(module, original)
    command = [str(tool), "--strip-debug", str(module)]
    with (evidence / "strip-stdout.log").open("wb") as stdout, (evidence / "strip-stderr.log").open("wb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    return {"command": command, "exitCode": result.returncode,
            "input": before, "unstripped": identity(original), "output": identity(module)}, result.returncode


def staged_target_inputs(source, kdir, repo, kernel_source=None, target_contract=None):
    profile = source / "host/manager_su_runtime_target_profile.h"
    if not profile.is_file():
        return []
    receipt_path = source / "SOURCE-SELECTION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    binding = receipt.get("targetBinding")
    if not binding:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT_REQUIRED")
    if binding.get("kind") == "runtime-kmi-component":
        reference = binding.get("runtimeLayoutProfile")
        if (receipt.get("runtimeFactsSelected") is not True or not reference or
                reference not in receipt.get("formalRuntimeSuccessors", [])):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_SELECTION_REQUIRED")
        layout_path = repo / reference["repositoryPath"] if "repositoryPath" in reference else Path(reference["path"])
        if any(identity(layout_path)[key] != reference[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_SELECTION_IDENTITY")
        layout = json.loads(layout_path.read_text(encoding="utf-8-sig"))
        if layout.get("schema") != "maplesu-claim-runtime-layout-source-selection/1":
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_SELECTION_SCHEMA")
        required = {"manager_su_runtime_target_profile.h", "manager_task_profile_workbit.h",
                    *(unit + suffix for unit in ("manager_runtime_btf", "manager_runtime_accessor", "manager_task_profile_runtime")
                      for suffix in (".c", ".h"))}
        members = {}
        for name in required:
            logical = "runtime/ultra/identity/kernel/" + name
            declared = [row["after"] for row in layout.get("files", []) if row.get("logicalPath") == logical]
            staged = [row for row in receipt.get("inputs", []) if row.get("repositoryPath") == logical and
                      row.get("staged") == "host/" + name and row.get("selection") == "runtime-layout-source-successor"]
            path = source / "host" / name
            if len(declared) != 1 or len(staged) != 1 or any(
                    identity(path)[key] != declared[0][key] or staged[0]["selected"][key] != declared[0][key]
                    for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_SOURCE_IDENTITY:" + name)
            members[name] = path
        if any(identity(kdir / ".config")[key] != binding.get("buildConfig", {}).get(key)
               for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_BUILD_CONFIG")
        flags = (source / "selected-core.mk").read_text(encoding="utf-8")
        if ("-DMSU_INIT_BRIDGE_RUNTIME_FACTS=1" not in flags or any(
                "host/" + unit + ".o" not in flags for unit in
                ("manager_runtime_btf", "manager_runtime_accessor", "manager_task_profile_runtime"))):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_KBUILD")
        return [receipt_path, layout_path, *members.values()]
    if binding.get("kind") == "maplesu-init-bridge-kmi-target/1":
        spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).with_name("target_kmi.py"))
        kmi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(kmi)
        reference = binding["contract"]
        contract_path = target_contract if target_contract is not None else (
            repo / reference["repositoryPath"] if "repositoryPath" in reference else Path(reference["path"]))
        if any(identity(contract_path)[key] != reference[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_KMI_CONTRACT_IDENTITY")
        contract = kmi.read_contract(contract_path, kdir)
        if any(binding.get("kmiProfile", binding["profile"])[key] != contract["profile"][key]
               for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
        selected_inputs = []
        if receipt.get("runtimeLayoutSelected"):
            layout_ref = binding.get("runtimeLayoutProfile")
            if not layout_ref or layout_ref not in receipt.get("formalRuntimeSuccessors", []):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_REQUIRED")
            layout_path = (repo / layout_ref["repositoryPath"] if "repositoryPath" in layout_ref
                           else Path(layout_ref["path"]))
            if any(identity(layout_path)[key] != layout_ref[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_IDENTITY")
            layout = json.loads(layout_path.read_text(encoding="utf-8-sig"))
            if layout.get("schema") != "maplesu-claim-runtime-layout-source-selection/1":
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_SCHEMA")
            selected_profiles = [row for row in layout.get("files", []) if row.get("logicalPath") ==
                                 "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h"]
            staged_profiles = [row for row in receipt.get("inputs", [])
                               if row.get("repositoryPath") ==
                               "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h" and
                               row.get("staged") == "host/manager_su_runtime_target_profile.h"]
            actual_profile = identity(profile)
            if (len(selected_profiles) != 1 or len(staged_profiles) != 1 or
                    staged_profiles[0].get("selection") != "runtime-layout-source-successor" or any(
                    actual_profile[key] != selected_profiles[0]["after"][key] or
                    binding["profile"][key] != selected_profiles[0]["after"][key] or
                    staged_profiles[0]["selected"][key] != selected_profiles[0]["after"][key]
                    for key in ("bytes", "sha256"))):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_TARGET_PROFILE_IDENTITY")
            selected_inputs.append(layout_path)
        elif any(identity(profile)[key] != contract["profile"][key] or
                 binding["profile"][key] != contract["profile"][key]
               for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
        for field, expected in (("targetConfig", contract["inputs"]["targetConfig"]),
                                ("buildConfig", contract["inputs"]["buildConfig"])):
            if any(binding[field][key] != expected[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_KMI_CONFIG_BINDING:" + field)
        return [receipt_path, contract_path, profile, *selected_inputs, Path(__file__).with_name("target_kmi.py"),
                *[kmi.reference_path(row) for row in contract["inputs"].values()],
                kmi.reference_path(contract["targetSymvers"], contract_path.resolve().parent)]
    if kernel_source is None:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_ROOT_REQUIRED")
    reference = binding["ownerSelection"]
    owner_path = repo / reference["repositoryPath"] if "repositoryPath" in reference else Path(reference["path"])
    if any(identity(owner_path)[key] != reference[key] for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_OWNER_IDENTITY")
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    if binding["kernelProfile"] != owner["kernelProfile"]:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_GENERATION")
    expected_profile = [row["after"] for row in owner["kernelFiles"]
                        if row["logicalPath"] == "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h"]
    if len(expected_profile) != 1 or any(identity(profile)[key] != expected_profile[0][key] or
                                       binding["profile"][key] != expected_profile[0][key]
                                       for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
    if any(identity(kdir / ".config")[key] != owner["targetConfig"][key] or
           binding["targetConfig"][key] != owner["targetConfig"][key] for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_CONFIG_MISMATCH")
    source_files = binding["sourceFiles"]
    if sorted(row["repositoryPath"] for row in source_files) != sorted(TARGET_PROFILE_SOURCES):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT")
    actual_sources = []
    for row in source_files:
        declared = [item for item in owner["targetSourceFiles"]
                    if item["path"].replace("\\", "/").endswith("/" + row["repositoryPath"])]
        if len(declared) != 1 or any(row["actual"][key] != declared[0][key] or
                                   row["declared"][key] != declared[0][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + row["repositoryPath"])
        path = kernel_source / row["repositoryPath"]
        actual = identity(path)
        if any(actual[key] != declared[0][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + row["repositoryPath"])
        actual_sources.append(path)
    return [receipt_path, owner_path, profile, *actual_sources]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "kernel-build", "llvm-bin", "module-source", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--kernel-source", type=Path)
    parser.add_argument("--target-contract", type=Path)
    parser.add_argument("--modpost", type=Path)
    parser.add_argument("--legacy-direct-v2", action="store_true")
    parser.add_argument("--python-dependency-root", type=Path)
    parser.add_argument("--python-dependency-manifest", type=Path)
    parser.add_argument("--python-dependency-manifest-sha256")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--object", action="append", default=[])
    args = parser.parse_args()
    kdir, source = args.kernel_build.resolve(), args.module_source.resolve()
    if any(not re.fullmatch(r"(?:host/|producer/module/)?[a-zA-Z0-9_]+\.o", name) for name in args.object):
        raise ValueError("ULTRA_BRIDGE_OBJECT_TARGET")
    component_only = args.native_only or bool(args.object)
    direct = None
    if args.legacy_direct_v2:
        if component_only or not args.modpost or not args.kernel_source or not all((
                args.python_dependency_root, args.python_dependency_manifest, args.python_dependency_manifest_sha256)):
            raise ValueError("ULTRA_BRIDGE_DIRECT_V2_BUILD_ARGUMENTS")
        spec = importlib.util.spec_from_file_location("bridge_direct_modpost", Path(__file__).with_name("legacy_direct_modpost.py"))
        direct = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(direct)
        # KMI validation may itself parse ELF. Select and validate the frozen
        # dependency before any such import, not after target selection.
        direct_dependencies = direct.dependency(args.python_dependency_root.resolve(), args.python_dependency_manifest.resolve(),
                                                args.python_dependency_manifest_sha256)
    elif any((args.python_dependency_root, args.python_dependency_manifest, args.python_dependency_manifest_sha256)):
        raise ValueError("ULTRA_BRIDGE_DIRECT_V2_BUILD_ARGUMENTS")
    targets = args.object or (["native_layout.o", "native_lookup.o"] if args.native_only else ["modules"])
    outputs = [source / name for name in (targets if component_only else ["maplesu_ultra_bridge.ko"])]
    if any(path.exists() for path in outputs):
        raise ValueError("ULTRA_BRIDGE_OUTPUT_EXISTS: use an independent source-only build directory")
    kbuild = source / "Kbuild"
    selected = [Path(__file__).resolve(), kbuild, kdir / ".config", kdir / "include/generated/utsrelease.h",
                *[path.resolve() for path in args.source]]
    selected.extend(staged_target_inputs(source, kdir, args.repo_root.resolve(),
                                         args.kernel_source.resolve() if args.kernel_source else None,
                                         args.target_contract.resolve() if args.target_contract else None))
    if direct is not None:
        kernel_source = args.kernel_source.resolve()
        rule_path = kernel_source / "scripts/Makefile.modpost"
        rule = direct.rule_expression(rule_path)
        rule_family = direct.RULE_HASHES[identity(rule_path)["sha256"]]
        modpost_source = kernel_source / "scripts/mod/modpost.c"
        if identity(modpost_source)["sha256"] != direct.MODPOST_SOURCE_HASHES[rule_family]:
            raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_SOURCE_IDENTITY")
        config = (kdir / ".config").read_text(encoding="utf-8")
        if not re.search(r"^CONFIG_MODVERSIONS=y$", config, re.M):
            raise ValueError("ULTRA_BRIDGE_DIRECT_MODVERSIONS_REQUIRED")
        selected.extend([Path(__file__).resolve(), Path(direct.__file__).resolve(),
                         Path(__file__).with_name("legacy_direct.py"), kernel_source / "Makefile", rule_path, modpost_source,
                         *direct.staged_sources(source), *direct_dependencies])
    vmlinux = kdir / "vmlinux"
    vmlinux_present = vmlinux.is_file()
    if not component_only:
        # Modpost needs the real exports. Bare modules can skip BTF without
        # vmlinux; a successful link still supplies no target/BTF qualification.
        selected.append(kdir / "Module.symvers")
        if vmlinux_present:
            selected.append(vmlinux)
        if not re.search(r"^obj-m\s*(?::=|\+=|=).*\bmaplesu_ultra_bridge\.o\b",
                         kbuild.read_text(), re.M):
            raise ValueError("ULTRA_BRIDGE_MODULE_PROVIDER_REQUIRED: see bridge-provider-gap.md")
    tool = args.llvm_bin.resolve()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    strict_modpost = None
    if direct is not None:
        spec = importlib.util.spec_from_file_location("bridge_strict_modpost", Path(__file__).with_name("strict_modpost.py"))
        strict = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(strict)
        strict_modpost = strict.prepare(kernel_source, kdir, args.modpost.resolve(), tool / "clang",
                                        rule_family, evidence / "strict-modpost")
        selected.extend(strict_modpost["inputs"])
    before = [identity(path) for path in dict.fromkeys(selected)]
    tools = [identity(tool / name) for name in ("clang", "ld.lld", "llvm-nm")]
    if not component_only:
        tools.append(identity(tool / "llvm-strip"))
    if args.modpost:
        tools.append(identity(args.modpost.resolve()))
    if direct is not None:
        tools.append(identity(Path(sys.executable).resolve()))
        tools.extend(identity(path) for path in [*strict_modpost["tools"], strict_modpost["tool"]])
    command = ["make", "-C", str(kdir), "M=" + str(source), "ARCH=arm64",
               "LLVM=" + str(tool) + "/", "MAPLESU_REPO_ROOT=" + str(args.repo_root.resolve()),
               "V=1"]
    request_path = evidence / "DIRECT-MODPOST-REQUEST.json"
    if direct is not None:
        request = {"schema": "maplesu-direct-v2-modpost-request/1", "moduleSource": str(source),
                   "ruleFamily": rule_family,
                   "rules": identity(rule_path), "modpostSource": identity(modpost_source),
                   "kernelBuild": str(kdir), "parser": identity(Path(__file__).with_name("legacy_direct.py")),
                   "modpost": identity(strict_modpost["tool"]), "inputs": [*before, *tools],
                   "strictModpost": identity(strict_modpost["receipt"]),
                   "dependencyRoot": str(args.python_dependency_root.resolve()),
                   "dependencyManifest": identity(args.python_dependency_manifest.resolve()),
                   "receipt": str(evidence / "DIRECT-MODPOST.json")}
        with request_path.open("x", encoding="utf-8") as stream:
            json.dump(request, stream, indent=2)
            stream.write("\n")
        # Enter the explicitly selected source tree so its frozen rule executes;
        # CONFIG/automatic variables remain evaluated in that original recipe.
        command[2] = str(kernel_source)
        command.extend(["O=" + str(kdir), "MODPOST=" + direct.make_command(Path(direct.__file__).resolve(), request_path, rule),
                        "KBUILD_MODPOST_WARN="])
    elif args.modpost:
        command.extend(["MODPOST=" + str(args.modpost.resolve()), "KBUILD_MODPOST_WARN="])
    command.extend(targets)
    with (evidence / "stdout.log").open("wb") as stdout, (evidence / "stderr.log").open("wb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    after = [identity(Path(row["path"])) for row in before]
    tools_after = [identity(Path(row["path"])) for row in tools]
    receipt = {"command": command, "exitCode": result.returncode, "sources": before,
               "tools": tools, "inputsUnchanged": before == after and tools == tools_after and
               (component_only or vmlinux.is_file() == vmlinux_present),
               "nativeComponentsOnly": component_only, "targetQualified": False,
               "targetVmlinuxCaptured": not component_only and vmlinux_present,
               "targetBtfQualified": False,
               "deviceOperations": False, "sdkOrSuQualified": False}
    validation_error = None
    strip_exit = 0
    if result.returncode == 0 and receipt["inputsUnchanged"] and not component_only and outputs[0].is_file():
        receipt["stripDebug"], strip_exit = strip_module_debug(outputs[0], tool / "llvm-strip", evidence)
        receipt["inputsUnchanged"] = (before == [identity(Path(row["path"])) for row in before] and
                                      tools == [identity(Path(row["path"])) for row in tools] and
                                      vmlinux.is_file() == vmlinux_present)
        if strip_exit:
            receipt["exitCode"] = strip_exit
    if direct is not None:
        receipt["legacyDirectV2"] = {"request": identity(request_path), "finalModuleVerified": False,
                                     "fixedRuleFamily": rule_family, "strictModpost": identity(strict_modpost["receipt"])}
        try:
            if result.returncode == 0 and strip_exit == 0:
                preflight_path = evidence / "DIRECT-MODPOST.json"
                preflight = json.loads(preflight_path.read_bytes())
                if preflight.get("exitCode") != 0 or not preflight.get("inputsUnchanged") or not preflight.get("onlyExactAliasDiagnostics"):
                    raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_RECEIPT")
                if any(identity(Path(row["path"])) != row for row in preflight["symvers"]):
                    raise ValueError("ULTRA_BRIDGE_DIRECT_SYMVERS_CHANGED")
                releases = re.findall(r'^#define UTS_RELEASE "([^"\r\n]+)"$',
                                      (kdir / "include/generated/utsrelease.h").read_text(), re.M)
                if len(releases) != 1:
                    raise ValueError("ULTRA_BRIDGE_DIRECT_BUILD_RELEASE")
                final = direct.final_module(outputs[0].read_bytes(), direct.load_parser(direct.checked(request["parser"])),
                                            preflight, [Path(row["path"]) for row in preflight["symvers"]], releases[0])
                receipt["legacyDirectV2"].update(finalModuleVerified=True, preflight=identity(preflight_path), final=final)
        except (ValueError, KeyError, OSError) as error:
            validation_error = error
            receipt["legacyDirectV2"]["validationError"] = str(error)
    if (result.returncode == 0 and strip_exit == 0 and validation_error is None and
            receipt["inputsUnchanged"] and all(path.is_file() for path in outputs)):
        receipt["artifacts"] = [identity(path) for path in outputs]
    (evidence / "BUILD.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if result.returncode:
        raise SystemExit(result.returncode)
    if strip_exit:
        raise SystemExit(strip_exit)
    if not receipt["inputsUnchanged"]:
        raise ValueError("ULTRA_BRIDGE_BUILD_INPUT_CHANGED")
    if validation_error is not None:
        raise validation_error
    if "artifacts" not in receipt:
        raise ValueError("ULTRA_BRIDGE_KBUILD_OUTPUT_MISSING")


if __name__ == "__main__":
    main()
