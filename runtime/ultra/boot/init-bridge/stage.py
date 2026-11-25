#!/usr/bin/env python3
"""Select exact source-only inputs for one independent native module build.

No compiler, build, tests, device, whole-tree copy, link or toolchain copy runs
here. The producer is always selected at its original repository-relative path.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re


HOST_RUNTIME_UNITS = ("manager_installation_state", "manager_su_runtime_factory", "manager_su_gate",
                      "manager_su_runtime_target", "su_observed_install_source",
                      "su_durable_authority", "su_durable_modern")
EARLY_RUNTIME_UNITS = ("manager_early_fixed", "manager_early_oem", "manager_early_root",
                       "manager_early_selinux", "manager_early_runtime_factory",
                       "manager_early_root_backend", "manager_early_selinux_backend")
TARGET_PROFILE_SOURCES = ("fs/exec.c", "fs/stat.c", "fs/open.c",
                          "arch/arm64/include/asm/syscall_wrapper.h",
                          "arch/arm64/include/asm/ptrace.h", "include/linux/binfmts.h")
RUNTIME_FACT_UNITS = ("manager_runtime_btf", "manager_runtime_accessor", "manager_task_profile_runtime")
RUNTIME_FACT_HEADERS = ("manager_task_profile_workbit.h",)


def identity(path, data=None):
    if data is None:
        data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def seccomp_release_traits(source):
    clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", source.decode("utf-8"), flags=re.S)
    declarations = list(re.finditer(r"\bvoid\s+seccomp_filter_release\s*\(\s*struct\s+task_struct\s*\*\s*tsk\s*\)\s*\{", clean))
    if len(declarations) != 1:
        raise ValueError("ULTRA_BRIDGE_SECCOMP_RELEASE_BODY_DECLARATION")
    begin, at, depth = declarations[0].end(), declarations[0].end(), 1
    while depth and at < len(clean):
        depth += (clean[at] == "{") - (clean[at] == "}")
        at += 1
    if depth:
        raise ValueError("ULTRA_BRIDGE_SECCOMP_RELEASE_BODY_BOUNDS")
    body = clean[begin:at - 1]
    compact = re.sub(r"\s+", "", body)
    locking = "spin_lock_irq(&tsk->sighand->siglock);" in compact
    unlocking = "spin_unlock_irq(&tsk->sighand->siglock);" in compact
    exiting = "WARN_ON((tsk->flags&PF_EXITING)==0)" in compact
    fields = set(re.findall(r"\btsk\s*->\s*(\w+)", body))
    seccomp_fields = set(re.findall(r"\btsk\s*->\s*seccomp\s*\.\s*(\w+)", body))
    if locking != unlocking or (locking and not exiting) or fields - {"flags", "sighand", "seccomp"} or seccomp_fields != {"filter"}:
        raise ValueError("ULTRA_BRIDGE_SECCOMP_RELEASE_TASK_CONTRACT")
    if "sighand" in fields and not locking and "WARN_ON(tsk->sighand!=NULL);" not in compact:
        raise ValueError("ULTRA_BRIDGE_SECCOMP_RELEASE_SIGHAND_CONTRACT")
    if any(token not in compact for token in
           ("orig=tsk->seccomp.filter;", "tsk->seccomp.filter=NULL;", "__seccomp_filter_release(orig);")):
        raise ValueError("ULTRA_BRIDGE_SECCOMP_RELEASE_DETACH_CONTRACT")
    return {"locksTask": locking, "requiresPfExiting": exiting,
            "taskFields": sorted(fields), "seccompFields": sorted(seccomp_fields),
            "bodySha256": hashlib.sha256(body.encode("utf-8")).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "host-overlay", "core-overlay", "su-overlay", "kernel-source",
                 "kernel-build", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--core-selection", type=Path)
    parser.add_argument("--host-selection", type=Path)
    parser.add_argument("--runtime-candidate", type=Path)
    parser.add_argument("--runtime-successor", type=Path, action="append", default=[])
    parser.add_argument("--target-kmi", type=Path)
    parser.add_argument("--require-resident-text-owner-kmi", action="store_true")
    parser.add_argument("--su-selection", type=Path, action="append", default=[])
    parser.add_argument("--runtime-layout-source-selection", type=Path)
    parser.add_argument("--runtime-layout-source-selection-sha256")
    parser.add_argument("--runtime-facts", action="store_true",
                        help="Select boot-time fact producers for an independent KMI component")
    parser.add_argument("--seccomp-source-selection", type=Path)
    parser.add_argument("--seccomp-source-selection-sha256")
    args = parser.parse_args()
    if args.require_resident_text_owner_kmi and not args.target_kmi:
        raise ValueError("ULTRA_BRIDGE_KMI_RESIDENT_TARGET_REQUIRED")
    candidate = Path(__file__).resolve().parents[4]
    output = args.out.resolve()
    if output.exists():
        raise ValueError("ULTRA_BRIDGE_STAGE_OUTPUT_EXISTS")
    rows, content, generated_from = [], {}, []
    bindings, formal_selections = {}, {}
    runtime_selection, su_selections = {}, []
    su_source_evolution = []
    core_successors, runtime_successors = {}, []
    formal_runtime, initialization_child, runtime_su, target_binding = False, False, {}, {}

    def capture_bytes(path):
        data = path.read_bytes()
        generated_from.append(identity(path, data))
        return data

    def capture(path):
        return capture_bytes(path).decode("utf-8")

    def resolve_reference(reference):
        path = Path(reference["path"])
        return path if path.is_absolute() else args.repo_root.resolve() / path

    def checked_reference(reference):
        data = capture_bytes(resolve_reference(reference))
        if any(generated_from[-1][key] != reference[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_SELECTION_REFERENCE_IDENTITY:" + reference["path"])
        return data

    if args.runtime_candidate and (not args.core_selection or not args.su_selection):
        raise ValueError("ULTRA_BRIDGE_RUNTIME_FORMAL_INPUTS")
    if bool(args.core_selection) != bool(args.host_selection):
        raise ValueError("ULTRA_BRIDGE_DEPLOYMENT_SELECTION_PAIR")
    if args.core_selection:
        core = json.loads(capture(args.core_selection))
        core_identity = generated_from[-1]
        current_core = "sourceFreeze" in core
        freeze_ref = core["sourceFreeze"] if current_core else core["ownerFreezeIdentity"]
        freeze = json.loads(capture(resolve_reference(freeze_ref)))
        if any(generated_from[-1][key] != freeze_ref[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_CORE_FREEZE_IDENTITY")
        source_root = Path(freeze["sourceRoot"])
        if not source_root.is_absolute():
            source_root = args.repo_root.resolve() / source_root
        if source_root.resolve() != args.core_overlay.resolve():
            raise ValueError("ULTRA_BRIDGE_CORE_SOURCE_ROOT")
        if current_core:
            frozen_core = {row["path"]: row for row in freeze["files"]}
            for row in core["files"]:
                relative, reference = row["logicalPath"], row["selected"]
                if relative not in frozen_core or any(reference[key] != frozen_core[relative][key]
                                                       for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_CORE_SUCCESSOR_FREEZE_MEMBER:" + relative)
                core_successors[relative] = (reference, "core-owner-freeze")
        else:
            for row in core["nativeInputs"] + core["supportInputs"]:
                bindings[row["logicalPath"]] = (row["snapshotIdentity"], "core-native-selection")
            for row in core["files"]:
                bindings[row["logicalPath"]] = (row["ownerSelected"], "core-owner-freeze")
        host_selection_bytes = capture_bytes(args.host_selection)
        host_selection = json.loads(host_selection_bytes)
        if current_core:
            if not args.runtime_candidate:
                raise ValueError("ULTRA_BRIDGE_CORE_SUCCESSOR_REQUIRES_RUNTIME")
            # The old checkpoint keeps its true predecessor; it is not rewritten
            # to claim CORE73. Only exact per-path successors are applied below.
            checked_reference(host_selection["corePredecessor"])
        elif any(host_selection["corePredecessor"][key] != core_identity[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_HOST_CORE_GENERATION")
        # The real HOST selection's files.after includes its corrected config2 TU.
        for row in host_selection["files"]:
            bindings[row["logicalPath"]] = (row["after"], "host-final-after")
        host_identity = identity(args.host_selection, host_selection_bytes)
        formal_selections = {"core": core_identity, "freeze": freeze_ref, "host": host_identity}
        if host_selection.get("runtimeChannel") and not args.runtime_candidate:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_CANDIDATE_REQUIRED")

    if args.runtime_candidate:
        runtime = json.loads(capture(args.runtime_candidate))
        runtime_identity = generated_from[-1]
        runtime_path, builder_successors, seen_builders = args.runtime_candidate.resolve(), [], set()
        late_successors = []
        late_schemas = {"maplesu-host-sync-builder-candidate/1": "sync",
                        "maplesu-host-retirement-candidate/1": "retirement",
                        "maplesu-host-btf-variable-producer-candidate/1": "producer"}
        while runtime.get("schema") in late_schemas:
            if runtime_path in seen_builders:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_BUILDER_PARENT_CYCLE")
            seen_builders.add(runtime_path)
            late_successors.append({"candidate": runtime, "mode": late_schemas[runtime["schema"]]})
            runtime_path = resolve_reference(runtime["parentCandidate"])
            runtime = json.loads(checked_reference(runtime["parentCandidate"]))
        while runtime.get("schema") in ("maplesu-host-sdk-current-task-intake-candidate/1",
                                         "maplesu-host-publication-builder-candidate/1"):
            if runtime_path in seen_builders:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_BUILDER_PARENT_CYCLE")
            seen_builders.add(runtime_path)
            successor = runtime
            successor_freeze = json.loads(checked_reference(successor["sourceFreeze"]))
            parent = json.loads(checked_reference(successor["parentCandidate"]))
            if any(successor_freeze["parentCandidate"][key] != successor["parentCandidate"][key] or
                   successor_freeze["parentFreeze"][key] != parent["sourceFreeze"][key]
                   for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_BUILDER_PARENT_FREEZE")
            checked_reference(successor_freeze["parentFreeze"])
            members = list(successor_freeze["files"])
            if "factoryFreeze" in successor_freeze:
                factory_freeze = json.loads(checked_reference(successor_freeze["factoryFreeze"]))
                if any(factory_freeze["parentCandidate"][key] != successor["parentCandidate"][key]
                       for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_PUBLICATION_PREDECESSOR")
                members += factory_freeze["files"]
            effective_refs = [row for row in members
                              if resolve_reference(row).name == "EFFECTIVE-SOURCE-SELECTION.json" and
                              resolve_reference(row).parent == runtime_path.parent]
            if len(effective_refs) != 1:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_EFFECTIVE_SELECTION")
            successor_effective = effective_refs[0]
            if "effectiveSelection" in successor and any(successor["effectiveSelection"][key] != successor_effective[key]
                                                         for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
            builder_successors.append({"candidate": successor, "freeze": successor["sourceFreeze"],
                "members": members, "effectiveReference": successor_effective,
                "effective": json.loads(checked_reference(successor_effective)),
                "emission": json.loads(checked_reference(successor["sourceEmission"]))})
            runtime_path = resolve_reference(successor["parentCandidate"])
            runtime = parent
        if builder_successors and runtime.get("schema") != "maplesu-host-initialization-child-candidate/1":
            raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_PARENT_REQUIRED")
        initialization_child = runtime.get("schema") == "maplesu-host-initialization-child-candidate/1"
        formal_runtime = initialization_child or runtime.get("schema") == "maplesu-host-runtime-successor-candidate/1"
        runtime_freeze = runtime["freeze"] if formal_runtime and not initialization_child else runtime["sourceFreeze"]
        frozen = json.loads(checked_reference(runtime_freeze))
        if initialization_child:
            parent = json.loads(checked_reference(runtime["parentCandidate"]))
            if any(parent["freeze"][key] != frozen["parentFreeze"][key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PARENT_FREEZE")
            parent_freeze = json.loads(checked_reference(frozen["parentFreeze"]))
            frozen_sources = parent_freeze["sourceInputs"] + frozen["ownedSources"]
            frozen_members = frozen_sources + parent_freeze["localReceipts"] + frozen["receipts"]
            effective_refs = [row for row in frozen["receipts"]
                              if resolve_reference(row).name == "EFFECTIVE-SOURCE-SELECTION.json" and
                              resolve_reference(row).parent == runtime_path.parent]
            if len(effective_refs) != 1:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_EFFECTIVE_SELECTION")
            effective_ref, emission_ref = effective_refs[0], runtime["sourceEmission"]
            fields = ("builder", "initializationSelection", "sourceEmission", "status")
        else:
            frozen_sources = frozen["sourceInputs"] if formal_runtime else frozen["files"]
            frozen_members = frozen_sources + frozen.get("localReceipts", [])
            fields = ("builder", "effectiveSelection", "finalEmission") if formal_runtime else ("selection", "sourceEmission")
            if formal_runtime:
                effective_ref, emission_ref = runtime["effectiveSelection"], runtime["finalEmission"]
        for reference in frozen_sources:
            checked_reference(reference)
        for field in fields:
            reference = runtime[field]
            if not any(resolve_reference(row) == resolve_reference(reference) and
                       all(row[key] == reference[key] for key in ("bytes", "sha256"))
                       for row in frozen_members):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_FREEZE_MEMBER:" + field)
        if formal_runtime:
            checked_reference(runtime["builder"])
            effective = json.loads(checked_reference(effective_ref))
            final_emission = json.loads(checked_reference(emission_ref))
            if initialization_child:
                status = json.loads(checked_reference(runtime["status"]))
                initialization_reference = runtime["initializationSelection"]
                initialized = json.loads(checked_reference(initialization_reference))
                parent_effective = json.loads(checked_reference(parent["effectiveSelection"]))
                if any(initialized["parentCandidate"][key] != runtime["parentCandidate"][key] or
                       initialized["parentSourceSelection"][key] != parent["effectiveSelection"][key]
                       for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_PREDECESSOR")
                expected_native = {resolve_reference(row).name: row for row in parent_effective["native"]}
                for row in initialized["kernelFiles"]:
                    name = Path(row["logicalPath"]).name
                    previous = expected_native.get(name)
                    if bool(previous) != bool(row["before"]) or previous and any(
                            previous[key] != row["before"][key] for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_PREDECESSOR:" + name)
                    expected_native[name] = row["after"]
                if len(expected_native) != len(effective["native"]) or any(
                        resolve_reference(row).name not in expected_native or any(
                            row[key] != expected_native[resolve_reference(row).name][key] for key in ("bytes", "sha256"))
                        for row in effective["native"]):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_NATIVE_GENERATION")
                ready = status.get("parentAllFrozenInputsStable") and status.get("nativeSuStartupCallerImplemented")
            else:
                ready = runtime.get("sourceIntegrationComplete")
            if not ready or not final_emission.get("actualBuildPrefixExecuted"):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_NOT_READY")
            for child in reversed(builder_successors):
                successor_candidate = child["candidate"]
                previous_effective, previous_reference = effective, effective_ref
                frozen_sources += child["members"]
                frozen_members += child["members"]
                fields = [successor_candidate["builder"], successor_candidate["sourceEmission"], successor_candidate["status"],
                          successor_candidate["sdkOwnedInventory"], child["effectiveReference"]]
                publication = successor_candidate.get("publicationSelection")
                selection = publication or successor_candidate["sdkCurrentTaskSelection"]
                fields.append(selection)
                for reference in fields:
                    if not any(resolve_reference(row) == resolve_reference(reference) and
                               all(row[key] == reference[key] for key in ("bytes", "sha256"))
                               for row in frozen_members):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_FREEZE_MEMBER:" + reference["path"])
                    checked_reference(reference)
                effective, effective_ref = child["effective"], child["effectiveReference"]
                final_emission, emission_ref = child["emission"], successor_candidate["sourceEmission"]
                expected_native = {resolve_reference(row).name: row for row in previous_effective["native"]}
                if publication:
                    selected_publication = json.loads(checked_reference(publication))
                    if any(selected_publication["parentCandidate"][key] != successor_candidate["parentCandidate"][key] or
                           selected_publication["parentEffectiveSelection"][key] != previous_reference[key] or
                           selected_publication["initializationSelection"][key] != initialization_reference[key]
                           for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_PUBLICATION_PREDECESSOR")
                    for row in selected_publication["files"]:
                        name = Path(row["logicalPath"]).name
                        previous = expected_native.get(name)
                        if not previous or any(previous[key] != row["before"][key] for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_PUBLICATION_PREDECESSOR:" + name)
                        expected_native[name] = row["after"]
                    evolution = effective["hostPublicationSourceEvolution"]["identity"]
                else:
                    evolution = effective["sdkCurrentTaskSourceEvolution"]["identity"]
                if any(evolution[key] != selection[key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_BUILDER_SELECTION_GENERATION")
                if len(expected_native) != len(effective["native"]) or any(
                        resolve_reference(row).name not in expected_native or any(
                            row[key] != expected_native[resolve_reference(row).name][key] for key in ("bytes", "sha256"))
                        for row in effective["native"]):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_NATIVE_GENERATION")
                for field in ("support", "su"):
                    previous = sorted((resolve_reference(row).name, row["bytes"], row["sha256"])
                                      for row in previous_effective.get(field, []))
                    current = sorted((resolve_reference(row).name, row["bytes"], row["sha256"])
                                     for row in effective.get(field, []))
                    if previous != current:
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_BUILDER_MEMBER_CHANGED:" + field)
                if any(effective["protocol"][key] != previous_effective["protocol"][key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_PROTOCOL_GENERATION")
                if not final_emission.get("actualBuildPrefixExecuted") or final_emission["sourceFiles"] != len(effective["native"]) or any(
                        document["builder"][key] != successor_candidate["builder"][key]
                        for document in (effective, final_emission) for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
                runtime, runtime_freeze = successor_candidate, child["freeze"]
            producer_only, late_selections = False, []
            for child in reversed(late_successors):
                successor, mode = child["candidate"], child["mode"]
                parent = json.loads(checked_reference(successor["parentCandidate"]))
                if any(parent["effectiveSelection"][key] != effective_ref[key] or
                       parent["builder"][key] != effective["builder"][key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_PARENT")
                previous_effective, previous_reference = effective, effective_ref
                effective_ref = successor["effectiveSelection"]
                effective = json.loads(checked_reference(effective_ref))
                checked_reference(successor["builder"])
                status = json.loads(checked_reference(successor["status"]))
                if any(effective["builder"][key] != successor["builder"][key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
                expected = {field: {resolve_reference(row).name: row for row in previous_effective.get(field, [])}
                            for field in ("native", "support", "su")}
                expected_protocol = previous_effective["protocol"]
                if mode in ("sync", "retirement"):
                    selection_ref = successor["sourceSelection"]
                    selection = json.loads(checked_reference(selection_ref))
                    if any(selection["parentCandidate"][key] != successor["parentCandidate"][key] or
                           selection["parentEffectiveSelection"][key] != previous_reference[key]
                           for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_PREDECESSOR")
                    sdk_expected, sdk_ref = {}, None
                    if mode == "sync":
                        prior_sdk_ref = runtime.get("sdkInventory") or runtime.get("sdkOwnedInventory")
                        if not prior_sdk_ref or any(selection["parentSdkInventory"][key] != prior_sdk_ref[key]
                                                    for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_SDK_PARENT")
                        sdk_parent = json.loads(checked_reference(prior_sdk_ref))
                        sdk_expected = {row["logicalPath"]: row["selected"] for row in sdk_parent["files"]}
                        sdk_ref = successor["sdkInventory"]
                        sdk = json.loads(checked_reference(sdk_ref))
                        if any(effective["sdkInventory"][key] != sdk_ref[key] for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_SDK_GENERATION")
                    seen = set()
                    for row in selection["files"]:
                        logical, before, after = row["logicalPath"], row["before"], row["after"]
                        name = Path(logical).name
                        if logical in seen:
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_DUPLICATE:" + logical)
                        seen.add(logical)
                        if logical == "runtime/ultra/authorization/request_protocol.h":
                            previous, expected_protocol = expected_protocol, after
                        elif logical.startswith("runtime/ultra/identity/kernel/"):
                            groups = [field for field in expected if name in expected[field]]
                            if not groups:
                                raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_MEMBER:" + logical)
                            previous = expected[groups[0]][name]
                            for group in groups:
                                if any(expected[group][name][key] != previous[key] for key in ("bytes", "sha256")):
                                    raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_PREDECESSOR:" + logical)
                                expected[group][name] = after
                        elif logical.startswith("runtime/maplesu-sdk/") and logical in sdk_expected:
                            previous, sdk_expected[logical] = sdk_expected[logical], after
                        else:
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_MEMBER:" + logical)
                        if any(before[key] != previous[key] for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_PREDECESSOR:" + logical)
                        checked_reference(after)
                        frozen_sources.append(after)
                    evolution_name = "hostSyncSourceEvolution" if mode == "sync" else "hostRetirementSourceEvolution"
                    if any(effective[evolution_name]["identity"][key] != selection_ref[key] for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_SELECTION_GENERATION")
                    if sdk_ref:
                        actual_sdk = {row["logicalPath"]: row["selected"] for row in sdk["files"]}
                        if actual_sdk.keys() != sdk_expected.keys() or any(
                                actual_sdk[name][key] != row[key] for name, row in sdk_expected.items() for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_SDK_GENERATION")
                    else:
                        freeze = json.loads(checked_reference(successor["sourceFreeze"]))
                        if any(freeze["builder"][key] != successor["builder"][key] or
                               freeze["selection"][key] != selection_ref[key] or
                               freeze["effective"][key] != effective_ref[key] for key in ("bytes", "sha256")):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_FREEZE")
                        if sorted((row["bytes"], row["sha256"]) for row in freeze["files"]) != sorted(
                                (row["after"]["bytes"], row["after"]["sha256"]) for row in selection["files"]):
                            raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_FREEZE")
                    final_emission = json.loads(checked_reference(successor["sourceEmission"]))
                    if (not successor.get("sourceSelectedInIsolatedBuilder") or
                            not final_emission.get("actualBuildPrefixExecuted") or any(
                                final_emission["builder"][key] != successor["builder"][key] for key in ("bytes", "sha256"))):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_NOT_READY")
                    emission_ref = successor["sourceEmission"]
                    late_selections.append(selection_ref)
                else:
                    freeze = json.loads(checked_reference(successor["sourceFreeze"]))
                    collector = json.loads(checked_reference(successor["mainCollectorSuccessor"]))
                    validation = json.loads(checked_reference(successor["sourceValidation"]))
                    if any(freeze["parentCandidate"][key] != successor["parentCandidate"][key] or
                           freeze["mainCollectorCandidate"][key] != successor["mainCollectorSuccessor"][key] or
                           freeze["beforeBuilder"][key] != collector["candidateBuilder"][key] or
                           freeze["afterBuilder"][key] != successor["builder"][key] or
                           freeze["effectiveSelection"][key] != effective_ref[key] or
                           freeze["validation"][key] != successor["sourceValidation"][key] or
                           collector["owner"][key] != parent["builder"][key] for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_PRODUCER_PARENT")
                    for field in ("beforeBuilder", "archivedBefore", "afterBuilder", "sourceDiff", "completeR7Delta", "actualEvidence"):
                        checked_reference(freeze[field])
                    checked_reference(collector["candidateCollector"])
                    checked_reference(collector["validationExecution"])
                    evolution = effective["hostProducerEvolution"]
                    if (not status.get("sourcePrepared") or not status.get("sourceValidationPassed") or
                            not validation.get("descriptorAbiAstUnchanged") or freeze.get("nativeSourcesChanged") is not False or
                            collector.get("status") != "PASS_ACTUAL_R7_DEPENDENCIES" or any(
                                evolution["parentCandidate"][key] != successor["parentCandidate"][key] or
                                evolution["dependencyCollectorSuccessor"][key] != successor["mainCollectorSuccessor"][key] or
                                evolution["sourceValidation"][key] != successor["sourceValidation"][key]
                                for key in ("bytes", "sha256"))):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_PRODUCER_NOT_READY")
                    producer_only = True
                for field in expected:
                    current = {resolve_reference(row).name: row for row in effective.get(field, [])}
                    if len(current) != len(effective.get(field, [])) or current.keys() != expected[field].keys() or any(
                            current[name][key] != row[key] for name, row in expected[field].items() for key in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_RUNTIME_LATE_MEMBER_CHANGED:" + field)
                if any(effective["protocol"][key] != expected_protocol[key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_PROTOCOL_GENERATION")
                if "sourceFreeze" in successor:
                    runtime_freeze = successor["sourceFreeze"]
                runtime = successor
            if builder_successors and not any(row["selector"] == "select_host_initialization_sources" and
                    all(row["selection"][key] == initialization_reference[key] for key in ("bytes", "sha256"))
                    for row in effective["layers"]):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_INITIALIZATION_GENERATION")
            if any(document["builder"][key] != runtime["builder"][key]
                   for document in ((effective,) if producer_only else (effective, final_emission)) for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
            if not any(row["selector"] == "select_host_deployment_sources" and
                       all(row["selection"][key] == host_identity[key] for key in ("bytes", "sha256"))
                       for row in effective["layers"]):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_HOST_GENERATION")
            sources = {resolve_reference(row): row for row in frozen_sources}
            for reference in effective["native"] + effective.get("support", []) + effective["su"] + [effective["protocol"]]:
                member = sources.get(resolve_reference(reference))
                if not member or any(member[key] != reference[key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_SOURCE_MEMBER:" + reference["path"])
                if builder_successors or late_successors:
                    checked_reference(reference)
            if final_emission.get("sourceFiles", len(effective["native"])) != len(effective["native"]):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
            runtime_su = {resolve_reference(row).name: row for row in effective["su"]}
            emission = {"selectedNativeInputs": effective["native"], "protocol": effective["protocol"],
                        "runtimeObjects": HOST_RUNTIME_UNITS}
        else:
            if any(runtime["selection"][key] != host_identity[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_HOST_GENERATION")
            emission = json.loads(checked_reference(runtime["sourceEmission"]))
            if any(emission["sourceSelection"][key] != host_identity[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_EMISSION_GENERATION")
        names = set()
        for reference in emission["selectedNativeInputs"]:
            name = resolve_reference(reference).name
            if name in names or (Path(name).suffix not in (".c", ".h") and name not in (
                    "manager_legacy_hook.inc", "manager_legacy_provider.inc")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_NATIVE_MEMBER:" + name)
            names.add(name)
            bindings["runtime/ultra/identity/kernel/" + name] = (reference,
                "host-runtime-successor-frozen" if formal_runtime else "host-runtime-frozen")
        if set(emission["runtimeObjects"]) != set(HOST_RUNTIME_UNITS):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_OBJECTS")
        for unit in HOST_RUNTIME_UNITS:
            required = (unit + ".c",) if unit == "manager_su_runtime_target" else (unit + ".c", unit + ".h")
            if not set(required).issubset(names):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_MEMBER_MISSING:" + unit)
        protocol = host_selection["protocolInput"]
        expected_protocol = (effective["protocol"] if formal_runtime and late_successors else
                             core_successors.get(protocol["logicalPath"], (protocol["after"],))[0] if formal_runtime else protocol["after"])
        if any(emission["protocol"][key] != expected_protocol[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_PROTOCOL_GENERATION")
        bindings[protocol["logicalPath"]] = (emission["protocol"], "host-runtime-protocol")
        for row in ([] if formal_runtime else host_selection["files"]):
            binding = bindings.get(row["logicalPath"])
            if binding and any(binding[0][key] != row["after"][key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_NATIVE_GENERATION:" + row["logicalPath"])
        for reference in host_selection.get("sourceCorrections", []):
            checked_reference(reference)
        runtime_selection = {"candidate": runtime_identity, "freeze": runtime_freeze,
                             "emission": emission_ref if formal_runtime else runtime["sourceEmission"]}
        if formal_runtime:
            runtime_selection["effectiveSelection"] = effective_ref
            if builder_successors:
                runtime_selection["builderSuccessors"] = [child["candidate"]["sourceFreeze"]
                                                           for child in reversed(builder_successors)]
                runtime_selection["sdkOwnedInventory"] = runtime.get("sdkOwnedInventory") or effective.get("sdkInventory")
            if late_successors:
                runtime_selection["laterSourceSelections"] = late_selections
                runtime_selection["sourceOnlyProducerSuccessor"] = producer_only

    # Keep the actual HOST protected-file/parser merge. New CORE owns session,
    # credential, helper metadata and shared protocol; old CORE54 cannot win.
    host_merged = {"install_records.c", "install_records.h", "protected_install_kernel.c",
                   "protected_install_kernel.h"}
    for relative, binding in core_successors.items():
        if Path(relative).name not in host_merged and not (formal_runtime and relative in bindings):
            bindings[relative] = binding
    if args.runtime_successor and not runtime_selection:
        raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_REQUIRES_RUNTIME")
    early_members = {"runtime/ultra/identity/kernel/" + unit + suffix
                     for unit in EARLY_RUNTIME_UNITS for suffix in (".c", ".h")}
    early_added = False
    successor_parent = effective_ref if formal_runtime else runtime_identity if runtime_selection else None
    for manifest in args.runtime_successor:
        selection = json.loads(capture(manifest))
        runtime_successors.append(generated_from[-1])
        if "priorSelection" in selection:
            checked_reference(selection["priorSelection"])
        if selection.get("schema") == "maplesu-init-bridge-runtime-source-successor/1" and (
                not successor_parent or not selection.get("priorSelection") or any(
                    selection["priorSelection"][key] != successor_parent[key] for key in ("bytes", "sha256"))):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_PARENT")
        for row in selection["files"]:
            relative = row["logicalPath"]
            previous = bindings.get(relative)
            protocol_successor = relative == "runtime/ultra/authorization/request_protocol.h"
            if (not relative.startswith("runtime/ultra/identity/kernel/") and not protocol_successor or
                    protocol_successor and "priorSelection" not in selection or not previous or not row.get("before") or any(
                    previous[0][key] != row["before"][key] for key in ("bytes", "sha256"))):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_PREDECESSOR:" + relative)
            bindings[relative] = (row["after"], "host-runtime-successor")
        for row in selection.get("addedFiles", []):
            relative = row["logicalPath"]
            if ("priorSelection" not in selection or relative not in early_members or
                    relative in bindings or row.get("before")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_ADDITION_CONTRACT:" + relative)
            bindings[relative] = (row["after"], "host-early-runtime-addition")
            early_added = True
        successor_parent = runtime_successors[-1]
    with_early_runtime = early_added or "runtime/ultra/identity/kernel/manager_early_runtime_factory.c" in bindings
    if with_early_runtime and not early_members.issubset(bindings):
        raise ValueError("ULTRA_BRIDGE_EARLY_RUNTIME_SOURCE_SET")

    su_prefix = "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/"
    session_receipt = "runtime/maplesu-sdk/sdk/src/payload/su/su_session_receipt.h"
    nonroot_units = ("su_nonroot_transition", "su_nonroot_transition_work", "su_nonroot_mount_source")
    nonroot_members = tuple("runtime/ultra/identity/kernel/" + unit + suffix
                            for unit in nonroot_units for suffix in (".c", ".h"))
    for manifest in args.su_selection:
        selection = json.loads(capture(manifest))
        su_selections.append(generated_from[-1])
        entries = selection.get("files", [selection])
        provider = None
        if "providerSelection" in selection:
            provider = json.loads(checked_reference(selection["providerSelection"]))
        for row in entries:
            relative = row["logicalPath"]
            if not relative.startswith(su_prefix) and relative != session_receipt and relative not in nonroot_members:
                continue
            reference = row.get("frozen") or row.get("source") or row.get("after") or row.get("candidate")
            if provider is not None:
                owned = next(item["after"] for item in provider["files"] if item["logicalPath"] == relative)
                if any(owned[key] != reference[key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_SU_PROVIDER_GENERATION:" + relative)
                reference = owned
            previous = bindings.get(relative)
            if previous and (not row.get("before") or
                    any(previous[0][key] != row["before"][key] for key in ("bytes", "sha256"))):
                raise ValueError("ULTRA_BRIDGE_SU_PREDECESSOR:" + relative)
            if row.get("before"):
                su_source_evolution.append({"logicalPath": relative, "before": row["before"],
                    "after": reference, "selection": su_selections[-1]})
            bindings[relative] = (reference, "su-formal-selection")
    for name, reference in runtime_su.items():
        # A reviewed source successor may evolve the exact frozen native
        # cohort. Keep the original parent proof and verify every child edge.
        for child in su_source_evolution:
            if child["logicalPath"] != su_prefix + name:
                continue
            if any(child["before"][key] != reference[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_SU_PREDECESSOR:" + name)
            checked_reference(child["before"])
            reference = child["after"]
        selected = bindings.get(su_prefix + name)
        if not selected or any(selected[0][key] != reference[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_SUCCESSOR_SU_GENERATION:" + name)

    with_runtime_layout = False
    if bool(args.runtime_layout_source_selection) != bool(args.runtime_layout_source_selection_sha256):
        raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_SELECTION_PAIR")
    if args.runtime_layout_source_selection:
        raw = capture_bytes(args.runtime_layout_source_selection)
        if hashlib.sha256(raw).hexdigest() != args.runtime_layout_source_selection_sha256:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_SELECTION_IDENTITY")
        runtime_layout_identity = dict(generated_from[-1])
        if args.runtime_layout_source_selection.resolve().is_relative_to(args.repo_root.resolve()):
            runtime_layout_identity["repositoryPath"] = args.runtime_layout_source_selection.resolve().relative_to(
                args.repo_root.resolve()).as_posix()
        selected_layout = json.loads(raw)
        if selected_layout.get("schema") != "maplesu-claim-runtime-layout-source-selection/1":
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_SELECTION_SCHEMA")
        layout_external_members = {
            "runtime/ultra/authorization/" + name for name in
            ("request_protocol.h", "execution_frame.h", "legacy_hook_private.h", "publication_return_private.h")
        } | {su_prefix + name for name in (
            "su_exec_session.c", "su_exec_session.h", "su_install_registry.c", "su_install_registry.h",
            "su_profile_apply.c", "su_profile_apply.h", "su_profile_execution.c", "su_profile_execution.h",
            "su_profile_namespace.c", "su_profile_namespace.h"
        )} | {session_receipt} | {
            "runtime/ultra/boot/init-bridge/" + name for name in
            ("native_lookup.c", "native_lookup.h", "native_cfi.h", "native_imports.c", "native_imports.h",
             "native_direct.h", "native_sdk_imports.c", "native_sdk.h", "Kbuild",
             "boot_events.c", "boot_events.h", "preinit.h", "bridge.c",
             "native_layout.c", "native_layout.h")
        }
        seen = set()
        for row in selected_layout["files"]:
            relative = row["logicalPath"]
            if ((not relative.startswith("runtime/ultra/identity/kernel/") and relative not in layout_external_members) or
                    any(part in ("", ".", "..") for part in relative.split("/")) or "\\" in relative or relative in seen):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_SELECTION_MEMBER:" + relative)
            seen.add(relative)
            before, after = row.get("before"), row["after"]
            previous = bindings.get(relative)
            if before is None:
                if relative not in {"runtime/ultra/identity/kernel/manager_dynamic_layout.c",
                                    "runtime/ultra/identity/kernel/manager_dynamic_layout.h",
                                    "runtime/ultra/identity/kernel/manager_ksu_compat.c",
                                    "runtime/ultra/identity/kernel/manager_ksu_compat.h",
                                    *("runtime/ultra/identity/kernel/" + unit + suffix
                                      for unit in RUNTIME_FACT_UNITS for suffix in (".c", ".h")),
                                    *("runtime/ultra/identity/kernel/" + name for name in RUNTIME_FACT_HEADERS),
                                    "runtime/ultra/boot/init-bridge/native_direct.h"} or previous:
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_ADDITION:" + relative)
            else:
                checked_reference(before)
                if previous and any(previous[0][key] != before[key] for key in ("bytes", "sha256")):
                    raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_PREDECESSOR:" + relative)
            checked_reference(after)
            bindings[relative] = (after, "runtime-layout-source-successor")
        required_layout = {"runtime/ultra/identity/kernel/manager_dynamic_layout.c",
                           "runtime/ultra/identity/kernel/manager_dynamic_layout.h"}
        if not required_layout.issubset(seen):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_LAYOUT_SOURCE_CLOSURE")
        runtime_successors.append(runtime_layout_identity)
        with_runtime_layout = True
    if args.runtime_facts:
        required_facts = {"runtime/ultra/identity/kernel/" + unit + suffix
                          for unit in RUNTIME_FACT_UNITS for suffix in (".c", ".h")}
        required_facts.update("runtime/ultra/identity/kernel/" + name for name in RUNTIME_FACT_HEADERS)
        if not runtime_selection or not with_runtime_layout or not required_facts.issubset(bindings):
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_SOURCE_CLOSURE")
        if args.target_kmi:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_EXACT_TARGET_CONFLICT")

    def select(relative, destination, overlays, included_by=None):
        binding = bindings.get(relative)
        if runtime_selection and relative.startswith("runtime/ultra/identity/kernel/") and not binding and not included_by:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_MEMBER_MISSING:" + relative)
        if args.su_selection and (relative.startswith(su_prefix) or relative == session_receipt) and not binding:
            raise ValueError("ULTRA_BRIDGE_SU_MEMBER_MISSING:" + relative)
        if binding:
            source = resolve_reference(binding[0])
        else:
            paths = [root.resolve() / relative for root in overlays]
            source = next((path for path in paths if path.is_file()), None)
        if source is None or not source.is_file():
            raise ValueError("ULTRA_BRIDGE_SOURCE_MISSING:" + relative)
        data = source.read_bytes()
        selected = identity(source, data)
        if binding and any(selected[key] != binding[0][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_FORMAL_SOURCE_IDENTITY:" + relative)
        row = {"repositoryPath": relative, "selected": selected, "staged": destination}
        if binding:
            row["selection"] = binding[1]
        if included_by:
            row["includedBy"] = included_by
            if not binding:
                row["selection"] = "core-private-include"
        rows.append(row)
        content[destination] = data

    bridge = "runtime/ultra/boot/init-bridge/"
    for path in sorted(Path(__file__).parent.iterdir()):
        if path.suffix in (".c", ".h") or path.name in ("Kbuild", "preinit_blob.S"):
            select(bridge + path.name, path.name, [candidate])
    select(bridge + "preinit/runner.c", "preinit/runner.c", [candidate])
    # Pin nolibc to the same authoritative KSU checkout; no toolchain copy.
    for path in sorted((args.repo_root / "third_party/kernelsu/upstream/kernel/preinit/runner/nolibc").rglob("*.h")):
        relative = path.relative_to(args.repo_root).as_posix()
        select(relative, "preinit/nolibc/" + path.relative_to(args.repo_root / "third_party/kernelsu/upstream/kernel/preinit/runner/nolibc").as_posix(), [args.repo_root])
    host = "runtime/ultra/identity/kernel/"
    core_units = (("manager_task_state", "manager_credential_domain") +
                  (("manager_dynamic_layout",) if with_runtime_layout else ()) +
                  (RUNTIME_FACT_UNITS if args.runtime_facts else ()))
    units = ("install_records", "protected_install_kernel", "manager_apk_identity", "manager_claim_entry",
             "manager_owner", "manager_owner_watch", "manager_resident_host", "manager_management",
             "manager_uid_gateway", "manager_uid_snapshot") + core_units
    roots = [args.core_overlay, args.host_overlay, args.repo_root]
    for unit in units:
        for suffix in (".c", ".h"):
            select(host + unit + suffix, "host/" + unit + suffix, roots)
    for name in ("manager_claim_abi.h", "manager_owner_claim.h", "manager_resident_abi.h", "manager_claim_loader.h",
                 "manager_credential_profile.h", "manager_deployment_namespace.h", "manager_early_helper.h",
                 ):
        select(host + name, "host/" + name, roots)
    if runtime_selection:
        for unit in HOST_RUNTIME_UNITS + (EARLY_RUNTIME_UNITS if with_early_runtime else ()):
            suffixes = (".c",) if unit == "manager_su_runtime_target" else (".c", ".h")
            for suffix in suffixes:
                select(host + unit + suffix, "host/" + unit + suffix, roots)
        # Freestanding HOST emission includes this source; a normal LKM uses
        # native exported byte helpers, so no second memcpy/memset is linked.
        select(host + "manager_bytes.c", "host/manager_bytes.c", roots)
    producer = "jailbreak-providers/root-loader/"
    for name in ("module/maplesu_boot_sdk.c", "module/boot_sdk_call.S", "module/boot_sdk_protocol.h",
                 "module/boot_sdk_allocator.h", "boot_sdk_abi.h"):
        select(producer + name, "producer/" + name, [candidate, args.repo_root])
    target_profile = host + "manager_su_runtime_target_profile.h" in bindings
    kmi_contract = None
    if args.target_kmi:
        if not target_profile:
            raise ValueError("ULTRA_BRIDGE_KMI_RUNTIME_PROFILE_REQUIRED")
        spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).with_name("target_kmi.py"))
        kmi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(kmi)
        if args.require_resident_text_owner_kmi:
            kmi_contract = kmi.read_contract(args.target_kmi, args.kernel_build,
                require_resident_text_owner=True,
                selected_imports={name: content.get(name) for name in ("native_imports.c", "native_imports.h",
                    "native_direct.h", "native_sdk_imports.c", "native_sdk.h", "Kbuild",
                    "producer/module/maplesu_boot_sdk.c")})
        else:
            kmi_contract = kmi.read_contract(args.target_kmi, args.kernel_build,
                selected_imports={name: content.get(name) for name in ("native_imports.c", "native_imports.h",
                    "native_direct.h", "native_sdk_imports.c", "native_sdk.h", "Kbuild",
                    "producer/module/maplesu_boot_sdk.c")})
        capture_bytes(args.target_kmi)
        for reference in [*kmi_contract["inputs"].values(), kmi_contract["profile"], kmi_contract["targetSymvers"]]:
            capture_bytes(kmi.reference_path(reference))
        profile_reference = dict(kmi_contract["profile"], path=str(kmi.reference_path(kmi_contract["profile"])))
        if not with_runtime_layout:
            bindings[host + "manager_su_runtime_target_profile.h"] = (profile_reference, "target-image-kmi-profile")
        elif host + "manager_su_runtime_target_profile.h" not in seen:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SOURCE_REQUIRED")
    if target_profile:
        select(host + "manager_su_runtime_target_profile.h", "host/manager_su_runtime_target_profile.h", roots)
    for name in ("request_protocol.h", "execution_frame.h", "legacy_hook_private.h", "publication_return_private.h"):
        select("runtime/ultra/authorization/" + name, name, [args.core_overlay, args.repo_root])
    su = "runtime/maplesu-sdk/sdk/src/module/su_redirect_tu/kernel/"
    su_units = ("su_install_registry", "su_profile_apply", "su_profile_namespace",
                "su_profile_execution", "su_profile_resolve")
    for unit in su_units:
        for suffix in (".c", ".h"):
            select(su + unit + suffix, "host/" + unit + suffix, [args.su_overlay, args.repo_root])
    # Keep the canonical relative receipt include in the unmodified kernel TU.
    # These objects are linked into the actual bridge LKM: THIS_MODULE is its
    # real owner, and the existing bridge pins that module after publication.
    session_members = (su + "su_exec_session.c", su + "su_exec_session.h", session_receipt)
    with_session = any(relative in bindings for relative in session_members)
    session_object = "sdk/src/module/su_redirect_tu/kernel/su_exec_session.o"
    if with_session:
        if not all(relative in bindings for relative in session_members):
            raise ValueError("ULTRA_BRIDGE_SU_SESSION_SOURCE_SET")
        select(session_members[0], session_object[:-2] + ".c", [args.su_overlay, args.repo_root])
        select(session_members[1], "host/su_exec_session.h", [args.su_overlay, args.repo_root])
        select(session_receipt, "sdk/src/payload/su/su_session_receipt.h", [args.su_overlay, args.repo_root])
    elif re.search(rb"\bmsu_su_exec_session_\w+\s*\(", content.get("host/manager_su_runtime_factory.c", b"")):
        raise ValueError("ULTRA_BRIDGE_SU_SESSION_SELECTION_REQUIRED")
    ksu_members = (host + "manager_ksu_compat.c", host + "manager_ksu_compat.h")
    with_ksu_compat = any(relative in bindings for relative in ksu_members)
    if with_ksu_compat:
        if not all(relative in bindings for relative in ksu_members):
            raise ValueError("ULTRA_BRIDGE_KSU_COMPAT_SOURCE_SET")
        for relative in ksu_members:
            select(relative, "host/" + Path(relative).name, roots)
    elif re.search(rb"\bmsu_ksu_compat_\w+\s*\(", content.get("host/manager_su_runtime_factory.c", b"")):
        raise ValueError("ULTRA_BRIDGE_KSU_COMPAT_SELECTION_REQUIRED")
    # An explicit six-file cohort belongs to this same real bridge LKM.
    # Never fill an incomplete formal cohort from a mutable overlay.
    with_nonroot = any(relative in bindings for relative in nonroot_members)
    nonroot_objects = ["host/" + unit + ".o" for unit in nonroot_units]
    if with_nonroot:
        if not all(relative in bindings for relative in nonroot_members):
            raise ValueError("ULTRA_BRIDGE_SU_NONROOT_SOURCE_SET")
        if not with_session:
            raise ValueError("ULTRA_BRIDGE_SU_NONROOT_SESSION_REQUIRED")
        for relative in nonroot_members:
            select(relative, "host/" + Path(relative).name, [args.su_overlay, args.repo_root])
    elif any(re.search(rb"\bmsu_su_(?:nonroot_|runtime_nonroot_)\w+\s*\(",
                       content.get("host/" + unit + ".c", b"")) for unit in HOST_RUNTIME_UNITS):
        raise ValueError("ULTRA_BRIDGE_SU_NONROOT_SELECTION_REQUIRED")
    # Follow only the reviewed private include closure from actually selected
    # sources, retaining each selected file's identity. Conditional includes are
    # available to the compiler without enabling their native target provider.
    private_includes = {
        "legacy_hook_private.h": ("runtime/ultra/authorization/legacy_hook_private.h", "legacy_hook_private.h"),
        "publication_return_private.h": ("runtime/ultra/authorization/publication_return_private.h", "publication_return_private.h"),
        "manager_legacy_hook.inc": (host + "manager_legacy_hook.inc", "host/manager_legacy_hook.inc"),
        "manager_legacy_provider.inc": (host + "manager_legacy_provider.inc", "host/manager_legacy_provider.inc"),
        "native-text/kprobe_text_owner.h": (host + "native-text/kprobe_text_owner.h", "host/native-text/kprobe_text_owner.h"),
        "linux/maplesu/legacy_hook_private.h": ("runtime/ultra/authorization/legacy_hook_private.h", "linux/maplesu/legacy_hook_private.h"),
    }
    # Source-selected local headers form a bounded closure, not an overlay scan.
    # Their identity was already checked above and is checked again by select.
    for relative in sorted(bindings):
        if relative.startswith(host) and relative.endswith(".h"):
            name = relative[len(host):]
            dependency = (relative, "host/" + name)
            if name in private_includes and private_includes[name] != dependency:
                raise ValueError("ULTRA_BRIDGE_RUNTIME_HEADER_COLLISION:" + name)
            private_includes[name] = dependency
    include_queue = list(content)
    for included_by in include_queue:
        for name in re.findall(rb'^\s*#\s*include\s*[<"]([^>"\r\n]+)[>"]', content[included_by], re.M):
            dependency = private_includes.get(name.decode("utf-8"))
            if dependency:
                if dependency[1] not in content:
                    select(*dependency, [args.core_overlay, args.repo_root], included_by=included_by)
                    include_queue.append(dependency[1])
                else:
                    # Required CORE members were already identity-checked;
                    # attach provenance without reselecting or weakening it.
                    row = next(row for row in rows if row["staged"] == dependency[1])
                    row.setdefault("includedBy", included_by)
                    row.setdefault("selection", "core-private-include")
    config = capture(args.kernel_build / ".config")
    native_config = generated_from[-1]
    native_private_headers = []
    pages = [size for token, size in (("4K", 4096), ("16K", 16384), ("64K", 65536))
             if "CONFIG_ARM64_" + token + "_PAGES=y" in config.splitlines()]
    if len(pages) != 1:
        raise ValueError("ULTRA_BRIDGE_NATIVE_PAGE_CONFIG")
    if with_nonroot:
        # Read the selected kernel source through the existing exact-source resolver.
        select("fs/mount.h", "native-private/fs/mount.h", [args.kernel_source])
        rows[-1]["selection"] = "native-kernel-private-header"
        native_private_headers.append({"repositoryPath": "fs/mount.h",
            "source": rows[-1]["selected"], "staged": rows[-1]["staged"],
            "kernelSource": str(args.kernel_source.resolve()),
            "kernelBuild": str(args.kernel_build.resolve()),
            "config": native_config, "pageBytes": pages[0]})
    if target_profile and kmi_contract:
        contract_reference = identity(args.target_kmi)
        if args.target_kmi.resolve().is_relative_to(args.repo_root.resolve()):
            contract_reference["repositoryPath"] = args.target_kmi.resolve().relative_to(args.repo_root.resolve()).as_posix()
        target_binding = {"kind": kmi_contract["schema"], "contract": contract_reference,
                          "kernelProfile": kmi_contract["kernelProfile"],
                          "targetConfig": kmi_contract["inputs"]["targetConfig"],
                          "buildConfig": kmi_contract["inputs"]["buildConfig"],
                          "pageBytes": pages[0], "profile": kmi_contract["profile"],
                          "kernelImageIdentityEstablished": True, "targetQualified": False}
        if with_runtime_layout:
            target_binding["kmiProfile"] = target_binding["profile"]
            target_binding["profile"] = bindings[host + "manager_su_runtime_target_profile.h"][0]
            target_binding["runtimeLayoutProfile"] = runtime_layout_identity
        if args.require_resident_text_owner_kmi:
            target_binding["residentTextOwner"] = kmi_contract["residentTextOwner"]
    elif args.runtime_facts:
        if not target_profile:
            raise ValueError("ULTRA_BRIDGE_RUNTIME_FACTS_PROFILE_REQUIRED")
        target_binding = {"kind": "runtime-kmi-component", "buildConfig": native_config,
                          "pageBytes": pages[0], "runtimeLayoutProfile": runtime_layout_identity,
                          "profile": bindings[host + "manager_su_runtime_target_profile.h"][0],
                          "kernelImageIdentityEstablished": False, "targetQualified": False}
    elif target_profile:
        if not initialization_child:
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT_REQUIRED")
        expected_config = checked_reference(initialized["targetConfig"])
        if config.encode("utf-8") != expected_config:
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_CONFIG_MISMATCH")
        source_bindings = []
        for relative in TARGET_PROFILE_SOURCES:
            declared = [row for row in initialized["targetSourceFiles"]
                        if row["path"].replace("\\", "/").endswith("/" + relative)]
            if len(declared) != 1:
                raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT:" + relative)
            expected = checked_reference(declared[0])
            actual_path = args.kernel_source / relative
            actual = capture_bytes(actual_path)
            if actual != expected:
                raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + relative)
            source_bindings.append({"repositoryPath": relative, "declared": declared[0],
                                    "actual": identity(actual_path, actual)})
        owner_selection = dict(initialization_reference)
        owner_path = resolve_reference(owner_selection).resolve()
        if owner_path.is_relative_to(args.repo_root.resolve()):
            owner_selection["repositoryPath"] = owner_path.relative_to(args.repo_root.resolve()).as_posix()
        target_binding = {"ownerSelection": owner_selection, "kernelProfile": initialized["kernelProfile"],
                          "targetConfig": initialized["targetConfig"], "pageBytes": pages[0],
                          "profile": bindings[host + "manager_su_runtime_target_profile.h"][0],
                          "sourceFiles": source_bindings,
                          "kernelImageIdentityEstablished": False}
    fs_header = args.kernel_source / "include/linux/fs_struct.h"
    fs = re.sub(r"/\*.*?\*/|//[^\n]*", "", capture(fs_header), flags=re.S)
    declaration = re.search(r"struct\s+fs_struct\s*\{(.*?)\}[^;]*;", fs, re.S)
    if not declaration:
        raise ValueError("ULTRA_BRIDGE_FS_STRUCT_DECLARATION")
    body = declaration.group(1)
    sequence = re.findall(r"\b([A-Za-z_]\w*)\s+seq\s*;", body)
    if len(sequence) != 1 or sequence[0] not in ("seqlock_t", "seqcount_t", "seqcount_spinlock_t"):
        raise ValueError("ULTRA_BRIDGE_FS_SEQUENCE_DECLARATION")
    lock = bool(re.search(r"\bspinlock_t\s+lock\s*;", body))
    if bool(re.search(r"\block\b", body)) != lock:
        raise ValueError("ULTRA_BRIDGE_FS_LOCK_DECLARATION")
    execmem_header = args.kernel_source / "include/linux/execmem.h"
    execmem_present = execmem_header.is_file()
    execmem = capture(execmem_header) if execmem_present else ""
    execmem = re.sub(r"/\*.*?\*/|//[^\n]*", "", execmem, flags=re.S)
    feature = {"MSU_RESOLVER_FS_HAS_LOCK": int(lock), "MSU_RESOLVER_FS_SEQLOCK": int(sequence[0] == "seqlock_t"),
               "MSU_MANAGEMENT_EXECMEM_ALLOC_RW": int(bool(re.search(r"\bexecmem_alloc_rw\s*\(", execmem))),
               "MSU_MANAGEMENT_TASK_STATE_VERIFIED": int("manager_task_state" in core_units)}
    seccomp_api = None
    if bool(args.seccomp_source_selection) != bool(args.seccomp_source_selection_sha256):
        raise ValueError("ULTRA_BRIDGE_SECCOMP_SOURCE_SELECTION_PAIR")
    if b"MSU_TASK_SECCOMP_RELEASE_LOCKS_TASK" in content["host/manager_task_state.c"]:
        enabled = "CONFIG_SECCOMP_FILTER=y" in config.splitlines()
        seccomp_api = {"schema": "maplesu-seccomp-release-body/1", "symbol": "seccomp_filter_release",
                       "enabled": enabled, "config": native_config}
        if enabled:
            seccomp_source = args.kernel_source / "kernel/seccomp.c"
            seccomp_header = args.kernel_source / "include/linux/seccomp.h"
            if not seccomp_source.is_file():
                if not args.seccomp_source_selection:
                    raise ValueError("ULTRA_BRIDGE_SECCOMP_BODY_SOURCE_REQUIRED")
                raw = capture_bytes(args.seccomp_source_selection)
                if hashlib.sha256(raw).hexdigest() != args.seccomp_source_selection_sha256:
                    raise ValueError("ULTRA_BRIDGE_SECCOMP_SOURCE_SELECTION_IDENTITY")
                seccomp_api["sourceSelection"] = generated_from[-1]
                selected_seccomp = json.loads(raw)
                if selected_seccomp.get("schema") != "maplesu-bridge-seccomp-source-selection/1":
                    raise ValueError("ULTRA_BRIDGE_SECCOMP_SOURCE_SELECTION_SCHEMA")
                selected_inputs = selected_seccomp["inputs"]
                for key, path in (("config", args.kernel_build / ".config"),
                                  ("sourceMakefile", args.kernel_source / "Makefile"),
                                  ("fsHeader", args.kernel_source / "include/linux/fs_struct.h"),
                                  ("credHeader", args.kernel_source / "include/linux/cred.h")):
                    actual = capture_bytes(path)
                    if any(generated_from[-1][field] != selected_inputs[key][field] for field in ("bytes", "sha256")):
                        raise ValueError("ULTRA_BRIDGE_SECCOMP_SPARSE_SOURCE_MISMATCH:" + key)
                source_bytes = checked_reference(selected_inputs["source"])
                seccomp_api["source"] = generated_from[-1]
                header_bytes = checked_reference(selected_inputs["header"])
                seccomp_api["header"] = generated_from[-1]
                seccomp_api["sourceImage"] = selected_seccomp["image"]
            else:
                source_bytes = capture_bytes(seccomp_source)
                seccomp_api["source"] = generated_from[-1]
                header_bytes = capture_bytes(seccomp_header)
                seccomp_api["header"] = generated_from[-1]
            seccomp_api.update(seccomp_release_traits(source_bytes))
            content["native-private/seccomp-release-source.c"] = source_bytes
            content["native-private/seccomp-release-header.h"] = header_bytes
            feature["MSU_TASK_SECCOMP_RELEASE_LOCKS_TASK"] = int(seccomp_api["locksTask"])
        else:
            feature["MSU_TASK_SECCOMP_RELEASE_LOCKS_TASK"] = 0
    if b"MSU_MANAGEMENT_CRED_UCOUNTS" in content["host/manager_management.c"]:
        cred_header = args.kernel_source / "include/linux/cred.h"
        cred = re.sub(r"/\*.*?\*/|//[^\n]*", "", capture(cred_header), flags=re.S)
        declaration = re.search(r"\bstruct\s+cred\s*\{", cred)
        if not declaration:
            raise ValueError("ULTRA_BRIDGE_CRED_DECLARATION")
        level, end = 1, declaration.end()
        while level and end < len(cred):
            level += (cred[end] == "{") - (cred[end] == "}")
            end += 1
        if level:
            raise ValueError("ULTRA_BRIDGE_CRED_DECLARATION")
        body = cred[declaration.end():end - 1]
        fields = re.findall(r"\bstruct\s+ucounts\s*\*\s*ucounts\s*;", body)
        helpers = re.findall(r"\bextern\s+int\s+set_cred_ucounts\s*\(\s*struct\s+cred\s*\*\s*(?:[A-Za-z_]\w*)?\s*\)\s*;", cred)
        if (len(fields) > 1 or len(helpers) > 1 or bool(re.search(r"\bucounts\b", body)) != bool(fields) or
                bool(re.search(r"\bset_cred_ucounts\b", cred)) != bool(helpers) or bool(fields) != bool(helpers)):
            raise ValueError("ULTRA_BRIDGE_CRED_UCOUNTS_CONTRACT")
        feature["MSU_MANAGEMENT_CRED_UCOUNTS"] = int(bool(fields))
    content["host/msu_resolver_build_config.h"] = ("#ifndef MSU_INIT_BRIDGE_FEATURE_CONFIG\n#define MSU_INIT_BRIDGE_FEATURE_CONFIG\n" +
        "".join("#define %s %d\n" % row for row in feature.items()) + "#endif\n").encode()
    content["boot_sdk_layout.h"] = ("#define MSU_BS_STATIC_BOOTSTRAP 0\n#define MSU_BS_ENVIRONMENT 1\n"
        "#define MSU_BS_EXECVE_REG 1\n#define MSU_BS_EXECVE_CHAR 0\n"
        "#define MSU_BS_ALLOCATOR_NOPROF 0\n#define MSU_BS_PAGE_BYTES %d\n" % pages[0]).encode()
    core_objects = ["host/" + unit + ".o" for unit in core_units]
    if with_session:
        core_objects.append(session_object)
    if with_nonroot:
        core_objects.extend(nonroot_objects)
    content["selected-core.mk"] = ("# Fixed task-state and credential-domain dependencies, not a whole CORE snapshot.\n"
        "maplesu_ultra_bridge-y += " + " ".join(core_objects) + "\n").encode()
    if with_session:
        content["selected-core.mk"] += ("ccflags-y += -DMSU_SU_EXEC_SESSION_NATIVE=1\nCFLAGS_" + session_object +
            " += -DMSU_INIT_BRIDGE_HOST_IMPORTS=1 -include $(src)/native_imports.h\n").encode()
    if args.runtime_facts:
        content["selected-core.mk"] += b"ccflags-y += -DMSU_INIT_BRIDGE_RUNTIME_FACTS=1\n"
        for unit in RUNTIME_FACT_UNITS + ("manager_su_runtime_target",):
            content["selected-core.mk"] += ("CFLAGS_host/" + unit +
                ".o += -DMSU_INIT_BRIDGE_HOST_IMPORTS=1 -include $(src)/native_imports.h\n").encode()
    if with_nonroot:
        content["selected-core.mk"] += b"ccflags-y += -DMSU_SU_NONROOT_NATIVE=1\n"
        for obj in nonroot_objects:
            content["selected-core.mk"] += ("CFLAGS_" + obj +
                " += -DMSU_INIT_BRIDGE_HOST_IMPORTS=1 -include $(src)/native_imports.h\n").encode()
        content["selected-core.mk"] += (
            "CFLAGS_host/su_nonroot_mount_source.o += -I$(src)/native-private\n").encode()
    if kmi_contract and kmi_contract.get("abiEvidence", {}).get("method") == "same-kmi-module-loader":
        selected_features = {name: int(bool(feature.get(name, 0))) for name in
                             ("MSU_MANAGEMENT_RESIDENT_TEXT_OWNER", "MSU_MANAGEMENT_CRED_UCOUNTS")}
        selected_features.update(MSU_SU_EXEC_SESSION_NATIVE=int(with_session), MSU_SU_NONROOT_NATIVE=int(with_nonroot))
        if selected_features != kmi_contract.get("nativeImportsFeatures"):
            raise ValueError("ULTRA_BRIDGE_KMI_NATIVE_SELECTED_FEATURES")
    # CORE73's real resident calls installation_init with its own host/name.
    # Bind the existing HOST constructor at that typed call, without editing or
    # copying either owner implementation. Cleanup follows HOST's same order.
    factory_binding = bool(runtime_selection and (core_successors or target_profile))
    resident_runtime = False
    if factory_binding:
        resident = content["host/manager_resident_host.c"].decode("utf-8")
        resident_runtime = bool(re.search(r"\bmsu_su_runtime_init\s*\(", resident))
        if resident_runtime and not target_profile:
            factory_binding = False
        elif not all(re.search(r"\b" + name + r"\s*\(", resident) for name in
                     ("msu_installation_init", "msu_management_discard_unpublished")):
            raise ValueError("ULTRA_BRIDGE_CORE_FACTORY_CALLSITE_MISSING")
    if factory_binding:
        content["native_factory_bind.h"] = b"""/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MSU_INIT_BRIDGE_FACTORY_BIND_H
#define MSU_INIT_BRIDGE_FACTORY_BIND_H
#include "manager_installation_state.h"
#include "manager_management.h"
int msu_init_bridge_installation_init(const maplesu_host_instance *host, const unsigned char name[16]);
int msu_init_bridge_management_discard(void);
#ifdef MSU_INIT_BRIDGE_RESIDENT_FACTORY
#define msu_installation_init msu_init_bridge_installation_init
#define msu_management_discard_unpublished msu_init_bridge_management_discard
#endif
#endif
"""
        content["native_factory_bind.c"] = b"""// SPDX-License-Identifier: GPL-3.0-only
#include <linux/string.h>
#include "native_factory_bind.h"
#include "manager_su_runtime_factory.h"
_Static_assert(__builtin_types_compatible_p(typeof(&msu_init_bridge_installation_init),
    typeof(&msu_installation_init)), "actual installation constructor prototype");
_Static_assert(__builtin_types_compatible_p(typeof(&msu_init_bridge_management_discard),
    typeof(&msu_management_discard_unpublished)), "actual management discard prototype");
int msu_init_bridge_installation_init(const maplesu_host_instance *host, const unsigned char name[16])
{
    struct msu_deployment_namespace_record deployment = {
        .magic = MSU_DEPLOYMENT_NAMESPACE_MAGIC, .schema = MSU_DEPLOYMENT_NAMESPACE_SCHEMA,
        .bytes = sizeof(deployment),
    };
    int error = msu_installation_init(host, name);
    if (error) return error;
    memcpy(deployment.name, name, sizeof(deployment.name));
    error = msu_su_runtime_init(host, &deployment);
    memzero_explicit(&deployment, sizeof(deployment));
    return error;
}
int msu_init_bridge_management_discard(void)
{
    int error = msu_su_runtime_close();
    if (error) return error;
    error = msu_management_discard_unpublished();
    if (error) return error;
    return msu_su_runtime_discarded();
}
"""
        if target_profile:
            content["native_factory_bind.c"] = content["native_factory_bind.c"].replace(
                b'#include "manager_su_runtime_factory.h"\n',
                b'#include "manager_su_runtime_factory.h"\n#include "native_lookup.h"\n').replace(
                b"    int error = msu_installation_init(host, name);\n",
                b"    int error = msu_su_runtime_target_bind(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);\n"
                b"    if (error) return error;\n    error = msu_installation_init(host, name);\n")
            if resident_runtime:
                # The formal HOST child already owns runtime init and teardown.
                # Intercept only its installation call, never duplicate either.
                content["native_factory_bind.h"] = content["native_factory_bind.h"].replace(
                    b"#define msu_management_discard_unpublished msu_init_bridge_management_discard\n", b"").replace(
                    b"int msu_init_bridge_management_discard(void);\n", b"")
                content["native_factory_bind.c"] = b"""// SPDX-License-Identifier: GPL-3.0-only
#include "native_factory_bind.h"
#include "manager_su_runtime_factory.h"
#include "native_lookup.h"
_Static_assert(__builtin_types_compatible_p(typeof(&msu_init_bridge_installation_init),
    typeof(&msu_installation_init)), "actual installation constructor prototype");
int msu_init_bridge_installation_init(const maplesu_host_instance *host, const unsigned char name[16])
{
    int error = msu_su_runtime_target_bind(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);
    return error ? error : msu_installation_init(host, name);
}
"""
        if with_early_runtime:
            content["native_factory_bind.c"] = content["native_factory_bind.c"].replace(
                b'#include "native_factory_bind.h"\n',
                b'#include "native_factory_bind.h"\n#include "manager_early_runtime_factory.h"\n')
            if b'#include "native_lookup.h"\n' not in content["native_factory_bind.c"]:
                content["native_factory_bind.c"] = content["native_factory_bind.c"].replace(
                    b'#include "manager_early_runtime_factory.h"\n',
                    b'#include "manager_early_runtime_factory.h"\n#include "native_lookup.h"\n')
            if target_profile:
                anchor = b"    int error = msu_su_runtime_target_bind(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);\n"
                replacement = anchor + (b"    if (error) return error;\n"
                    b"    error = msu_early_runtime_target_bind(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);\n")
            else:
                anchor = b"    int error = msu_installation_init(host, name);\n"
                replacement = (b"    int error = msu_early_runtime_target_bind(msu_init_bridge_lookup, msu_init_bridge_resolve_cfi);\n"
                    b"    if (error) return error;\n    error = msu_installation_init(host, name);\n")
            if content["native_factory_bind.c"].count(anchor) != 1:
                raise ValueError("ULTRA_BRIDGE_EARLY_RUNTIME_FACTORY_CALLSITE")
            content["native_factory_bind.c"] = content["native_factory_bind.c"].replace(anchor, replacement)
    runtime_objects = ["host/" + unit + ".o" for unit in HOST_RUNTIME_UNITS] if runtime_selection else []
    if with_ksu_compat:
        runtime_objects.append("host/manager_ksu_compat.o")
    if with_early_runtime:
        runtime_objects.extend("host/" + unit + ".o" for unit in EARLY_RUNTIME_UNITS)
    content["selected-runtime.mk"] = ("# Exact frozen HOST constructor/provider/installation objects.\n" +
        ("maplesu_ultra_bridge-y += " + " ".join(runtime_objects) + "\n"
         "host_tus += manager_installation_state manager_su_runtime_factory "
         "su_observed_install_source su_durable_authority su_durable_modern\n"
         if runtime_objects else "")).encode()
    if with_ksu_compat:
        content["selected-runtime.mk"] += b"host_tus += manager_ksu_compat\n"
    if factory_binding:
        content["selected-runtime.mk"] += ("maplesu_ultra_bridge-y += native_factory_bind.o\n"
            "CFLAGS_host/manager_resident_host.o += -DMSU_INIT_BRIDGE_RESIDENT_FACTORY=1 "
            "-include $(src)/native_factory_bind.h\n").encode()
    if with_early_runtime:
        if not factory_binding:
            raise ValueError("ULTRA_BRIDGE_EARLY_RUNTIME_BOOT_BIND_REQUIRED")
        content["selected-runtime.mk"] += ("host_tus += " + " ".join(EARLY_RUNTIME_UNITS) + "\n").encode()
    output.mkdir(parents=True)
    for name, data in content.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for row in rows:
        path = Path(row["selected"]["path"])
        if not path.is_file() or identity(path) != row["selected"]:
            raise ValueError("ULTRA_BRIDGE_SOURCE_CHANGED_DURING_SELECTION:" + str(path))
    for captured in generated_from:
        path = Path(captured["path"])
        if not path.is_file() or identity(path) != captured:
            raise ValueError("ULTRA_BRIDGE_GENERATION_INPUT_CHANGED:" + str(path))
    if execmem_header.is_file() != execmem_present:
        raise ValueError("ULTRA_BRIDGE_GENERATION_INPUT_CHANGED:" + str(execmem_header))
    receipt = {"inputs": rows, "generatedFrom": generated_from,
               "seccompReleaseApi": seccomp_api,
               "formalDeploymentSelections": formal_selections,
               "formalRuntimeSelections": runtime_selection, "formalSuSelections": su_selections,
               "formalSuSourceEvolution": su_source_evolution,
               "formalRuntimeSuccessors": runtime_successors,
               "coreFactoryCallBindingGenerated": factory_binding,
               "runtimeTargetBindGenerated": bool(factory_binding and target_profile),
               "earlyRuntimeTargetBindGenerated": bool(factory_binding and with_early_runtime),
               "residentOwnsRuntimeLifecycle": resident_runtime,
               "targetBinding": target_binding,
               "selectedNativePrivateHeaders": native_private_headers,
               "generatedFactoryBinding": [identity(output / name, content[name]) for name in
                   ("native_factory_bind.c", "native_factory_bind.h") if factory_binding],
               "selectedHostRuntimeObjects": runtime_objects,
               "credentialMode": "module-parameter", "pageBytes": pages[0],
               "selectedCoreDependencyObjects": core_objects, "runtimeLayoutSelected": with_runtime_layout,
               "runtimeFactsSelected": args.runtime_facts, "wholeCoreSnapshotSelected": False,
               "selectedCorePrivateIncludes": [row for row in rows if "includedBy" in row],
               "selectedSuComponentObjects": ["host/" + unit + ".o" for unit in su_units],
               "compiled": False, "tested": False, "targetQualified": False,
               "fullUltraEquivalent": False, "factoryInstalled": False}
    (output / "SOURCE-SELECTION.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
