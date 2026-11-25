#!/usr/bin/env python3
"""Aggregate actual strict-built bundles; never generate or qualify a module from catalog hints."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

HASH = re.compile(r"[0-9a-f]{64}")
COMPONENTS = ("targetBoot", "handoff", "bridge", "config", "moduleSymvers", "targetContract",
              "btf", "sessionAbi", "taskProfileAbi", "abiEvidence", "bundleSources", "ksuInit")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": sha(data)}


def same(actual, declared, code):
    require(isinstance(declared, dict) and all(actual.get(k) == declared.get(k) for k in ("bytes", "sha256")), code)


def relative(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,240}", value)
            and all(x not in ("", ".", "..") for x in value.split("/")), "ULTRA_CATALOG_PATH")
    return value


def selected_path(base, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def selection_sources(selection):
    common = {}
    dependencies = []
    rows = selection.get("inputs")
    require(isinstance(rows, list) and rows, "ULTRA_CATALOG_SOURCE_INPUTS")
    for row in rows:
        name = relative(row["repositoryPath"].replace("\\", "/"))
        actual = row["selected"]
        require(isinstance(actual.get("bytes"), int) and actual["bytes"] > 0 and
                isinstance(actual.get("sha256"), str) and HASH.fullmatch(actual["sha256"]), "ULTRA_CATALOG_SOURCE_IDENTITY")
        source = Path(actual["path"])
        same(identity(source), actual, "ULTRA_CATALOG_SELECTED_SOURCE_CHANGED:" + name)
        dependencies.append((source, {k: actual[k] for k in ("bytes", "sha256")}))
        # A DDK-private header is a per-target ABI input, not a different software generation.
        if row.get("selection") == "native-kernel-private-header":
            continue
        value = {k: actual[k] for k in ("bytes", "sha256")}
        require(name not in common or common[name] == value, "ULTRA_CATALOG_SOURCE_CONFLICT:" + name)
        common[name] = value
    require(common, "ULTRA_CATALOG_SOURCE_GENERATION_EMPTY")
    return dict(sorted(common.items())), dependencies


def check_strict_build(selection_file, build_file, bridge):
    selection_identity, build_identity = identity(selection_file), identity(build_file)
    build = read_json(build_file)
    require(build.get("exitCode") == 0 and build.get("inputsUnchanged") is True, "ULTRA_CATALOG_STRICT_BUILD")
    require(any(x.get("path", "").replace("\\", "/").endswith("/SOURCE-SELECTION.json") and
                all(x.get(k) == selection_identity[k] for k in ("bytes", "sha256"))
                for x in build.get("sources", [])), "ULTRA_CATALOG_STRICT_SOURCE_SELECTION")
    artifacts = build.get("artifacts", [])
    if isinstance(artifacts, dict):
        artifacts = [artifacts]
    require(any(all(x.get(k) == bridge[k] for k in ("bytes", "sha256")) for x in artifacts),
            "ULTRA_CATALOG_STRICT_MODULE")
    return selection_identity, build_identity


def inspect_component(row, plan_root):
    root = selected_path(plan_root, row["bundle"])
    selection_file = selected_path(plan_root, row["sourceSelection"])
    build_file = selected_path(plan_root, row["strictBuild"])
    manifest_file = root / "manifest.json"
    manifest = read_json(manifest_file)
    fields = {"schemaVersion", "kind", "kmi", "architecture", "pageSize", "cfiMode", "kernelRelease",
              "credentialMode", "metadataDisplacement", "runtimeFactsAbi", "sourceGenerationSha256",
              "handoff", "handoffSha256", "bridge", "bridgeSha256"}
    optional = {"ksuInit", "ksuInitSha256", "bundleSources", "bundleSourcesSha256"}
    require(fields.issubset(manifest) and not set(manifest) - fields - optional and
            manifest.get("schemaVersion") == 2 and manifest.get("kind") == "kmi-component",
            "ULTRA_CATALOG_COMPONENT_SCHEMA")
    require(isinstance(manifest["kmi"], str) and re.fullmatch(r"android[0-9]+-(?:5\.(?:10|15)|6\.(?:1|6|12|18))", manifest["kmi"]),
            "ULTRA_CATALOG_COMPONENT_KMI")
    require(manifest["architecture"] == "arm64" and type(manifest["pageSize"]) is int and
            manifest["pageSize"] in (4096, 16384, 65536) and
            manifest["cfiMode"] in ("none", "kcfi", "legacy-lto-cfi") and
            manifest["credentialMode"] == "module-parameter" and
            manifest["runtimeFactsAbi"] == "maplesu-runtime-facts/1", "ULTRA_CATALOG_COMPONENT_ABI")
    require(HASH.fullmatch(manifest["sourceGenerationSha256"]) and
            type(manifest["metadataDisplacement"]) is int, "ULTRA_CATALOG_COMPONENT_FACTS")
    files = {"manifest.json": identity(manifest_file)}
    for field in ("handoff", "bridge", "ksuInit", "bundleSources"):
        require((field in manifest) == (field + "Sha256" in manifest), "ULTRA_CATALOG_COMPONENT_PAIR:" + field)
        if field not in manifest:
            continue
        name = relative(manifest[field])
        require(name not in files, "ULTRA_CATALOG_COMPONENT_CONFLICT")
        path = root / name
        require(not path.is_symlink() and path.resolve().is_relative_to(root), "ULTRA_CATALOG_COMPONENT_SYMLINK")
        files[name] = identity(path)
        require(files[name]["sha256"] == manifest[field + "Sha256"], "ULTRA_CATALOG_COMPONENT_HASH:" + field)
    # Consumers need only the compact manifest; publication additionally retains
    # the actual source/build receipts rather than fabricating a target image.
    require("bundleSources" in manifest, "ULTRA_CATALOG_COMPONENT_BUILD_SOURCES")
    sources = read_json(root / manifest["bundleSources"])
    require(sources.get("schemaVersion") == 2 and sources.get("kind") == "kmi-component" and
            isinstance(sources.get("inputs"), dict), "ULTRA_CATALOG_COMPONENT_BUILD_SOURCES")
    require({"bridge", "handoff", "config", "release", "handoff_verifier", "source_selection", "strict_build"}
            <= sources["inputs"].keys(), "ULTRA_CATALOG_COMPONENT_BUILD_INPUTS")
    dependencies = [(selection_file, identity(selection_file)), (build_file, identity(build_file))]
    for name, item in sources["inputs"].items():
        original = Path(item["path"])
        same(identity(original), item, "ULTRA_CATALOG_COMPONENT_ORIGINAL_CHANGED:" + name)
        dependencies.append((original, {k: item[k] for k in ("bytes", "sha256")}))
        bundled = item.get("bundledAs")
        if bundled is not None:
            require(bundled in files and files[bundled]["sha256"] == item.get("bundledSha256") and
                    files[bundled]["bytes"] == item.get("bundledBytes"), "ULTRA_CATALOG_COMPONENT_BUNDLED:" + name)
    bridge = sources["inputs"]["bridge"]
    same(files[manifest["bridge"]], bridge, "ULTRA_CATALOG_COMPONENT_MODULE_MODIFIED")
    selection_identity, build_identity = check_strict_build(selection_file, build_file, bridge)
    same(selection_identity, sources.get("sourceSelection"), "ULTRA_CATALOG_COMPONENT_SELECTION")
    same(build_identity, sources.get("strictBuild"), "ULTRA_CATALOG_COMPONENT_BUILD")
    same(selection_identity, sources["inputs"]["source_selection"], "ULTRA_CATALOG_COMPONENT_SELECTION_INPUT")
    same(build_identity, sources["inputs"]["strict_build"], "ULTRA_CATALOG_COMPONENT_BUILD_INPUT")
    build = read_json(build_file)
    for name in ("config", "release"):
        require(any(all(row.get(k) == sources["inputs"][name][k] for k in ("bytes", "sha256"))
                    for row in build.get("sources", [])), "ULTRA_CATALOG_COMPONENT_STRICT_INPUT:" + name)
    release_text = Path(sources["inputs"]["release"]["path"]).read_text(encoding="utf-8")
    releases = re.findall(r'^#define UTS_RELEASE "([^"\r\n]+)"$', release_text, re.M)
    require(releases == [manifest["kernelRelease"]], "ULTRA_CATALOG_COMPONENT_BUILD_RELEASE")
    selection = read_json(selection_file)
    require(selection.get("runtimeFactsSelected") is True and
            selection.get("targetBinding", {}).get("kind") == "runtime-kmi-component",
            "ULTRA_CATALOG_COMPONENT_RUNTIME_SOURCE")
    common, selected_dependencies = selection_sources(selection)
    dependencies += selected_dependencies
    generation_inputs = {"moduleSources": common, "handoffSha256": manifest["handoffSha256"]}
    generation = sha(encoded(generation_inputs))
    require(generation == manifest["sourceGenerationSha256"] == sources.get("sourceGenerationSha256") and
            sources.get("generationInputs") == generation_inputs, "ULTRA_CATALOG_COMPONENT_GENERATION")
    api_spec = importlib.util.spec_from_file_location("catalog_component_package", Path(__file__).with_name("package.py"))
    api = importlib.util.module_from_spec(api_spec)
    api_spec.loader.exec_module(api)
    # Cohort labels describe the actual build, not the consumer kernel.
    actual_cohort = api.component_kmi(None, selection, build)
    require(actual_cohort is None or actual_cohort == manifest["kmi"],
            "ULTRA_CATALOG_COMPONENT_KMI_CLASSIFICATION")
    config = api.config_values(Path(sources["inputs"]["config"]["path"]).read_bytes())
    actual = api.inspect_component_module((root / manifest["bridge"]).read_bytes(), manifest["kernelRelease"],
                                         config, manifest["cfiMode"])
    require(actual["cfiMode"] == manifest["cfiMode"], "ULTRA_CATALOG_COMPONENT_CFI_CLASSIFICATION")
    require(actual["pageBytes"] == manifest["pageSize"] and
            actual["metadataDisplacement"] == manifest["metadataDisplacement"], "ULTRA_CATALOG_COMPONENT_METADATA")
    proof = {"schema": "maplesu-init-bridge-component/1", "manifestSha256": files["manifest.json"]["sha256"],
             "sourceGenerationSha256": generation, "kmi": manifest["kmi"], "architecture": "arm64",
             "pageSize": manifest["pageSize"], "cfiMode": manifest["cfiMode"],
             "sourceSelection": selection_identity, "strictBuild": build_identity,
             "bundledModule": files[manifest["bridge"]], "artifactQualified": False, "deviceQualified": False}
    dependencies += [(root / name, value) for name, value in files.items()]
    return {"root": root, "files": files, "proof": proof, "generation": generation, "dependencies": dependencies}


def check_shared_generation(output, components):
    legacy_path = output / "catalog.json"
    require(not (output / "manifest.json").exists() or legacy_path.is_file(),
            "ULTRA_CATALOG_LEGACY_GENERATION_REQUIRED")
    if not legacy_path.is_file():
        return []
    legacy = read_json(legacy_path)
    require(legacy.get("schema") == "maplesu-init-bridge-catalog/1", "ULTRA_CATALOG_LEGACY_SCHEMA")
    dependencies = [(legacy_path, identity(legacy_path))]
    required = {"runtime/ultra/identity/kernel/" + name for name in
                ("manager_management.c", "manager_resident_host.c", "manager_task_state.c",
                 "manager_su_runtime_target.c")} | {"jailbreak-providers/root-loader/module/maplesu_boot_sdk.c"}
    for row in legacy.get("variants", []):
        proof_path = output / relative(row["proof"])
        actual = identity(proof_path)
        require(actual["sha256"] == row["proofSha256"], "ULTRA_CATALOG_LEGACY_PROOF_IDENTITY")
        dependencies.append((proof_path, actual))
        proof = read_json(proof_path)
        old = proof.get("generationInputs", {})
        require(sha(encoded(old)) == legacy.get("sourceGenerationSha256"), "ULTRA_CATALOG_LEGACY_GENERATION")
        for component in components:
            new = read_json(component["root"] / "manifest.json")
            source = read_json(component["root"] / new["bundleSources"])["generationInputs"]
            previous, current = old.get("moduleSources", {}), source.get("moduleSources", {})
            require(required <= previous.keys() and required <= current.keys(), "ULTRA_CATALOG_SHARED_SOURCE_CLOSURE")
            require(old.get("handoffSha256") == source.get("handoffSha256") and
                    all(previous[key] == current[key] for key in previous.keys() & current.keys()),
                    "ULTRA_CATALOG_SHARED_GENERATION")
    require(legacy.get("variants"), "ULTRA_CATALOG_LEGACY_VARIANTS")
    return dependencies


def package_components(plan, plan_path, output, append):
    rows = plan.get("components", [])
    require(isinstance(rows, list) and len(rows) <= 64, "ULTRA_CATALOG_PLAN_COMPONENTS")
    components = [inspect_component(row, plan_path.parent) for row in rows]
    generations = {item["generation"] for item in components}
    if not rows:
        require(isinstance(plan.get("sourceGenerationSha256"), str) and HASH.fullmatch(plan["sourceGenerationSha256"]),
                "ULTRA_CATALOG_EMPTY_GENERATION")
        generations.add(plan["sourceGenerationSha256"])
    require(len(generations) == 1, "ULTRA_CATALOG_MIXED_GENERATIONS")
    keys = [(x["proof"]["kmi"], x["proof"]["pageSize"], x["proof"]["cfiMode"]) for x in components]
    require(len(set(keys)) == len(keys), "ULTRA_CATALOG_DUPLICATE_COMPONENT")
    manifests = [x["proof"]["manifestSha256"] for x in components]
    require(len(set(manifests)) == len(manifests), "ULTRA_CATALOG_DUPLICATE_MANIFEST")
    if append:
        require(output.is_dir() and not (output / "catalog-kmi.json").exists() and
                not (output / "components").exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
        shared_dependencies = check_shared_generation(output, components)
    else:
        require(not output.exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
        shared_dependencies = []
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for item in components:
        proof = item["proof"]
        prefix = "components/" + proof["manifestSha256"] + "/"
        for name, expected in item["files"].items():
            destination = output / prefix / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item["root"] / name, destination)
            same(identity(destination), expected, "ULTRA_CATALOG_COPY_CHANGED:" + name)
        (output / prefix / "COMPONENT-PROOF.json").write_bytes(encoded(proof))
        entries.append({field: proof[field] for field in ("kmi", "architecture", "pageSize", "cfiMode", "manifestSha256")})
        entries[-1]["prefix"] = prefix
    for item in components:
        for path, expected in item["dependencies"]:
            same(identity(path), expected, "ULTRA_CATALOG_INPUT_CHANGED:" + str(path))
    for path, expected in shared_dependencies:
        same(identity(path), expected, "ULTRA_CATALOG_INPUT_CHANGED:" + str(path))
    catalog = {"schema": "maplesu-init-bridge-catalog/2", "sourceGenerationSha256": next(iter(generations)),
               "components": sorted(entries, key=lambda x: (x["kmi"], x["pageSize"], x["cfiMode"]))}
    (output / "catalog-kmi.json").write_bytes(encoded(catalog))
    return catalog


def inspect_variant(row, plan_root):
    root = selected_path(plan_root, row["bundle"])
    selection_file = selected_path(plan_root, row["sourceSelection"])
    build_file = selected_path(plan_root, row["strictBuild"])
    manifest_file = root / "manifest.json"
    manifest = read_json(manifest_file)
    require(manifest.get("schemaVersion") == 1, "ULTRA_CATALOG_MANIFEST_SCHEMA")
    require(all(isinstance(manifest.get(field), str) and HASH.fullmatch(manifest[field]) for field in
                ("kernelSha256", "targetBootSha256")), "ULTRA_CATALOG_TARGET_IDENTITY")
    files = {"manifest.json": identity(manifest_file)}
    for field in COMPONENTS:
        if field not in manifest:
            continue
        name = relative(manifest[field])
        require(name not in files, "ULTRA_CATALOG_COMPONENT_CONFLICT")
        component = root / name
        require(not component.is_symlink() and component.resolve().is_relative_to(root), "ULTRA_CATALOG_COMPONENT_SYMLINK")
        files[name] = identity(component)
        require(files[name]["sha256"] == manifest.get(field + "Sha256"), "ULTRA_CATALOG_COMPONENT_HASH:" + field)
    require(all(x in manifest for x in ("targetBoot", "bridge", "handoff", "config", "moduleSymvers", "targetContract", "bundleSources")),
            "ULTRA_CATALOG_COMPONENT_REQUIRED")
    sources = read_json(root / manifest["bundleSources"])
    require(sources.get("schemaVersion") == 1 and isinstance(sources.get("inputs"), dict), "ULTRA_CATALOG_BUNDLE_SOURCES")
    for name, item in sources["inputs"].items():
        bundled = item.get("bundledAs")
        if bundled is not None:
            bundled = relative(bundled)
            actual = identity(root / bundled)
            require(actual["sha256"] == item.get("bundledSha256") and actual["bytes"] == item.get("bundledBytes"),
                    "ULTRA_CATALOG_BUNDLED_SOURCE:" + name)
            files[bundled] = actual
    bridge = sources["inputs"]["bridge"]
    same(identity(Path(bridge["path"])), bridge, "ULTRA_CATALOG_ORIGINAL_MODULE_CHANGED")
    selection_identity = identity(selection_file)
    build_identity = identity(build_file)
    build = read_json(build_file)
    require(build.get("exitCode") == 0 and build.get("inputsUnchanged") is True, "ULTRA_CATALOG_STRICT_BUILD")
    require(any(x.get("path", "").replace("\\", "/").endswith("/SOURCE-SELECTION.json") and
                all(x.get(k) == selection_identity[k] for k in ("bytes", "sha256")) for x in build.get("sources", [])),
            "ULTRA_CATALOG_STRICT_SOURCE_SELECTION")
    artifacts = build.get("artifacts", [])
    if isinstance(artifacts, dict):
        artifacts = [artifacts]
    require(any(all(x.get(k) == bridge[k] for k in ("bytes", "sha256")) for x in artifacts),
            "ULTRA_CATALOG_STRICT_MODULE")
    selection = read_json(selection_file)
    common, dependencies = selection_sources(selection)
    for field, provenance_key in (("sessionAbi", "bridgeProvenance"), ("taskProfileAbi", "provenance")):
        if field not in manifest:
            continue
        abi = read_json(root / manifest[field])
        provenance = abi.get(provenance_key, {})
        same({k: bridge[k] for k in ("bytes", "sha256")}, provenance.get("bridge"), "ULTRA_CATALOG_ABI_MODULE:" + field)
        same(selection_identity, provenance.get("sourceSelection"), "ULTRA_CATALOG_ABI_SOURCE:" + field)
        same(build_identity, provenance.get("strictBuild"), "ULTRA_CATALOG_ABI_BUILD:" + field)
        require(abi.get("bundledModuleSha256") == manifest["bridgeSha256"], "ULTRA_CATALOG_ABI_BUNDLED:" + field)
    generation_inputs = {"moduleSources": common, "handoffSha256": manifest["handoffSha256"]}
    generation = sha(encoded(generation_inputs))
    proof = {"schema": "maplesu-init-bridge-variant/1", "manifestSha256": files["manifest.json"]["sha256"],
             "sourceGenerationSha256": generation, "targetBootSha256": manifest["targetBootSha256"],
             "kernelSha256": manifest["kernelSha256"], "sourceSelection": selection_identity,
             "strictBuild": build_identity, "originalModule": {k: bridge[k] for k in ("bytes", "sha256")},
             "bundledModule": files[manifest["bridge"]], "generationInputs": generation_inputs,
             "targetInputs": {field: manifest[field + "Sha256"] for field in
                              ("config", "moduleSymvers", "targetContract", "btf", "sessionAbi", "taskProfileAbi", "abiEvidence") if field in manifest},
             "artifactQualified": False, "deviceQualified": False}
    dependencies += [(selection_file, selection_identity), (build_file, build_identity),
                     (Path(bridge["path"]), {k: bridge[k] for k in ("bytes", "sha256")})]
    dependencies += [(root / name, value) for name, value in files.items()]
    return {"root": root, "files": files, "proof": proof, "generation": generation, "dependencies": dependencies}


def package(plan_path, output, append=False):
    plan = read_json(plan_path)
    if plan.get("schema") == "maplesu-init-bridge-catalog-plan/2":
        return package_components(plan, plan_path, output, append)
    require(plan.get("schema") == "maplesu-init-bridge-catalog-plan/1", "ULTRA_CATALOG_PLAN_SCHEMA")
    rows = plan.get("variants", [])
    require(isinstance(rows, list) and 1 <= len(rows) <= 64, "ULTRA_CATALOG_PLAN_VARIANTS")
    variants = [inspect_variant(row, plan_path.parent) for row in rows]
    generations = {item["generation"] for item in variants}
    require(len(generations) == 1, "ULTRA_CATALOG_MIXED_GENERATIONS")
    manifests = [item["proof"]["manifestSha256"] for item in variants]
    require(len(set(manifests)) == len(manifests), "ULTRA_CATALOG_DUPLICATE_MANIFEST")
    default = plan.get("defaultManifestSha256")
    require(default in manifests, "ULTRA_CATALOG_DEFAULT_REQUIRED")
    chosen = variants[manifests.index(default)]
    if append:
        require(output.is_dir() and identity(output / "manifest.json")["sha256"] == default, "ULTRA_CATALOG_DEFAULT_CHANGED")
        require(not (output / "catalog-kmi.json").exists(), "ULTRA_CATALOG_PUBLISH_EXACT_BEFORE_COMPONENTS")
        for name, expected in chosen["files"].items():
            same(identity(output / name), expected, "ULTRA_CATALOG_DEFAULT_COMPONENT_CHANGED:" + name)
        require(not (output / "catalog.json").exists() and not (output / "variants").exists()
                and not (output / "catalog-proofs").exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
    else:
        require(not output.exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
    # All identities are checked before writing; the index is published last, never a partial choice.
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for item in variants:
        proof = item["proof"]
        manifest = proof["manifestSha256"]
        prefix = "" if manifest == default else "variants/" + manifest + "/"
        if not append or prefix:
            for name, expected in item["files"].items():
                destination = output / prefix / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(item["root"] / name, destination)
                same(identity(destination), expected, "ULTRA_CATALOG_COPY_CHANGED:" + name)
        proof_path = "catalog-proofs/" + manifest + ".json"
        proof_bytes = encoded(proof)
        (output / "catalog-proofs").mkdir(exist_ok=True)
        (output / proof_path).write_bytes(proof_bytes)
        entries.append({"manifestSha256": manifest, "prefix": prefix, "targetBootSha256": proof["targetBootSha256"],
                        "kernelSha256": proof["kernelSha256"], "sourceGenerationSha256": item["generation"],
                        "proof": proof_path, "proofSha256": sha(proof_bytes)})
    for item in variants:
        for path, expected in item["dependencies"]:
            same(identity(path), expected, "ULTRA_CATALOG_INPUT_CHANGED:" + str(path))
    catalog = {"schema": "maplesu-init-bridge-catalog/1", "sourceGenerationSha256": next(iter(generations)),
               "defaultManifestSha256": default, "variants": sorted(entries, key=lambda x: x["manifestSha256"])}
    (output / "catalog.json").write_bytes(encoded(catalog))
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--append-to-default", action="store_true")
    args = parser.parse_args()
    print(json.dumps(package(args.plan.resolve(), args.output.resolve(), args.append_to_default), sort_keys=True))


if __name__ == "__main__":
    main()
