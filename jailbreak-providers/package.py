"""Stage built provider natives and their identity manifest for the APK.

The manifest is what the App verifies at runtime: entry name, built digest, target
KMI and the kernel module digest that was actually embedded. Regenerating it is
part of the packaging edge, so a shipped APK can never carry an unlisted entry.

R12 (review 2026-10-26): copying a product and re-hashing it proves only that the
copy is self-consistent. The build report names a digest and a size for every
product, so those are verified *before* anything is written, the requested KO
variant must be the variant that is actually derived in the report, and the
target directory is emptied first so a stale file from an earlier build can never
ride along. Ghostlock's pinned exact-profile set is packaged and digest-listed
here too, because the product cannot resolve a profile it never shipped.
"""
import argparse
import hashlib
import gzip
import json
import sys
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REQUIRED = {
    "libmaplesu_root_consumer.so": {"targetKmi": "", "provider": "shared"},
    "libdfroot.so": {"targetKmi": "", "provider": "dirtyfrag"},
    "libmaplesu_dirtyfrag_bootstrap.so": {"targetKmi": "", "provider": "dirtyfrag"},
    "libmaplesu_ghostlock_provider.so": {"targetKmi": "", "provider": "ghostlock"},
    "libmaplesu_ghostlock_extract.so": {"targetKmi": "", "provider": "ghostlock"},
}
PROFILE_MANIFEST = HERE / "ghostlock" / "upstream-manifest.json"
PROFILE_DIR = HERE / "ghostlock" / "upstream" / "app" / "src" / "main" / "assets" / "kernel_profiles"
PROFILE_ASSET = "ghostlock"
# MapleSU's own profiles live outside the retained upstream bytes: they are
# converted from public anchors and must stay individually reviewable.
PRODUCT_PROFILE_DIR = HERE / "ghostlock" / "product-profiles"
PRODUCT_PROFILE_MANIFEST = PRODUCT_PROFILE_DIR / "manifest.json"
INDEX_ENTRY = re.compile(r'\{\s*release\s*=\s*"([^"]+)"\s*,\s*file\s*=\s*"([^"]+)"\s*\}')
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message):
    # Gradle hides SystemExit messages, so surface the reason on stderr as well.
    print("package.py: " + str(message), file=sys.stderr)
    raise SystemExit(message)


def verify_product(record, name):
    """The report's own identity for one product must still describe the file."""
    for field in ("path", "sha256", "bytes"):
        if field not in record:
            fail("build report entry for " + name + " has no " + field)
    if not DIGEST.match(str(record["sha256"])):
        fail("build report digest for " + name + " is not a sha256")
    source = Path(record["path"])
    if not source.is_file():
        fail("missing product " + str(source))
    actual_bytes = source.stat().st_size
    if actual_bytes != int(record["bytes"]):
        fail("product size drift for %s: report=%s file=%s"
             % (name, record["bytes"], actual_bytes))
    actual = sha(source)
    if actual != record["sha256"]:
        fail("product digest drift for %s: report=%s file=%s"
             % (name, record["sha256"], actual))
    return source


def ko_record(report, variant):
    overlay = report.get("dirtyfragOverlay", {}).get("content", {})
    if not overlay:
        fail("build report has no dirtyfrag overlay")
    if report.get("koVariant") != variant:
        fail("requested KO variant %s but the build produced %s"
             % (variant, report.get("koVariant")))
    modules = report.get("dirtyfragModules")
    if not modules:
        fail("build report has no embedded DirtyFrag module inventory; rebuild the providers")
    expected = {Path(key).name.removeprefix("dfroot-").removesuffix(".minimal.ko")
                for key in overlay.get("files", {}) if key.endswith(".minimal.ko")}
    if set(modules) != expected:
        fail("embedded DirtyFrag module inventory differs from the derived family set")
    images = {}
    for kmi, record in sorted(modules.items()):
        source = verify_product(record, "DirtyFrag " + kmi)
        images[kmi] = {"sha256": record["sha256"], "bytes": source.stat().st_size}
    return images


def profiles():
    """Copies the pinned exact-profile set and returns its identity records."""
    if not PROFILE_MANIFEST.is_file():
        fail("ghostlock upstream manifest is missing")
    manifest = json.loads(PROFILE_MANIFEST.read_text(encoding="utf-8"))
    retained = {}
    for item in manifest.get("files", []):
        path = item.get("path", "")
        if path.startswith("upstream/app/src/main/assets/kernel_profiles/"):
            retained[path.rsplit("/", 1)[1]] = item
    if not retained:
        fail("ghostlock manifest lists no kernel profiles")
    index = PROFILE_DIR / "index.conf"
    if not index.is_file():
        fail("ghostlock profile index is missing")
    entries = INDEX_ENTRY.findall(index.read_text(encoding="utf-8"))
    if not entries:
        fail("ghostlock profile index has no registrations")
    files = []
    for name, record in sorted(retained.items()):
        source = PROFILE_DIR / name
        if not source.is_file():
            fail("retained profile is missing: " + name)
        actual = sha(source)
        if record.get("sha256") and actual != record["sha256"]:
            fail("retained profile digest mismatch: " + name)
        files.append({"file": name, "sha256": actual, "bytes": source.stat().st_size})
    registered = []
    for release, name in entries:
        if name not in retained:
            fail("profile index points at an unshipped file: " + name)
        registered.append({"release": release, "file": name})
    # Product profiles: our own conversions, pinned by their own manifest so a
    # change is either a deliberate manifest edit or a hard failure.
    if PRODUCT_PROFILE_MANIFEST.is_file():
        product = json.loads(PRODUCT_PROFILE_MANIFEST.read_text(encoding="utf-8"))
        for item in product.get("profiles", []):
            name = item.get("file", "")
            release = item.get("release", "")
            source = PRODUCT_PROFILE_DIR / name
            if not name or not release or not source.is_file():
                fail("product profile record is incomplete: " + repr(item))
            actual = sha(source)
            if item.get("sha256") and actual != item["sha256"]:
                fail("product profile digest mismatch: " + name)
            if any(entry["release"] == release for entry in registered):
                fail("product profile duplicates a registered release: " + release)
            files.append({"file": name, "sha256": actual, "bytes": source.stat().st_size})
            registered.append({"release": release, "file": name})
    return files, registered


def stage_profiles(assets_dir):
    files, registered = profiles()
    target = assets_dir / PROFILE_ASSET
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for record in files:
        source = PROFILE_DIR / record["file"]
        if not source.is_file():
            source = PRODUCT_PROFILE_DIR / record["file"]
        shutil.copy2(source, target / record["file"])
    return files, registered


IR_ASSET_DIR = "maplesu/ir"
# Ultra target: release-independent root module, no per-kernel spec beside it.
ROOT_ASSET_DIR = "maplesu/root"
# L3 target (ABI v1): the su gate the UMH helper loads from the attempt's stage-2
# slot. Packaged as its own block so the App can state `suGate` from the manifest
# instead of guessing: no block means no kernel su for this build.
L3_ASSET_DIR = "maplesu/l3"


def stage_ir(report, assets_dir):
    """Stage the in-kernel module and its per-release specs as APK assets.

    The App resolves a release by `uname -r` at runtime, so the set packaged here
    *is* the adaptation list: a release that is not in this directory must produce
    MAPLESU_IR_UNSUPPORTED on the device instead of attempting a kernel patch with
    offsets that were never verified. Every digest is re-taken from the file that is
    actually copied, and the recorded one is compared to it.
    """
    ir = report.get("ir")
    if not ir or "build" not in ir:
        fail("build report has no in-kernel module (ir); refusing to package an APK "
             "whose jailbreak cannot install its kernel root")
    build = ir["build"]
    module_source = Path(build["module"])
    if not module_source.is_file():
        fail("in-kernel module is missing: " + str(module_source))
    if sha(module_source) != build["sha256"]:
        fail("in-kernel module changed since it was built")
    target = assets_dir / IR_ASSET_DIR
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    module_name = module_source.name
    shutil.copy2(module_source, target / module_name)
    if sha(target / module_name) != build["sha256"]:
        fail("copied in-kernel module digest changed")
    specs = []
    for record in ir.get("specs", []):
        source = Path(record["path"])
        if not source.is_file():
            fail("spec is missing: " + str(source))
        if sha(source) != record["sha256"]:
            fail("spec changed since it was generated: " + source.name)
        destination = target / source.name
        shutil.copy2(source, destination)
        if sha(destination) != record["sha256"]:
            fail("copied spec digest changed: " + source.name)
        specs.append({
            "release": record["release"],
            "asset": IR_ASSET_DIR + "/" + source.name,
            "sha256": record["sha256"],
            "bytes": destination.stat().st_size,
            "imageSha256": record.get("imageSha256", ""),
            "blocks": record.get("blocks", []),
        })
    canary_block = None
    canary = ir.get("canary")
    if canary:
        source = Path(canary["path"])
        if not source.is_file():
            fail("canary module is missing: " + str(source))
        if sha(source) != canary["sha256"]:
            fail("canary module changed since it was built")
        destination = target / source.name
        shutil.copy2(source, destination)
        if sha(destination) != canary["sha256"]:
            fail("copied canary digest changed")
        canary_block = {"asset": IR_ASSET_DIR + "/" + source.name,
                        "sha256": canary["sha256"],
                        "bytes": destination.stat().st_size,
                        "purpose": "loader-contract canary; bring-up probes only"}
    # Root-loader canary helper asset. Step-2 shipped a dedicated 5.5 KB helper here;
    # step-3 removed it because the module now execs `<CE>/bs` (the bootstrap the App
    # stages on every route - design §3.4). The block therefore stays optional: a
    # record without a helper, or with an empty devicePath, is the new normal and must
    # not fail packaging. A build that still carries one is packaged exactly as before,
    # so a step-2 frozen set stays reproducible from its own report.
    root_canary = ir.get("rootCanary") or {}
    helper_block = None
    helper = root_canary.get("helper")
    helper_path = (helper or {}).get("path")
    helper_device = (helper or {}).get("devicePath", "")
    if helper and helper_device and helper_path:
        source = Path(helper["path"])
        if not source.is_file():
            fail("canary helper is missing: " + str(source))
        if sha(source) != helper["sha256"]:
            fail("canary helper changed since it was built")
        destination = target / source.name
        shutil.copy2(source, destination)
        if sha(destination) != helper["sha256"]:
            fail("copied canary helper digest changed")
        helper_block = {
            "asset": IR_ASSET_DIR + "/" + source.name,
            "sha256": helper["sha256"],
            "bytes": destination.stat().st_size,
            "devicePath": helper_device,
            "deviceMode": helper.get("deviceMode", ""),
            "purpose": "root-loader canary helper (step-2 packaging only; step-3 "
                       "execs the App-staged <CE>/bs instead)",
        }
    if root_canary.get("enabled"):
        # The point of this mode: the deprecated per-release module must not be able
        # to reach the device through the product IR slot.
        if not build.get("facts", {}).get("stub"):
            fail("root-canary packaging needs the product IR slot to carry the stub")
        if canary_block is None:
            fail("root-canary packaging needs the canary slot to carry the module")
        # No helper requirement: from step-3 the handover target is `<CE>/bs`.
    if not specs:
        fail("the build produced no per-release specs; an empty adaptation list is not shippable")
    # Ultra's kernel payload. Packaged on every product build and verified here, so
    # the root block an APK advertises is always the module this build gated.
    root_block = None
    root = report.get("root") or {}
    root_module = root.get("module") or {}
    if root_module.get("path"):
        source = Path(root_module["path"])
        if not source.is_file():
            fail("root module is missing: " + str(source))
        if sha(source) != root_module["sha256"]:
            fail("root module changed since it was built")
        root_target = assets_dir / ROOT_ASSET_DIR
        if root_target.exists():
            shutil.rmtree(root_target)
        root_target.mkdir(parents=True)
        destination = root_target / source.name
        shutil.copy2(source, destination)
        if sha(destination) != root_module["sha256"]:
            fail("copied root module digest changed")
        root_block = {
            "asset": ROOT_ASSET_DIR + "/" + source.name,
            "sha256": root_module["sha256"],
            "bytes": destination.stat().st_size,
            "imports": root_module.get("imports") or [],
            "kcfiInitTypeId": root_module.get("kcfiInitTypeId") or "",
            "releaseIndependent": True,
            "purpose": "Ultra target: symbols resolved at load time, no per-release spec",
        }
    # L3 su gate. Optional in the sense that a tree without the L3 module still
    # packages a working handover: the absence is then visible as `l3Module: null`
    # and the App reports suGate=UNAVAILABLE, which is the truth. A build that says
    # it FAILED is refused here, because shipping it would advertise an su that the
    # build itself has already decided cannot work.
    l3 = report.get("l3") or {}
    if l3.get("state") == "FAILED":
        fail("the L3 module build failed: " + str(l3.get("error") or l3.get("exitCode")))
    l3_block = None
    l3_module = l3.get("module") or {}
    if l3_module.get("path"):
        source = Path(l3_module["path"])
        if not source.is_file():
            fail("l3 module is missing: " + str(source))
        if sha(source) != l3_module["sha256"]:
            fail("l3 module changed since it was built")
        l3_target = assets_dir / L3_ASSET_DIR
        if l3_target.exists():
            shutil.rmtree(l3_target)
        l3_target.mkdir(parents=True)
        destination = l3_target / source.name
        shutil.copy2(source, destination)
        if sha(destination) != l3_module["sha256"]:
            fail("copied l3 module digest changed")
        l3_block = {
            "asset": L3_ASSET_DIR + "/" + source.name,
            "sha256": l3_module["sha256"],
            "bytes": destination.stat().st_size,
            "kernelRelease": l3_module.get("kernelRelease") or "",
            "kmi": l3_module.get("kmi") or "",
            "purpose": "L3 su gate: loaded by the UMH helper from "
                       "<CE>/maplesu_stage2.ko inside the module's window",
        }
    else:
        # No l3 block means this build ships no kernel su. A stale module from an
        # earlier build must not ride along as an unreferenced asset.
        l3_target = assets_dir / L3_ASSET_DIR
        if l3_target.exists():
            shutil.rmtree(l3_target)
    l3_modules = {}
    for kmi, record in l3.get("modules", {}).items():
        if not re.fullmatch(r"android\d+-\d+\.\d+", kmi) or record.get("kmi") != kmi:
            fail("invalid L3 family identity: " + kmi)
        source = verify_product(record, "L3 " + kmi)
        destination = assets_dir / L3_ASSET_DIR / kmi / "maplesu_l3.ko"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        l3_modules[kmi] = {
            "asset": destination.relative_to(assets_dir).as_posix(),
            "sha256": record["sha256"], "bytes": destination.stat().st_size,
            "kernelRelease": record.get("kernelRelease", ""), "kmi": kmi,
        }
    return {
        "module": {
            "asset": IR_ASSET_DIR + "/" + module_name,
            "sha256": build["sha256"],
            "bytes": (target / module_name).stat().st_size,
            "kcfiInitTypeId": build.get("facts", {}).get("kcfiInitTypeId", ""),
            "imports": build.get("facts", {}).get("imports", []),
            "stub": bool(build.get("facts", {}).get("stub")),
        },
        "specSection": ".ir_spec",
        "specs": specs,
        "root": root_block,
        # Same shape as `root`, so one parser reads both (IrImages.Module).
        "l3Module": l3_block,
        "l3Modules": l3_modules,
        "canary": canary_block,
        "canaryHelper": helper_block,
        # The path the packaged module actually execs (step-3: <CE>/bs). Recorded even
        # when no helper asset rides along, so the APK states the handover target.
        "canaryHelperPath": root_canary.get("helperPath"),
        "mode": "root-canary" if root_canary.get("enabled") else "product",
    }


MAPLESU93260_DIR = HERE / "maplesu-93260"
MAPLESU93260_DEVICE_NAMES = {"louise", "louise_cmd.sh", "probe", "PD2546-symbols.json"}
MAPLESU93260_ADDRESS_FIELDS = ("imageBase", "kprobeTable", "loadModule",
                               "moduleNotifyList", "traceModuleNotify", "traceSysExit")
MAPLESU93260_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
MAPLESU93260_KMI = re.compile(r"android\d{2}-\d+\.\d+")
MAPLESU93260_ADDRESS = re.compile(r"[0-9a-f]{1,16}")
MAPLESU93260_RUNNER = re.compile(r"plant-[0-9]{5}")
# The retained upstream exploit source (GPL-3.0) carries the per-kernel offset
# tables. We compile our own plants from it; upstream release binaries are not
# distributed.
SHARK_DIR = HERE / "shark"
SHARK_MANIFEST = SHARK_DIR / "manifest.json"
SHARK_PLANTS = SHARK_DIR / "plants" / "arm64-v8a"


def _build_missing_plants() -> None:
    """Compile the per-kernel plants when the exported tree carries no built copies."""
    builder = SHARK_DIR / "build_plants.py"
    if not builder.is_file():
        fail("plant builder missing")
    print("package.py: no built plants in the tree; compiling them from retained sources", flush=True)
    result = subprocess.run([sys.executable, str(builder)], cwd=str(HERE))
    if result.returncode:
        fail("plant build failed")


def planted_artifacts():
    """Our built plant digests, verified against the retained manifest."""
    if not SHARK_MANIFEST.is_file():
        fail("plant manifest missing")
    if not (SHARK_PLANTS / "plant-61821").is_file():
        _build_missing_plants()
    document = json.loads(SHARK_MANIFEST.read_text(encoding="utf-8"))
    records = {}
    for item in document.get("plants") or []:
        name = str(item.get("name", ""))
        source = SHARK_PLANTS / name
        if not MAPLESU93260_RUNNER.fullmatch(name) or not source.is_file():
            fail("plant missing: " + name)
        if source.stat().st_size != item.get("bytes") or sha(source) != item.get("sha256"):
            fail("plant drift: " + name)
        records[name] = item
    if not records:
        fail("plant manifest carries no plants")
    # The matching exploit source is part of the distributed record: verify it too,
    # so a plant update cannot ship without its corresponding source.
    for item in document.get("sources") or []:
        path = str(item.get("path", ""))
        source = SHARK_DIR / path
        if not path or not source.is_file():
            fail("plant source missing: " + path)
        if source.stat().st_size != item.get("bytes") or sha(source) != item.get("sha256"):
            fail("plant source drift: " + path)
    return records


def verify_maplesu93260_profile(profile, plants):
    """Rejects a profile the App would refuse, at build time instead of on a device."""
    profile_id = str(profile.get("id", ""))
    engine = str(profile.get("engine") or "retained")
    if not MAPLESU93260_ID.fullmatch(profile_id):
        fail("MapleSU_93260 profile id is not a payload-safe name: " + profile_id)
    if not str(profile.get("variant", "")).strip():
        fail("MapleSU_93260 profile " + profile_id + " has no variant")
    if not MAPLESU93260_KMI.fullmatch(str(profile.get("kmi", ""))):
        fail("MapleSU_93260 profile " + profile_id + " has an invalid kmi")
    if not isinstance(profile.get("kernelUapi"), int) or profile["kernelUapi"] <= 0:
        fail("MapleSU_93260 profile " + profile_id + " has an invalid kernelUapi")
    if engine == "retained":
        addresses = profile.get("addresses") or {}
        for field in MAPLESU93260_ADDRESS_FIELDS:
            value = str(addresses.get(field, ""))
            if not MAPLESU93260_ADDRESS.fullmatch(value) or int(value, 16) == 0:
                fail("MapleSU_93260 profile " + profile_id + " has no usable " + field)
    elif engine == "plant":
        runner = str(profile.get("runner", ""))
        if runner not in plants:
            fail("MapleSU_93260 profile " + profile_id + " names an unbuilt plant: " + runner)
    else:
        fail("MapleSU_93260 profile " + profile_id + " has an unknown engine: " + engine)
    page = profile.get("pageSize")
    if page is not None and not re.fullmatch(r"\d+k", str(page)):
        fail("MapleSU_93260 profile " + profile_id + " has an invalid pageSize")


def stage_maplesu93260_payload(assets_dir, profile, source_root, prefix):
    """Stages one kernel profile's payload set and returns its digest records.

    Every profile publishes the same four device-side names, because the retained
    flow reads them verbatim. The profile's own asset names may differ; the
    device name is what the APK inventory and `Payload` agree on.
    """
    payload = profile.get("payload") or {}
    mapping = payload.get("files") or {}
    if not mapping:
        fail("MapleSU_93260 profile " + str(profile.get("id")) + " has no payload mapping")
    if set(mapping.values()) != MAPLESU93260_DEVICE_NAMES:
        fail("MapleSU_93260 profile " + str(profile.get("id")) +
             " must publish exactly " + ", ".join(sorted(MAPLESU93260_DEVICE_NAMES)))
    records = []
    for name, device in mapping.items():
        source = source_root / name
        if not source.is_file():
            fail("MapleSU_93260 payload missing: " + str(source))
        raw = source.read_bytes()
        compressed = name.endswith(".bin")
        decoded = gzip.decompress(raw) if compressed else raw
        destination = assets_dir / prefix / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        records.append({"device": device, "asset": destination.relative_to(assets_dir).as_posix(),
                        "sha256": sha(source), "bytes": len(raw), "gzip": compressed,
                        "decodedSha256": hashlib.sha256(decoded).hexdigest(), "decodedBytes": len(decoded)})
    return records


def stage_maplesu93260_plant(assets_dir, profile):
    """Stages one of our built per-kernel plants and returns its digest record."""
    name = str(profile.get("runner", ""))
    if not MAPLESU93260_RUNNER.fullmatch(name):
        fail("MapleSU_93260 profile " + str(profile.get("id")) + " has an invalid plant name")
    source = SHARK_PLANTS / name
    if not source.is_file():
        fail("plant missing: " + name)
    raw = source.read_bytes()
    destination = assets_dir / "maplesu-93260/plant" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return {
        "asset": destination.relative_to(assets_dir).as_posix(),
        "sha256": sha(source),
        "bytes": len(raw),
        "gzip": False,
        "decodedSha256": sha(source),
        "decodedBytes": len(raw),
    }


def stage_maplesu93260(assets_dir):
    provider = HERE / "maplesu-93260"
    manifest = json.loads((provider / "upstream-manifest.json").read_text(encoding="utf-8"))
    # Verify retained Kotlin as well: source drift must be an explicit manifest update.
    for item in manifest["files"]:
        source = provider / item["path"]
        if source.stat().st_size != item["bytes"] or sha(source) != item["sha256"]:
            fail("MapleSU_93260 retained source drift: " + item["path"])
    # The catalog is MapleSU's own data: which exact builds this APK can serve and
    # which known builds it only recognises. A missing file is a packaging error.
    profiles_path = provider / "profiles.json"
    if not profiles_path.is_file():
        fail("MapleSU_93260 profiles.json missing")
    document = json.loads(profiles_path.read_text(encoding="utf-8"))
    default_id = str(document.get("defaultProfile", ""))
    plants = planted_artifacts()
    profiles = []
    seen_ids = set()
    seen_releases = set()
    seen_payload = set()
    for profile in document.get("profiles") or []:
        profile_id = str(profile.get("id", ""))
        engine = str(profile.get("engine") or "retained")
        releases = [str(item) for item in profile.get("releases") or []]
        payload_key = str(profile.get("payloadKey") or profile_id)
        verify_maplesu93260_profile(profile, plants)
        if not profile_id or profile_id in seen_ids:
            fail("MapleSU_93260 duplicate or empty profile id: " + profile_id)
        if not releases:
            fail("MapleSU_93260 profile " + profile_id + " declares no release")
        if not MAPLESU93260_ID.fullmatch(payload_key):
            fail("MapleSU_93260 profile " + profile_id + " has a payload-unsafe payloadKey")
        for release in releases:
            if release in seen_releases:
                fail("MapleSU_93260 release served twice: " + release)
            seen_releases.add(release)
        if payload_key in seen_payload:
            fail("MapleSU_93260 duplicate payload key: " + payload_key)
        seen_payload.add(payload_key)
        seen_ids.add(profile_id)
        entry = {key: value for key, value in profile.items()
                 if key not in ("payload", "addresses", "runner")}
        entry["engine"] = engine
        entry["kernelRelease"] = releases[0]
        if engine == "retained":
            entry["addresses"] = profile.get("addresses") or {}
            payload = profile.get("payload") or {}
            source_root = provider / str(payload.get("source", ""))
            if profile_id == default_id:
                # The retained 3.8.10 payload set is the compiled default; it must
                # be the same build the upstream manifest pins.
                if releases != [manifest["kernelRelease"]]:
                    fail("MapleSU_93260 default profile release differs from the retained manifest")
                prefix = "maplesu-93260/payload"
            else:
                prefix = "maplesu-93260/payload/" + payload_key
            entry["files"] = stage_maplesu93260_payload(assets_dir, profile, source_root, prefix)
        else:
            # `runner` stays the profile's name (the catalog matches it); the
            # digest record lives in `runnerFile` so the two never collide.
            entry["runner"] = str(profile.get("runner"))
            entry["runnerFile"] = stage_maplesu93260_plant(assets_dir, profile)
        profiles.append(entry)
    if not profiles or profiles[0]["id"] != default_id:
        fail("MapleSU_93260 default profile " + default_id + " is not packaged first")
    default_files = profiles[0].get("files")
    if not default_files or len(default_files) != len(MAPLESU93260_DEVICE_NAMES):
        fail("MapleSU_93260 default payload set is incomplete")
    declared = []
    declared_releases = set()
    for item in document.get("declared") or []:
        release = str(item.get("release", ""))
        if not release or release in seen_releases or release in declared_releases:
            continue
        if not str(item.get("variant", "")).strip():
            fail("MapleSU_93260 declared entry without a variant: " + release)
        declared_releases.add(release)
        declared.append(item)
    catalog = document.get("catalog") or {}
    return {
        "source": manifest["source"],
        "kernelRelease": manifest["kernelRelease"],
        "defaultProfile": default_id,
        "catalog": catalog,
        "profiles": profiles,
        # Retained shape: the default profile's payload set, still the first one.
        "files": default_files,
        "declared": declared,
    }


def build(report, output_dir, jni_dir, manifest_path, variant="minimal"):
    products = {item["name"]: item for item in report.get("artifacts", [])}
    ko_images = ko_record(report, variant)
    overlay = report["dirtyfragOverlay"]["content"]
    entries = []
    # A stale product from an earlier build must never be shipped as this one.
    if jni_dir.exists():
        shutil.rmtree(jni_dir)
    (jni_dir / "arm64-v8a").mkdir(parents=True, exist_ok=True)
    for name, spec in REQUIRED.items():
        record = products.get(name)
        if record is None:
            if name == "libmaplesu_ghostlock_provider.so":
                continue
            fail("build report is missing " + name)
        source = verify_product(record, name)
        target = jni_dir / "arm64-v8a" / name
        target.write_bytes(source.read_bytes())
        digest = sha(target)
        if digest != record["sha256"]:
            fail("copied product digest changed for " + name)
        entries.append({
            "name": name,
            "sha256": digest,
            "bytes": target.stat().st_size,
            "provider": spec["provider"],
            "targetKmi": spec["targetKmi"],
            "koVariant": variant,
            "koFile": "",
            "koSha256": "",
            "koImages": ko_images if spec["provider"] == "dirtyfrag" else {},
        })
    assets_dir = manifest_path.parent
    assets_dir.mkdir(parents=True, exist_ok=True)
    profile_files, profile_index = stage_profiles(assets_dir)
    ir_block = stage_ir(report, assets_dir)
    document = {
        "schemaVersion": 2,
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "contract": "TRANSIENT_PROVIDER_RESTORE_V1",
        "koVariant": variant,
        "sourceCommit": overlay.get("upstreamCommit", ""),
        "derivedKoSourceRebuilt": overlay.get("derivedKoSourceRebuilt", False),
        "artifacts": entries,
        "profiles": profile_index,
        "profileFiles": profile_files,
        "profileRoot": PROFILE_ASSET,
        "ir": ir_block,
        "maplesu93260": stage_maplesu93260(assets_dir),
    }
    manifest_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True, help="provider build output directory")
    parser.add_argument("--jni", type=Path, required=True, help="generated jniLibs directory")
    parser.add_argument("--manifest", type=Path, required=True, help="manifest JSON path")
    parser.add_argument("--ko-variant", default="minimal", help="KO variant that must be packaged")
    args = parser.parse_args()
    report = json.loads((args.build / "build.json").read_text(encoding="utf-8"))
    if report.get("exitCode") != 0 or not report.get("inputsStable"):
        raise SystemExit("provider build is not a clean, input-stable build")
    print(json.dumps(build(report, args.build, args.jni, args.manifest, args.ko_variant), indent=2))
