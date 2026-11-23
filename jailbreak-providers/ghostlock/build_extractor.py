"""Build the retained Ghostlock extractor for Android, without a research checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / "extractor-native"
NAME = "libmaplesu_ghostlock_extract.so"


def verify_dependencies():
    manifest = json.loads((NATIVE / "dependency-manifest.json").read_text(encoding="utf-8"))
    expected = set()
    for item in manifest["files"]:
        path = (NATIVE / item["path"]).resolve()
        if not path.is_relative_to((NATIVE / "vendor").resolve()) or path in expected:
            raise ValueError("invalid extractor dependency path")
        expected.add(path)
        data = path.read_bytes()
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("extractor dependency changed: " + item["path"])
    actual = {p.resolve() for p in (NATIVE / "vendor").rglob("*") if p.is_file()}
    if actual != expected:
        raise ValueError("unmanifested extractor dependency")


def build(ndk, output):
    verify_dependencies()
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    tools = ndk / "toolchains/llvm/prebuilt" / host / "bin"
    compiler = tools / ("aarch64-linux-android29-clang.cmd" if os.name == "nt"
                        else "aarch64-linux-android29-clang")
    archive = tools / ("llvm-ar.exe" if os.name == "nt" else "llvm-ar")
    if not compiler.is_file() or not archive.is_file():
        raise ValueError("extractor NDK tools missing")
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo.exe")
    toolchain = os.environ.get("MAPLESU_RUST_TOOLCHAIN",
                               "stable-x86_64-pc-windows-gnu" if os.name == "nt" else "stable")
    env = os.environ.copy()
    env.update(CC_aarch64_linux_android=str(compiler),
               AR_aarch64_linux_android=str(archive),
               CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=str(compiler),
               CARGO_NET_OFFLINE="false",
               CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS=
               "-C force-unwind-tables=no -C link-arg=-Wl,-z,max-page-size=16384")
    if toolchain.endswith("windows-gnu"):
        rust_home = Path(env.get("RUSTUP_HOME", str(Path.home() / ".rustup")))
        gnu_bin = rust_home / "toolchains" / toolchain / "lib/rustlib/x86_64-pc-windows-gnu/bin"
        mingw = env.get("MAPLESU_MINGW_BIN", "")
        env["PATH"] = os.pathsep.join(filter(None, [str(gnu_bin), mingw, env.get("PATH", "")]))
        env["CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER"] = str(gnu_bin / "rust-lld.exe")
    target_dir = Path(env.get("MAPLESU_GHOSTLOCK_CARGO_TARGET_DIR", str(output / "cargo")))
    # Keep prost-build's generated descriptor files inside the build window.
    # The host TEMP may be ACL-restricted or contain a stale directory from a
    # prior interrupted Cargo run; using the output-owned directory preserves
    # the same inputs while making the build reproducible on Windows.
    build_temp = target_dir.parent / "tmp"
    build_temp.mkdir(parents=True, exist_ok=True)
    env.update(TEMP=str(build_temp), TMP=str(build_temp), TMPDIR=str(build_temp))
    command = [cargo, "+" + toolchain, "build", "--locked", "--release",
               "--target", "aarch64-linux-android", "--target-dir", str(target_dir),
               "--manifest-path", str(NATIVE / "Cargo.toml")]
    subprocess.run(command, env=env, check=True)
    binary = target_dir / "aarch64-linux-android/release/ghostlock-extract"
    destination = output / NAME
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, destination)
    data = destination.read_bytes()
    if data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or int.from_bytes(data[18:20], "little") != 183:
        raise ValueError("extractor is not an arm64 ELF")
    (output / "build.json").write_text(json.dumps({
        "name": NAME, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        "upstreamCommit": "b67359641c8663e5184abba73ecdf2c456dce3e7",
        "command": command,
    }, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify_only:
        verify_dependencies()
    else:
        if args.ndk is None or args.output is None:
            parser.error("--ndk and --output are required for a build")
        build(args.ndk.resolve(), args.output.resolve())
