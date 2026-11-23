"""Compile and invoke the Android manager's actual Kotlin generator on the host JVM."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HOST_CACHE = Path(tempfile.gettempdir()) / 'MapleSU-specgen-product'
JVM_FLAGS = ['-no-stdlib', '-no-reflect', '-jvm-target', '17']


def _fetch_from_maven(group: str, artifact: str, version: str) -> Path:
    """Fetch a host-only dependency Gradle has not resolved into its cache yet."""
    target = HOST_CACHE / "deps" / (artifact + "-" + version + ".jar")
    if target.is_file():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    url = ("https://repo.maven.apache.org/maven2/" + group.replace(".", "/") + "/"
           + artifact + "/" + version + "/" + artifact + "-" + version + ".jar")
    with urllib.request.urlopen(url, timeout=180) as response:
        target.write_bytes(response.read())
    return target


def cached_jar(group: str, artifact: str, version: str) -> Path:
    cache = Path(os.environ.get("GRADLE_USER_HOME", Path.home() / ".gradle"))
    files = sorted((cache / "caches/modules-2/files-2.1" / group / artifact / version).glob("*/*.jar"))
    if not files:
        try:
            files = [_fetch_from_maven(group, artifact, version)]
        except Exception as error:
            raise RuntimeError("ULTRA_HOST_DEPENDENCY_MISSING:" + artifact) from error
    return files[0]


class _HostBuildFailure(RuntimeError):
    def __init__(self, code: str, result: subprocess.CompletedProcess):
        self.returncode = result.returncode
        super().__init__(f'{code}:{result.returncode}\n{result.stdout}{result.stderr}')


def _checked_build(command: list[str], code: str) -> None:
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode:
        raise _HostBuildFailure(code, result)


def _fingerprint(paths: list[Path], flags: list[str]) -> str:
    digest = hashlib.sha256(json.dumps(flags).encode())
    for path in [Path(__file__), *paths]:
        digest.update(str(path.resolve()).encode())
        digest.update(b'\0')
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _image_core_jar(java: str, explicit=None) -> Path:
    if explicit:
        image = Path(explicit)
        if not image.is_file():
            raise RuntimeError('ULTRA_HOST_IMAGE_CORE_MISSING:' + str(image))
        return image
    suffix = '.exe' if os.name == 'nt' else ''
    javac, jar_tool = (Path(java).parent / (name + suffix) for name in ('javac', 'jar'))
    for tool in (javac, jar_tool):
        if not tool.is_file():
            raise RuntimeError('ULTRA_HOST_JDK_TOOL_MISSING:' + str(tool))
    sources = sorted((ROOT / 'image-core/src/main/java').rglob('*.java'))
    if not sources:
        raise RuntimeError('ULTRA_HOST_IMAGE_CORE_SOURCE_MISSING')
    flags = ['--release', '17', '-encoding', 'UTF-8']
    image = HOST_CACHE / ('image-core-' + _fingerprint([javac, jar_tool, *sources], flags) + '.jar')
    if not image.is_file():
        HOST_CACHE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='image-build-', dir=HOST_CACHE) as directory:
            work = Path(directory)
            classes = work / 'classes'
            classes.mkdir()
            _checked_build([str(javac), *flags, '-d', str(classes), *map(str, sources)], 'ULTRA_HOST_IMAGE_CORE_COMPILE_FAILED')
            candidate = work / 'image-core.jar'
            _checked_build([str(jar_tool), '--create', '--file', str(candidate), '-C', str(classes), '.'],
                           'ULTRA_HOST_IMAGE_CORE_JAR_FAILED')
            os.replace(candidate, image)
    return image


def _host_runtime(java=None, image_core=None) -> tuple[str, Path, str]:
    if not java and os.environ.get('JAVA_HOME'):
        java = str(Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if os.name == 'nt' else 'java'))
    java = shutil.which(str(java)) if java else shutil.which('java')
    if not java:
        raise RuntimeError('ULTRA_HOST_JAVA_REQUIRED')
    image = _image_core_jar(java, image_core)
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '.')
    platforms = sorted((sdk / 'platforms').glob('android-*/android.jar'), reverse=True)
    android = next((item for item in platforms if item.parent.name == 'android-37.0'),
                   platforms[0] if platforms else None)
    if android is None or not android.is_file():
        raise RuntimeError('ULTRA_HOST_ANDROID_COMPILE_JAR_MISSING:' + str(sdk))
    stdlib = cached_jar('org.jetbrains.kotlin', 'kotlin-stdlib', '2.4.20')
    annotations = cached_jar('org.jetbrains', 'annotations', '13.0')
    json_library = cached_jar('org.jetbrains.kotlinx', 'kotlinx-serialization-json-jvm', '1.11.0')
    serial = cached_jar('org.jetbrains.kotlinx', 'kotlinx-serialization-core-jvm', '1.11.0')
    compiler = cached_jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.4.20')
    coroutines = cached_jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.11.0')
    dependencies = [stdlib, annotations, json_library, serial, image, android]
    sources = sorted((ROOT / 'manager/src/main/java/dev/maplesu/manager/ultrakernel').glob('*.kt'))
    sources += [ROOT / ('manager/src/main/java/dev/maplesu/manager/workmode/' + name) for name in (
        'Hashes.kt', 'WorkMode.kt', 'control/ControlPaths.kt', 'control/AtomicControlFile.kt')]
    sources += [ROOT / ('manager/src/main/java/dev/maplesu/manager/compat/' + name) for name in (
        'UltraStateStorage.kt', 'StoredInputs.kt')]
    sources.append(ROOT / 'tools/specgen/HostMain.kt')
    jar = HOST_CACHE / (_fingerprint([Path(java), *sources, *dependencies, compiler, coroutines], JVM_FLAGS) + '.jar')
    classpath = os.pathsep.join(map(str, dependencies))
    if not jar.is_file():
        HOST_CACHE.mkdir(parents=True, exist_ok=True)
        boot = os.pathsep.join(map(str, [compiler, stdlib, annotations, coroutines]))
        with tempfile.TemporaryDirectory(prefix='kotlin-build-', dir=HOST_CACHE) as directory:
            candidate = Path(directory) / 'host.jar'
            _checked_build([java, '-Xmx768m', '-cp', boot, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                *JVM_FLAGS, '-classpath', classpath, '-d', str(candidate), *map(str, sources)], 'ULTRA_HOST_COMPILE_FAILED')
            os.replace(candidate, jar)
    return java, jar, classpath


def describe_subject(image: bytes) -> dict:
    return _describe_layout(image, 'describe-subject', 'SUBJECT')


def describe_boot_credentials(image: bytes) -> dict:
    return _describe_layout(image, 'describe-boot-credentials', 'BOOT_CREDENTIALS')


def _describe_layout(image: bytes, operation: str, code: str) -> dict:
    java, jar, classpath = _host_runtime()
    with tempfile.TemporaryDirectory(prefix='MapleSU-subject-') as directory:
        work = Path(directory)
        kernel, output = work / 'Image', work / 'layout.json'
        kernel.write_bytes(image)
        command = [java, '-Xmx768m', '-cp', str(jar) + os.pathsep + classpath,
            'dev.maplesu.manager.ultrakernel.HostMainKt', '--kernel', str(kernel),
            '--operation', operation, '--out', str(output)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, encoding='utf-8', errors='replace')
        if result.returncode:
            raise RuntimeError(f'ULTRA_HOST_{code}_FAILED:{result.returncode}\n{result.stdout}{result.stderr}')
        try:
            facts = json.loads(output.read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise RuntimeError(f'ULTRA_HOST_{code}_OUTPUT:{type(error).__name__}\n{result.stdout}{result.stderr}') from error
        if not isinstance(facts, dict):
            raise RuntimeError(f'ULTRA_HOST_{code}_OUTPUT:OBJECT_REQUIRED\n{result.stdout}{result.stderr}')
        return facts


def generate(args, credential: bytes) -> int:
    if args.symbols or args.struct_offsets or Path(args.recipe).resolve() != (
            ROOT / 'tools/specgen/specgen/recipes/k22.json').resolve():
        raise RuntimeError('ULTRA_HOST_EXTERNAL_RECIPE_OR_SYMBOL_OVERRIDES_UNSUPPORTED')
    try:
        java, jar, classpath = _host_runtime(args.java, args.image_core)
    except _HostBuildFailure as error:
        sys.stderr.write(str(error) + '\n')
        return error.returncode
    command = [java, '-Xmx768m', '-cp', str(jar) + os.pathsep + classpath,
               'dev.maplesu.manager.ultrakernel.HostMainKt', '--out', str(args.out),
               '--assets', str(Path(getattr(args, 'assets', None) or
                                    ROOT / 'manager/src/main/assets').resolve())]
    for name in ('boot', 'kernel', 'receipt', 'require_release', 'patched_kernel', 'patched_boot'):
        value = getattr(args, name, None)
        if value is not None:
            command += ['--' + name.replace('_', '-'), str(value)]
    # Only the child JVM reads this pipe; no credential appears in its argv or build logs.
    return subprocess.run(command, input=credential + b'\n').returncode
