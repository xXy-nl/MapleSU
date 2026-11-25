#!/usr/bin/env python3
"""Narrow fixed-DDK V2 alias seam; retain all ordinary modpost checks."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys


RULE_HASHES = {
    "039ace952de66c17560d11c30b2be64951110033b50621e6ff80e6890b29babf": "android12-5.10",
    "4b241ef128f77162ec817a6cb8e6bee3a9ea0991408f41a005d2b6b19c60b03d": "android13-5.15",
}
MODPOST_SOURCE_HASHES = {"android12-5.10": "90ee67806aedb9eb8816bef3605489377431b3aa459165aa417dbad3cc2048c7",
                         "android13-5.15": "1d6bc058e71b8a8ce1ed8aec68c739d1447aab89cfdbf1f5f64c1eb64e644fae"}
BASE_FLAGS = "$(if $(CONFIG_MODVERSIONS),-m) $(if $(CONFIG_MODULE_SRCVERSION_ALL),-a) $(if $(CONFIG_SECTION_MISMATCH_WARN_ONLY),,-E) $(if $(KBUILD_MODPOST_WARN),-w) -o $@"
MODULE_FLAGS = "$(addprefix -i ,$(wildcard $(input-symdump))) $(if $(KBUILD_NSDEPS),-d $(MODULES_NSDEPS)) $(if $(CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS)$(KBUILD_NSDEPS),-N)"


def identity(path):
    data = Path(path).read_bytes()
    return {"path": str(Path(path).resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def checked(reference):
    path = Path(reference["path"])
    if identity(path) != reference:
        raise ValueError("ULTRA_BRIDGE_DIRECT_INPUT_CHANGED:" + str(path))
    return path


def load_parser(path):
    spec = importlib.util.spec_from_file_location("bridge_legacy_direct", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def dependency(root, manifest, sha256):
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_MANIFEST_IDENTITY")
    declared = json.loads(raw)
    if declared.get("schema") != "maplesu-python-dependency-source/1" or declared.get("distribution") != "pyelftools":
        raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_MANIFEST_SCHEMA")
    seen, paths = set(), []
    for row in declared["files"]:
        relative = row["relativePath"]
        if relative in seen or "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_MEMBER")
        seen.add(relative)
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or any(identity(path)[key] != row[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_SOURCE_IDENTITY:" + relative)
        paths.append(path)
    if "elftools/elf/elffile.py" not in seen:
        raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_PARSER_REQUIRED")
    for name, module in tuple(sys.modules.items()):
        if (name == "elftools" or name.startswith("elftools.")) and getattr(module, "__file__", None):
            path = Path(module.__file__).resolve()
            if not path.is_relative_to(root) or path.relative_to(root).as_posix() not in seen:
                raise ValueError("ULTRA_BRIDGE_DIRECT_PYTHON_ALREADY_LOADED:" + name)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return [manifest, *paths]


def rule_expression(path):
    actual = identity(path)
    if actual["sha256"] not in RULE_HASHES:
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_RULE_UNSUPPORTED:" + actual["sha256"])
    logical = re.sub(r"\\\r?\n[ \t]*", " ", path.read_text(encoding="utf-8"))
    assignments = [" ".join(value.split()) for value in
                   re.findall(r"^MODPOST\s*(?:\+?=)\s*(.*)$", logical, re.M)]
    family = RULE_HASHES[actual["sha256"]]
    base, modules = BASE_FLAGS, MODULE_FLAGS
    if family == "android13-5.15":
        base = base.replace("$(if $(KBUILD_MODPOST_WARN),-w) ", "")
        modules = modules.replace("$(wildcard $(input-symdump))", "$(existing-input-symdump)")
    expected = ["scripts/mod/modpost " + base, "-e", "-v $(module_scmversion)", modules, "-n"]
    if family == "android13-5.15":
        expected.append("-w")
    if assignments != expected:
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_RULE_SHAPE")
    expression = (base + " -e $(if $(filter y,$(CONFIG_MODULE_SCMVERSION)),"
                  "$(if $(module_scmversion),-v $(module_scmversion))) " + modules +
                  " $(if $(findstring i,$(filter-out --%,$(MAKEFLAGS))),-n)")
    if family == "android13-5.15":
        expression += " $(if $(KBUILD_MODPOST_WARN)$(filter-out $(existing-input-symdump), $(input-symdump)),-w)"
    return expression


def make_command(wrapper, request, rule):
    # Literal paths must survive make expansion before POSIX shell quoting.
    def quote(path):
        value = str(path)
        if "\n" in value or "\r" in value:
            raise ValueError("ULTRA_BRIDGE_DIRECT_COMMAND_PATH")
        return shlex.quote(value).replace("$", "$$")
    return " ".join(quote(path) for path in (sys.executable, wrapper)) + " --request " + quote(request) + " -- " + rule


def staged_sources(source):
    selection = source / "SOURCE-SELECTION.json"
    rows = json.loads(selection.read_bytes())["inputs"]
    paths, seen = [selection], set()
    for row in rows:
        relative = row["staged"]
        if relative in seen or "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ValueError("ULTRA_BRIDGE_DIRECT_STAGED_MEMBER")
        seen.add(relative)
        path = (source / relative).resolve()
        if not path.is_relative_to(source) or any(identity(path)[key] != row["selected"][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_DIRECT_STAGED_IDENTITY:" + relative)
        paths.append(path)
    # Snapshot generated Kbuild fragments and headers as actual build inputs too.
    return list(dict.fromkeys([*paths, *sorted(path for path in source.rglob("*") if path.is_file())]))


def arguments_facts(arguments, stdin, request):
    flags, values = set(), {}
    at = 0
    while at < len(arguments):
        arg = arguments[at]
        if arg in ("-m", "-a", "-E", "-e", "-N", "-n"):
            if arg in flags:
                raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_ARGUMENTS")
            flags.add(arg)
            at += 1
        elif arg in ("-o", "-i", "-v", "-d", "-T") and at + 1 < len(arguments):
            values.setdefault(arg, []).append(arguments[at + 1])
            at += 2
        else:
            raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_ARGUMENTS:" + arg)
    if not {"-m", "-e"}.issubset(flags) or any(len(values.get(arg, [])) != 1 for arg in ("-o", "-T")):
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_ARGUMENTS")
    if any(len(values.get(arg, [])) > 1 for arg in ("-v", "-d")):
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_ARGUMENTS")
    source = Path(request["moduleSource"])
    if Path(values["-o"][0]).resolve() != source / "Module.symvers":
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_OUTPUT")
    symvers = [Path(value).resolve() for value in values.get("-i", [])]
    expected_symvers = Path(request["kernelBuild"]) / "Module.symvers"
    if expected_symvers not in symvers or len(symvers) != len(set(symvers)):
        raise ValueError("ULTRA_BRIDGE_DIRECT_REAL_SYMVERS_REQUIRED")
    exports = read_exports(symvers)
    module_list = values["-T"][0]
    listed = stdin if module_list == "-" else Path(module_list).read_bytes()
    names = listed.decode("utf-8").splitlines()
    if len(names) != 1 or not names[0] or names[0] != names[0].strip():
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_MODULE_LIST")
    obj = Path(names[0]).resolve()
    if obj not in (source / "maplesu_ultra_bridge.o", source / "maplesu_ultra_bridge.lto.o"):
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_OBJECT")
    return obj, exports, [identity(path) for path in symvers], listed


def read_exports(paths):
    exported = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if not fields:
                continue
            if (len(fields) not in (4, 5) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", fields[0]) or
                    fields[3] not in ("EXPORT_SYMBOL", "EXPORT_SYMBOL_GPL") or fields[1] in exported):
                raise ValueError("ULTRA_BRIDGE_DIRECT_SYMVERS_FORMAT")
            exported[fields[1]] = (int(fields[0], 16), fields[2], fields[3], fields[4] if len(fields) == 5 else "")
    if not exported:
        raise ValueError("ULTRA_BRIDGE_DIRECT_SYMVERS_EMPTY")
    return exported


def missing_imports(data, aliases, exports):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    table = elf.get_section_by_name(".symtab")
    # Exactly the AArch64 exceptions in both frozen modpost.c implementations.
    ignored = {"__this_module", "_GLOBAL_OFFSET_TABLE_"}
    strong = [symbol.name for symbol in table.iter_symbols() if symbol.name and
              symbol["st_shndx"] == "SHN_UNDEF" and symbol["st_info"]["bind"] == "STB_GLOBAL" and
              symbol.name not in ignored]
    missing = [name for name in reversed([*strong, "module_layout"]) if name not in exports]
    if len(missing) != len(aliases) or set(missing) != set(aliases):
        raise ValueError("ULTRA_BRIDGE_DIRECT_ORDINARY_UNDEFINED:" + ",".join(sorted(set(missing) - set(aliases))))
    return missing


def accepted_diagnostics(stdout, stderr, missing, obj, family):
    if stdout:
        return False
    try:
        lines = stderr.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError:
        return False
    reported, suppression = [], False
    # Both fixed modpost implementations strip .o and then .lto.
    module = obj.with_name(obj.name.removesuffix(".o").removesuffix(".lto") + ".ko")
    limit = 10 if family == "android13-5.15" else len(missing)
    for line in lines:
        if not line:
            continue
        if (family == "android13-5.15" and len(missing) > limit and not suppression and len(reported) == limit and
                line == "WARNING: modpost: suppressed %d unresolved symbol warnings because there were too many)" % (len(missing) - limit)):
            suppression = True
            continue
        match = re.fullmatch(r'WARNING: modpost: "([A-Za-z0-9_]+)" \[([^\r\n]+)\] undefined!', line)
        if (not match or suppression or len(reported) >= limit or len(reported) >= len(missing) or
                match[1] != missing[len(reported)] or Path(match[2]).resolve() != module):
            return False
        reported.append(match[1])
    return reported == missing[:limit] and suppression == (len(missing) > limit)


def execute(request, arguments, stdin):
    if request.get("schema") != "maplesu-direct-v2-modpost-request/1":
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_REQUEST_SCHEMA")
    for reference in request["inputs"]:
        checked(reference)
    family = request["ruleFamily"]
    if (RULE_HASHES.get(identity(checked(request["rules"]))["sha256"]) != family or
            identity(checked(request["modpostSource"]))["sha256"] != MODPOST_SOURCE_HASHES.get(family)):
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODPOST_RULE_IDENTITY")
    dependency(Path(request["dependencyRoot"]), checked(request["dependencyManifest"]), request["dependencyManifest"]["sha256"])
    parser = load_parser(checked(request["parser"]))
    obj, exports, symvers, listed = arguments_facts(arguments, stdin, request)
    before = identity(obj)
    facts = parser.inspect(obj.read_bytes(), "legacy-lto-cfi")
    if not facts.get("directImportsV2"):
        raise ValueError("ULTRA_BRIDGE_DIRECT_V2_REQUIRED")
    aliases = facts["imports"]
    if any(name in exports for name in aliases):
        raise ValueError("ULTRA_BRIDGE_DIRECT_ALIAS_EXPORTED")
    missing = missing_imports(obj.read_bytes(), aliases, exports)
    tool = checked(request["modpost"])
    result = subprocess.run([str(tool), *arguments, "-w"], input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    try:
        unchanged = (identity(obj) == before and all(identity(Path(row["path"])) == row for row in symvers) and
                     all(identity(Path(row["path"])) == row for row in request["inputs"]))
    except OSError:
        unchanged = False
    accepted = accepted_diagnostics(result.stdout, result.stderr, missing, obj, family)
    receipt = {"schema": "maplesu-direct-v2-modpost/1", "command": [str(tool), *arguments, "-w"],
               "originalArguments": arguments, "originalStdinSha256": hashlib.sha256(stdin).hexdigest(),
               "moduleListSha256": hashlib.sha256(listed).hexdigest(), "object": before,
               "direct": facts, "symvers": symvers, "missingStrongImports": missing,
               "ordinaryStrongMissing": [], "fixedRuleFamily": family, "inputsUnchanged": unchanged,
               "realExitCode": result.returncode, "onlyExactAliasDiagnostics": accepted,
               "exitCode": result.returncode if result.returncode else 0 if accepted and unchanged else 1,
               "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
               "stderrSha256": hashlib.sha256(result.stderr).hexdigest(), "targetQualified": False}
    output = Path(request["receipt"])
    with output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    with output.with_suffix(".stdout").open("xb") as stream:
        stream.write(result.stdout)
    with output.with_suffix(".stderr").open("xb") as stream:
        stream.write(result.stderr)
    return receipt["exitCode"], result.stdout, result.stderr


def final_module(data, parser, preflight, symvers, release):
    from elftools.elf.elffile import ELFFile
    facts = parser.inspect(data, "legacy-lto-cfi")
    if any(facts.get(key) != preflight["direct"].get(key) for key in ("imports", "directImportsV2", "directMarkerSha256")):
        raise ValueError("ULTRA_BRIDGE_DIRECT_FINAL_ALIAS_CHANGED")
    elf = ELFFile(io.BytesIO(data))
    table, info = elf.get_section_by_name(".symtab"), elf.get_section_by_name(".modinfo")
    version_section = elf.get_section_by_name("__versions")
    if table is None or info is None or version_section is None:
        raise ValueError("ULTRA_BRIDGE_DIRECT_FINAL_METADATA")
    imports = {symbol.name for symbol in table.iter_symbols() if symbol.name and
               symbol["st_shndx"] == "SHN_UNDEF" and symbol["st_info"]["bind"] != "STB_WEAK"}
    ordinary = imports - set(facts["imports"])
    raw = version_section.data()
    if len(raw) % 64:
        raise ValueError("ULTRA_BRIDGE_DIRECT_MODVERSIONS_FORMAT")
    versions = {}
    for at in range(0, len(raw), 64):
        name = raw[at + 8:at + 64].split(b"\0", 1)[0].decode("ascii")
        if not name or name in versions or name in facts["imports"]:
            raise ValueError("ULTRA_BRIDGE_DIRECT_MODVERSIONS_FORMAT")
        versions[name] = struct.unpack_from("<Q", raw, at)[0]
    tags = [entry.decode("utf-8") for entry in info.data().split(b"\0") if entry]
    magic = [tag[9:] for tag in tags if tag.startswith("vermagic=")]
    if len(magic) != 1 or magic[0].split(" ", 1)[0] != release:
        raise ValueError("ULTRA_BRIDGE_DIRECT_VERMAGIC")
    namespaces = {tag[10:] for tag in tags if tag.startswith("import_ns=")}
    licenses = {tag[8:] for tag in tags if tag.startswith("license=")}
    gpl = bool(licenses & {"GPL", "GPL v2", "GPL and additional rights", "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL"})
    exports = read_exports(symvers)
    for name in sorted(ordinary | {"module_layout"}):
        if name not in exports:
            raise ValueError("ULTRA_BRIDGE_DIRECT_IMPORT_NOT_EXPORTED:" + name)
        crc, provider, export_class, namespace = exports[name]
        if provider != "vmlinux":
            raise ValueError("ULTRA_BRIDGE_DIRECT_EXTERNAL_MODULE_DEPENDENCY:" + name)
        if namespace and namespace not in namespaces:
            raise ValueError("ULTRA_BRIDGE_DIRECT_IMPORT_NAMESPACE:" + name)
        if export_class == "EXPORT_SYMBOL_GPL" and not gpl:
            raise ValueError("ULTRA_BRIDGE_DIRECT_IMPORT_GPL:" + name)
        if versions.get(name) != crc:
            raise ValueError("ULTRA_BRIDGE_DIRECT_IMPORT_CRC:" + name)
    return {"direct": facts, "ordinaryImports": sorted(ordinary), "ordinaryVersions": versions,
            "moduleLayoutChecked": True, "targetQualified": False, "moduleLoaded": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    code, stdout, stderr = execute(json.loads(args.request.read_bytes()), arguments, sys.stdin.buffer.read())
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
