"""Restore two disabled checks in pinned DDK modpost, in private build evidence."""
import difflib
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


PINS = {
    "android12-5.10": (
        "90ee67806aedb9eb8816bef3605489377431b3aa459165aa417dbad3cc2048c7",
        "9d976d8e7c2b5a64d7cdf0c6e5dbc2e78b1ecebcb3b9fd1b1ad86e2d1595e7a1",
        "4d75d7457c4dcfcecc61db4be53a718af4255429688edbd245b65f7945ce2bcf"),
    "android13-5.15": (
        "1d6bc058e71b8a8ce1ed8aec68c739d1447aab89cfdbf1f5f64c1eb64e644fae",
        "451cffc36b952eb25d1da070d41c3028d8c4aa0d82363ef8994e44b46dd042e1",
        "92feb3b61f37a456c05e6550d4c9490e9e2d0ac6286936459072b8dc8c6f6cdc"),
}
HOST_FLAGS = ["-Wp,-MMD,scripts/mod/.modpost.o.d", "-Wall", "-Wmissing-prototypes",
              "-Wstrict-prototypes", "-O2", "-fomit-frame-pointer", "-std=gnu89", "-I", "./scripts/mod"]


def identity(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def restore_source(data):
    for statement in (b"check_exports(mod);", b"s->module = exp->module;"):
        before = b"//\t\t" + statement
        if data.count(before) != 1:
            raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_SOURCE_SHAPE")
        data = data.replace(before, b"\t\t" + statement, 1)
    return data


def recorded_command(path, target):
    rows = re.findall(r"^cmd_" + re.escape(target) + r" := (.+)$", path.read_text(), re.M)
    if len(rows) != 1:
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_HOST_RULE")
    return shlex.split(rows[0])


def prepare(kernel_source, kernel_build, original_tool, compiler, family, output):
    """Return tool, exact build inputs/tools and immutable derivation receipt."""
    pin = PINS.get(family)
    source = kernel_source / "scripts/mod/modpost.c"
    if (pin is None or identity(source)["sha256"] != pin[0] or
            identity(original_tool)["sha256"] != pin[2]):
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_FIXED_IDENTITY")
    restored = restore_source(source.read_bytes())
    if hashlib.sha256(restored).hexdigest() != pin[1]:
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_DERIVED_IDENTITY")
    compile_rule = kernel_build / "scripts/mod/.modpost.o.cmd"
    link_rule = kernel_build / "scripts/mod/.modpost.cmd"
    compile_command = recorded_command(compile_rule, "scripts/mod/modpost.o")
    link_command = recorded_command(link_rule, "scripts/mod/modpost")
    if (compile_command != ["clang", *HOST_FLAGS, "-c", "-o", "scripts/mod/modpost.o", str(source)] or
            link_command != ["clang", "-o", "scripts/mod/modpost", "scripts/mod/modpost.o",
                             "scripts/mod/file2alias.o", "scripts/mod/sumversion.o"]):
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_HOST_RULE")
    source_makefile = kernel_source / "scripts/mod/Makefile"
    if not re.search(r"^modpost-objs\s*:=\s*modpost.o file2alias.o sumversion.o$", source_makefile.read_text(), re.M):
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_HOST_OBJECTS")
    inputs = [Path(__file__).resolve(), source, source_makefile, kernel_source / "scripts/Makefile.host",
              kernel_source / "Makefile", original_tool, compile_rule, link_rule]
    copies = {
        "source/scripts/mod/modpost.h": kernel_source / "scripts/mod/modpost.h",
        "source/include/linux/license.h": kernel_source / "include/linux/license.h",
        "build/scripts/mod/elfconfig.h": kernel_build / "scripts/mod/elfconfig.h",
    }
    for stem in ("file2alias", "sumversion"):
        inputs.extend([kernel_source / f"scripts/mod/{stem}.c", kernel_build / f"scripts/mod/.{stem}.o.cmd"])
        copies[f"build/scripts/mod/{stem}.o"] = kernel_build / f"scripts/mod/{stem}.o"
    inputs.extend(copies.values())
    before = [identity(path) for path in inputs]
    output.mkdir(parents=True, exist_ok=False)
    derived_source = output / "source/scripts/mod/modpost.c"
    derived_source.parent.mkdir(parents=True)
    derived_source.write_bytes(restored)
    generated = [derived_source]
    originals = output / "original"
    originals.mkdir()
    for name, path in (("modpost.c", source), ("modpost", original_tool)):
        snapshot = originals / name
        snapshot.write_bytes(path.read_bytes())
        generated.append(snapshot)
    patch = output / "PATCH.diff"
    patch.write_bytes(b"".join(difflib.diff_bytes(difflib.unified_diff,
        source.read_bytes().splitlines(keepends=True), restored.splitlines(keepends=True),
        fromfile=b"a/scripts/mod/modpost.c", tofile=b"b/scripts/mod/modpost.c")))
    generated.append(patch)
    for relative, original in copies.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original.read_bytes())
        generated.append(destination)
    compiler = compiler.resolve(strict=True)
    query = subprocess.run([str(compiler), "-print-prog-name=ld"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (output / "linker-query.stdout").write_bytes(query.stdout)
    (output / "linker-query.stderr").write_bytes(query.stderr)
    if query.returncode:
        raise SystemExit(query.returncode)
    linker = Path(query.stdout.decode("utf-8").strip()).resolve(strict=True)
    tools = [identity(compiler), identity(linker)]
    compile_command[0], compile_command[-1] = str(compiler), str(derived_source)
    link_command[0] = str(compiler)
    commands = []
    for name, argv in (("compile", compile_command), ("link", link_command)):
        with (output / f"{name}.stdout").open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
            result = subprocess.run(argv, cwd=output / "build", stdout=stdout, stderr=stderr, check=False)
        commands.append(dict(argv=argv, cwd=str(output / "build"), exitCode=result.returncode))
        if result.returncode:
            (output / "FAILED.json").write_text(json.dumps(dict(commands=commands, sources=before, tools=tools), indent=2) + "\n")
            raise SystemExit(result.returncode)
    unchanged = before == [identity(path) for path in inputs] and tools == [identity(Path(row["path"])) for row in tools]
    generated.extend([output / "build/scripts/mod/modpost.o", output / "build/scripts/mod/.modpost.o.d",
                      output / "build/scripts/mod/modpost", *sorted(output.glob("*.stdout")), *sorted(output.glob("*.stderr"))])
    receipt = output / "DERIVATION.json"
    receipt.write_text(json.dumps(dict(schema="maplesu-fixed-strict-modpost/1", family=family,
        originalSource=identity(source), derivedSource=identity(derived_source), originalTool=identity(original_tool),
        restoredStatements=["check_exports(mod);", "s->module = exp->module;"],
        sources=before, tools=tools, commands=commands, generated=[identity(path) for path in generated],
        inputsUnchanged=unchanged, wholeNativeBuild=False, targetQualified=False), indent=2) + "\n")
    if not unchanged:
        raise ValueError("ULTRA_BRIDGE_STRICT_MODPOST_INPUT_CHANGED")
    return dict(tool=output / "build/scripts/mod/modpost", inputs=[*inputs, *generated, receipt],
                tools=[compiler, linker], receipt=receipt)
