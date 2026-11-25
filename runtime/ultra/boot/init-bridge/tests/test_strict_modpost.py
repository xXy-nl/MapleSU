"""Private host-tool derivation contracts; subprocesses are explicit fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("strict_modpost_fixture", Path(__file__).resolve().parents[1] / "strict_modpost.py")
strict = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strict)


class StrictModpostChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maplesu-strict-modpost-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.build = self.root / "source", self.root / "build"
        self.output = self.root / "evidence"
        files = {
            self.source / "scripts/mod/modpost.c": b"before\n//\t\tcheck_exports(mod);\n//\t\ts->module = exp->module;\nafter\n",
            self.source / "scripts/mod/Makefile": b"modpost-objs\t:= modpost.o file2alias.o sumversion.o\n",
            self.source / "scripts/Makefile.host": b"host-rule fixture\n",
            self.source / "Makefile": b"kernel fixture\n",
            self.source / "scripts/mod/modpost.h": b"header fixture\n",
            self.source / "include/linux/license.h": b"license fixture\n",
            self.build / "scripts/mod/elfconfig.h": b"elfconfig fixture\n",
        }
        for stem in ("file2alias", "sumversion"):
            files[self.source / f"scripts/mod/{stem}.c"] = b"unchanged helper source\n"
            files[self.build / f"scripts/mod/{stem}.o"] = b"inert helper object\n"
            files[self.build / f"scripts/mod/.{stem}.o.cmd"] = b"unchanged helper command fixture\n"
        self.original_tool, self.compiler, self.linker = (self.root / name for name in ("modpost", "clang", "ld"))
        for path in (self.original_tool, self.compiler, self.linker):
            files[path] = ("inert tool " + path.name).encode()
        for path, data in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        compile_argv = ["clang", *strict.HOST_FLAGS, "-c", "-o", "scripts/mod/modpost.o", str(self.source / "scripts/mod/modpost.c")]
        self.compile_rule = self.build / "scripts/mod/.modpost.o.cmd"
        self.compile_rule.write_text("cmd_scripts/mod/modpost.o := " + shlex.join(compile_argv) + "\n")
        (self.build / "scripts/mod/.modpost.cmd").write_text(
            "cmd_scripts/mod/modpost := clang -o scripts/mod/modpost scripts/mod/modpost.o scripts/mod/file2alias.o scripts/mod/sumversion.o\n")
        data = files[self.source / "scripts/mod/modpost.c"]
        digest = lambda value: hashlib.sha256(value).hexdigest()
        self.pin = (digest(data), digest(strict.restore_source(data)), digest(self.original_tool.read_bytes()))

    def prepare(self):
        with patch.dict(strict.PINS, {"fixture-family": self.pin}):
            return strict.prepare(self.source, self.build, self.original_tool, self.compiler, "fixture-family", self.output)

    def fake_run(self, argv, **kwargs):
        if argv[-1] == "-print-prog-name=ld":
            return SimpleNamespace(returncode=0, stdout=str(self.linker).encode(), stderr=b"")
        base = Path(kwargs["cwd"])
        if "-c" in argv:
            (base / "scripts/mod/modpost.o").write_bytes(b"inert rebuilt host object")
            (base / "scripts/mod/.modpost.o.d").write_bytes(b"dependency fixture\n")
        else:
            (base / "scripts/mod/modpost").write_bytes(b"inert derived host tool")
        return SimpleNamespace(returncode=0)

    def test_only_two_disabled_statements_are_restored(self):
        data = (self.source / "scripts/mod/modpost.c").read_bytes()
        self.assertEqual(strict.restore_source(data), data.replace(b"//\t\t", b"\t\t"))
        for invalid in (data.replace(b"check_exports(mod);", b"other(mod);"), data + b"//\t\tcheck_exports(mod);\n"):
            with self.assertRaisesRegex(ValueError, "SOURCE_SHAPE"):
                strict.restore_source(invalid)

    def test_unknown_or_changed_fixed_inputs_stop_before_compiler(self):
        for field in ("family", "source", "tool"):
            with self.subTest(field=field), patch.object(strict.subprocess, "run") as run:
                pins = self.pin if field == "family" else tuple("0" * 64 if i == (0 if field == "source" else 2) else item
                    for i, item in enumerate(self.pin))
                with patch.dict(strict.PINS, {"fixture-family": pins}):
                    with self.assertRaisesRegex(ValueError, "FIXED_IDENTITY"):
                        strict.prepare(self.source, self.build, self.original_tool, self.compiler,
                                       "unknown" if field == "family" else "fixture-family", self.output)
                run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_changed_host_rule_stops_before_compiler(self):
        self.compile_rule.write_text(self.compile_rule.read_text().replace("-O2", "-O0"))
        with patch.object(strict.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "HOST_RULE"):
                self.prepare()
            run.assert_not_called()

    def test_private_tool_and_all_build_evidence_are_returned(self):
        source_before = (self.source / "scripts/mod/modpost.c").read_bytes()
        tool_before = self.original_tool.read_bytes()
        with patch.object(strict.subprocess, "run", side_effect=self.fake_run) as run:
            prepared = self.prepare()
        self.assertEqual(run.call_count, 3)
        receipt = json.loads(prepared["receipt"].read_bytes())
        self.assertTrue(receipt["inputsUnchanged"])
        self.assertEqual([row["exitCode"] for row in receipt["commands"]], [0, 0])
        self.assertIn(self.output / "PATCH.diff", prepared["inputs"])
        self.assertIn(prepared["receipt"], prepared["inputs"])
        self.assertIn(prepared["tool"], prepared["inputs"])
        self.assertEqual((self.source / "scripts/mod/modpost.c").read_bytes(), source_before)
        self.assertEqual(self.original_tool.read_bytes(), tool_before)
        self.assertFalse(receipt["wholeNativeBuild"])

    def test_actual_host_compiler_failure_code_is_preserved(self):
        def fail(argv, **kwargs):
            return self.fake_run(argv, **kwargs) if argv[-1] == "-print-prog-name=ld" else SimpleNamespace(returncode=7)
        with patch.object(strict.subprocess, "run", side_effect=fail) as run:
            with self.assertRaises(SystemExit) as failure:
                self.prepare()
        self.assertEqual(failure.exception.code, 7)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(json.loads((self.output / "FAILED.json").read_bytes())["commands"][0]["exitCode"], 7)

    def test_input_drift_is_rejected_after_host_link(self):
        def drift(argv, **kwargs):
            result = self.fake_run(argv, **kwargs)
            if argv[-1] == "scripts/mod/sumversion.o":
                (self.source / "scripts/mod/modpost.h").write_bytes(b"changed header")
            return result
        with patch.object(strict.subprocess, "run", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "INPUT_CHANGED"):
                self.prepare()
        self.assertFalse(json.loads((self.output / "DERIVATION.json").read_bytes())["inputsUnchanged"])


if __name__ == "__main__":
    unittest.main()
