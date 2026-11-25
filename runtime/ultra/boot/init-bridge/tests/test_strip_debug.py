"""Debug-strip artifact identity, failure propagation and signed-module preservation."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("strip_debug_builder", Path(__file__).parents[1] / "build_target.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class StripDebugChecks(unittest.TestCase):
    def test_stripped_identity_is_published_and_original_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module, tool = root / "bridge.ko", root / "llvm-strip"
            module.write_bytes(b"fixture code and debug")
            original = module.read_bytes()

            def run(command, **kwargs):
                self.assertEqual(command, [str(tool), "--strip-debug", str(module)])
                module.write_bytes(b"fixture code")
                return SimpleNamespace(returncode=0)

            with patch.object(builder.subprocess, "run", side_effect=run):
                receipt, code = builder.strip_module_debug(module, tool, root)
            self.assertEqual(code, 0)
            self.assertEqual(Path(receipt["unstripped"]["path"]).read_bytes(), original)
            self.assertEqual(receipt["input"]["sha256"], receipt["unstripped"]["sha256"])
            self.assertEqual(receipt["output"], builder.identity(module))
            self.assertNotEqual(receipt["input"]["sha256"], receipt["output"]["sha256"])

    def test_strip_error_retains_real_exit_and_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "bridge.ko"
            module.write_bytes(b"fixture module")

            def run(command, **kwargs):
                kwargs["stderr"].write(b"actual strip error\n")
                return SimpleNamespace(returncode=7)

            with patch.object(builder.subprocess, "run", side_effect=run):
                receipt, code = builder.strip_module_debug(module, root / "llvm-strip", root)
            self.assertEqual((code, receipt["exitCode"]), (7, 7))
            self.assertEqual((root / "strip-stderr.log").read_bytes(), b"actual strip error\n")

    def test_existing_signature_is_preserved_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "bridge.ko"
            original = b"fixture signed module~Module signature appended~\n"
            module.write_bytes(original)
            with patch.object(builder.subprocess, "run") as run:
                receipt, code = builder.strip_module_debug(module, root / "llvm-strip", root)
            run.assert_not_called()
            self.assertEqual(code, 0)
            self.assertEqual(receipt["status"], "SIGNED_MODULE_PRESERVED")
            self.assertEqual(module.read_bytes(), original)
            self.assertEqual(receipt["input"], receipt["output"])


if __name__ == "__main__":
    unittest.main()
