"""Fixed-Kbuild argument regressions; no compiler or modpost process runs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("legacy_modpost_flags", HERE / "legacy_direct_modpost.py")
seam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seam)


class DirectModpostArguments(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maplesu-modpost-flags-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.kernel = self.root / "module", self.root / "kernel"
        self.source.mkdir()
        self.kernel.mkdir()
        self.symvers = self.kernel / "Module.symvers"
        self.symvers.write_text("0x00000001\tmodule_layout\tvmlinux\tEXPORT_SYMBOL\t\n", encoding="utf-8")
        self.obj = self.source / "maplesu_ultra_bridge.lto.o"
        self.obj.write_bytes(b"argument fixture; not an ELF or executed object")
        self.request = {"moduleSource": str(self.source), "kernelBuild": str(self.kernel)}
        self.arguments = ["-m", "-E", "-o", str(self.source / "Module.symvers"), "-e",
                          "-i", str(self.symvers), "-T", "-"]
        self.stdin = (str(self.obj) + "\n").encode()

    def facts(self, arguments):
        return seam.arguments_facts(arguments, self.stdin, self.request)

    def test_make_n_keeps_existing_argument_facts(self):
        expected = self.facts(self.arguments)
        for arguments in (["-n", *self.arguments], [*self.arguments, "-n"]):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.facts(arguments), expected)
                self.assertEqual(arguments.count("-n"), 1)

    def test_duplicate_n_and_unsupported_flags_still_fail(self):
        for suffix in (["-n", "-n"], ["-w"], ["-k"], ["--unknown"]):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError, "MODPOST_ARGUMENTS"):
                    self.facts([*self.arguments, *suffix])

    def test_n_keeps_required_flags(self):
        for missing in ("-m", "-e"):
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ValueError, "MODPOST_ARGUMENTS"):
                    self.facts([arg for arg in self.arguments if arg != missing] + ["-n"])

    def test_n_keeps_exact_output_and_module_list(self):
        wrong_output = list(self.arguments)
        wrong_output[wrong_output.index("-o") + 1] = str(self.root / "Module.symvers")
        with self.assertRaisesRegex(ValueError, "MODPOST_OUTPUT"):
            self.facts([*wrong_output, "-n"])
        self.stdin = (str(self.root / "other.o") + "\n").encode()
        with self.assertRaisesRegex(ValueError, "MODPOST_OBJECT"):
            self.facts([*self.arguments, "-n"])

    def test_n_keeps_real_symvers_and_duplicate_checks(self):
        missing = self.arguments.index("-i")
        without_symvers = self.arguments[:missing] + self.arguments[missing + 2:]
        with self.assertRaisesRegex(ValueError, "REAL_SYMVERS_REQUIRED"):
            self.facts([*without_symvers, "-n"])
        with self.assertRaisesRegex(ValueError, "REAL_SYMVERS_REQUIRED"):
            self.facts([*self.arguments, "-i", str(self.symvers), "-n"])

    def test_n_does_not_skip_missing_or_invalid_symvers(self):
        self.symvers.unlink()
        with self.assertRaises(FileNotFoundError):
            self.facts([*self.arguments, "-n"])
        self.symvers.write_bytes(b"invalid symbol version dump\n")
        with self.assertRaisesRegex(ValueError, "SYMVERS_FORMAT"):
            self.facts([*self.arguments, "-n"])


if __name__ == "__main__":
    unittest.main()
