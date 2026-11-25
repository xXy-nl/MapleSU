"""Native gate entry contract; small observed bytes do not qualify a target ABI."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).parents[1] / "target_kmi.py")
kmi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kmi)

# Original 5.10 Image SHA256:
# 80e2007352c83cf00590a6264fe69da7da592ed5772c88daae918cdabd8289c2.
# Offsets identify the independently captured six words; they are not patch sites
# in these compact fixtures. Actual Image capture/replay is separate evidence.
ACTUAL_510_ENTRIES = (
    ("do_execveat_common", 0x50b09c,
     (0xd101c3ff, 0xf800865e, 0xa9017bfd, 0xa9026ffc, 0xa90367fa, 0xa9045ff8)),
    ("__arm64_sys_newfstatat", 0x509dc0,
     (0xd10303ff, 0xf800865e, 0xa90a7bfd, 0xf9005bf3, 0x910283fd, 0xf000d3a8)),
    ("__arm64_sys_faccessat", 0x4f8bdc,
     (0xf800865e, 0xa9bf7bfd, 0x910003fd, 0xb9400008, 0xf9400401, 0xb9401002)),
    ("__arm64_sys_statx", 0x509044,
     (0xd10303ff, 0xf800865e, 0xa90a7bfd, 0xf9005bf3, 0x910283fd, 0xf000d3a9)),
    ("__arm64_sys_faccessat2", 0x4f87d4,
     (0xf800865e, 0xa9bf7bfd, 0x910003fd, 0xb9400008, 0xf9400401, 0xb9401002)),
)


class ProfileEntryTests(unittest.TestCase):
    def test_observed_510_body_entries_keep_all_six_words(self):
        for name, original_offset, words in ACTUAL_510_ENTRIES:
            with self.subTest(name=name, original_offset=hex(original_offset)):
                self.assertEqual(kmi.profile_entry_words(bytes(4) + struct.pack("<6I", *words), 4, name), words)

    def test_existing_pac_and_bti_prefix_routes_keep_exact_words(self):
        for prefix in (0xd503233f, 0xd503237f, 0xd503231f, 0xd503235f, 0xd503245f, 0xd503249f, 0xd50324df):
            with self.subTest(prefix=hex(prefix)):
                words = (prefix, 0xd101c3ff, 0xf800865e, 0xa9017bfd, 0xa9026ffc, 0xa90367fa)
                self.assertEqual(kmi.profile_entry_words(bytes(4) + struct.pack("<6I", *words), 4, "body"), words)

    def test_patched_branches_or_pc_relative_entries_are_rejected(self):
        for instruction in (0x14000000, 0x94000000, 0xd61f0200, 0xd63f0200, 0xd65f03c0, 0x90000000, 0x10000000, 0x58000000, 0):
            for prefix in (None, 0xd503233f, 0xd503245f):
                with self.subTest(instruction=hex(instruction), prefix=prefix):
                    words = [instruction] if prefix is None else [prefix, instruction]
                    words += [0xd503201f] * (6 - len(words))
                    with self.assertRaisesRegex(ValueError, "PROFILE_ENTRY_REQUIRES_RECOVERED_INPUT:body"):
                        kmi.profile_entry_words(bytes(4) + struct.pack("<6I", *words), 4, "body")

    def test_bounds_remain_required(self):
        image = bytes(4) + struct.pack("<6I", 0xd503233f, 0xd101c3ff, 0, 0, 0, 0)
        for offset in (-4, 0, 2, 5, 8, len(image)):
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "PROFILE_BOUNDS:body"):
                    kmi.profile_entry_words(image, offset, "body")


if __name__ == "__main__":
    unittest.main(verbosity=2)
